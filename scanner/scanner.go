package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	ctl "github.com/deepfence/ThreatMapper/deepfence_utils/controls"
	"github.com/deepfence/ThreatMapper/deepfence_utils/log"
	cloudmetadata "github.com/deepfence/cloud-scanner/cloud-metadata"
	"github.com/deepfence/cloud-scanner/output"
	"github.com/deepfence/cloud-scanner/util"
	"github.com/deepfence/golang_deepfence_sdk/utils/tasks"
)

var (
	ComplianceModPath = os.Getenv("COMPLIANCE_MOD_PATH")
	cloudProviderPath = map[string]string{
		util.CloudProviderAWS:   ComplianceModPath + "/steampipe-mod-aws-compliance",
		util.CloudProviderGCP:   ComplianceModPath + "/steampipe-mod-gcp-compliance",
		util.CloudProviderAzure: ComplianceModPath + "/steampipe-mod-azure-compliance",
	}
	extrasForInProgress = map[string]interface{}{
		"result": util.ComplianceSummary{
			Total:                0,
			Alarm:                0,
			Ok:                   0,
			Info:                 0,
			Skip:                 0,
			Error:                0,
			CompliancePercentage: 0,
		},
		"total_checks": 0,
	}
)

type CloudComplianceScan struct {
	scanMap                  sync.Map
	CloudProvider            string
	CloudMetadata            cloudmetadata.CloudMetadata
	AccountID                string
	IsOrganizationDeployment bool
	ComplianceCheckTypes     []string
	ComplianceBenchmark      string
	ScanID                   string
	ScanInactiveThreshold    int // Threshold for inactive scan in seconds
}

func NewCloudComplianceScan(config util.Config) (*CloudComplianceScan, error) {
	return &CloudComplianceScan{
		scanMap:                  sync.Map{},
		CloudProvider:            config.CloudProvider,
		CloudMetadata:            cloudmetadata.CloudMetadata{},
		AccountID:                config.AccountID,
		IsOrganizationDeployment: config.IsOrganizationDeployment,
		ComplianceCheckTypes:     []string{},
		ComplianceBenchmark:      "all",
		ScanID:                   fmt.Sprintf("%s_%s", config.NodeID, util.GetDatetimeNow()),
		ScanInactiveThreshold:    config.ScanInactiveThreshold,
	}, nil
}

func (c *CloudComplianceScan) RunComplianceScanBenchmark(ctx context.Context,
	benchmark ctl.CloudComplianceScanBenchmark, accountId string) (*util.ComplianceGroup, error) {

	tempFileName := fmt.Sprintf("/tmp/%s.json", util.RandomString(12))
	defer os.Remove(tempFileName)
	log.Debug().Msgf("Account ID: %s, config cloud metadata id: %s", accountId, c.CloudMetadata.ID)

	cmdStr := fmt.Sprintf("cd %s && steampipe check --progress=false --output=none --search-path=%s_%s --export=%s %s", cloudProviderPath[c.CloudProvider], c.CloudProvider, strings.Replace(accountId, "-", "", -1), tempFileName, benchmark.Id)
	log.Debug().Msgf("Steampipe command: %s", cmdStr)
	cmd := exec.CommandContext(ctx, "bash", "-c", cmdStr)
	//cmd.Env = os.Environ()
	//cmd.Env = append(cmd.Env, "STEAMPIPE_INTROSPECTION=info")
	stdOut, stdErr := cmd.CombinedOutput()
	if _, err := os.Stat(tempFileName); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s: %v", stdOut, stdErr)
	}
	tempFile, err := os.Open(tempFileName)
	if err != nil {
		return nil, err
	}
	results, err := io.ReadAll(tempFile)
	if err != nil {
		return nil, err
	}
	var complianceResults util.ComplianceGroup
	err = json.Unmarshal(results, &complianceResults)
	if err != nil {
		return nil, err
	}
	complianceResults.ComplianceType = benchmark.ComplianceType
	return &complianceResults, nil
}

func (c *CloudComplianceScan) ScanControl(scan *ctl.CloudComplianceScanDetails) error {
	var errorControlIdWhileScan []string
	var mainErr error

	log.Debug().Msgf("pending scan: %v", scan)

	c.ScanID = scan.ScanId
	c.ComplianceCheckTypes = scan.ScanTypes

	res, scanCtx := tasks.StartStatusReporter(
		scan.ScanId,
		func(status tasks.ScanStatus) error {
			output.WriteScanStatus(status.ScanStatus, status.ScanId, status.ScanMessage)
			return nil
		},
		tasks.StatusValues{
			IN_PROGRESS: "IN_PROGRESS",
			CANCELLED:   "CANCELLED",
			FAILED:      "ERROR",
			SUCCESS:     "COMPLETE",
		},
		time.Duration(c.ScanInactiveThreshold)*time.Second)

	log.Info().Msgf("Adding to scanMap, scanid:%s", scan.ScanId)
	c.scanMap.Store(scan.ScanId, scanCtx)

	outputFile, mainErr := output.NewOutputFile(output.ScanFilename)

	defer func() {
		if mainErr != nil {
			log.Error().Msgf("Error in scan, scanid:%s", scan.ScanId)
		}

		log.Info().Msgf("Removing from scanMap, scanid:%s", scan.ScanId)
		c.scanMap.Delete(scan.ScanId)

		log.Info().Msgf("Stopping status publisher, scanid:%s", scan.ScanId)
		res <- mainErr
		close(res)

		log.Info().Msgf("Status publisher stopped, scanid:%s", scan.ScanId)
		time.Sleep(5 * time.Second)
		if outputFile != nil {
			err := outputFile.CloseOutputFile()
			if err != nil {
				log.Error().Msgf("Failed to close the output file")
			}
		}
	}()

	if mainErr != nil {
		log.Error().Msgf("Error creating output file, filename:%s, error:%s",
			output.ScanFilename, mainErr.Error())
	}

	log.Info().Msgf("compliance scan started: %s", scan.ScanId)
	extrasForInProgress["node_id"] = util.GetNodeID(c.CloudProvider, scan.AccountId)

	stopped := false
	wg := sync.WaitGroup{}
	for _, benchmark := range scan.Benchmarks {
		log.Info().Msgf("scan started for benchmark %s", benchmark.Id)
		err := scanCtx.Checkpoint("Running benchmark:" + benchmark.Id)
		if err != nil {
			mainErr = err
			stopped = true
			break
		}
		complianceResult, err := c.RunComplianceScanBenchmark(scanCtx.Context, benchmark, scan.AccountId)
		if err != nil {
			if scanCtx.Context.Err() == context.Canceled {
				mainErr = err
				stopped = true
				break
			}
			log.Error().Msgf("scan failed for benchmark %s, error:%s", benchmark.Id, err.Error())
			errorControlIdWhileScan = append(errorControlIdWhileScan, benchmark.Id)
			continue
		}

		wg.Add(1)
		go c.PublishBenchmarkResults(&wg, complianceResult, benchmark, scan.AccountId, scan.ScanId, outputFile)

		err = scanCtx.Checkpoint("compliance benchmark " + benchmark.Id + " completed")
		if err != nil {
			stopped = true
			mainErr = err
			break
		}

		log.Info().Msgf("compliance benchmark %s completed for %s", benchmark.Id, scan.ScanId)
	}

	wg.Wait()

	if stopped {
		log.Info().Msgf("Scan stopped by user request, scanid:%s, err:%s",
			scan.ScanId, mainErr.Error())
		scanCtx.StopTriggered.Store(true)
		return mainErr
	}

	if len(errorControlIdWhileScan) == len(scan.Benchmarks) {
		mainErr = errors.New("compliance scan failed for all possible controls")
		tempStr := strings.Join(errorControlIdWhileScan, ", ")
		mainErr = errors.New("compliance scan failed for all possible controls:" + tempStr)
		log.Error().Msgf(mainErr.Error())
		return mainErr
	}

	log.Info().Msgf("scan id %s COMPLETED", scan.ScanId)

	return nil
}

func filterAndPublishDocs(benchmark ctl.CloudComplianceScanBenchmark,
	docs []util.ComplianceDoc, outputFile *output.OutputFile) (util.ComplianceSummary, error) {

	required := map[string]struct{}{}
	for _, c := range benchmark.Controls {
		required[removeModName(c)] = struct{}{}
	}

	log.Debug().Msgf("Number of enabled controls for benchmark %s is %d", benchmark.Id, len(required))

	newSummary := util.ComplianceSummary{}

	dataBuff := bytes.Buffer{}
	for _, d := range docs {
		if _, found := required[d.ControlID]; found {
			jsonBytes, err := json.Marshal(d)
			if err != nil {
				log.Error().Msgf(err.Error())
				return newSummary, err
			}

			dataBuff.Write(jsonBytes)
			dataBuff.WriteString("\n")

			//newDocs = append(newDocs, d)
			// counts for new summary
			newSummary.Total++
			switch d.Status {
			case util.StatusAlarm:
				newSummary.Alarm++
			case util.StatusError:
				newSummary.Error++
			case util.StatusInfo:
				newSummary.Info++
			case util.StatusOk:
				newSummary.Ok++
			case util.StatusSkip:
				newSummary.Skip++
			}
		}
	}

	if dataBuff.Len() > 0 {
		outputFile.WriteData(&dataBuff)
	}
	return newSummary, nil
}

func (c *CloudComplianceScan) StopScan(scanId string) error {
	log.Info().Msgf("StopScan: %s", scanId)
	obj, found := c.scanMap.Load(scanId)
	logMsg := ""
	if !found {
		logMsg = "Failed to Stop scan, may have already completed"
		return nil
	} else {
		scanContext := obj.(*tasks.ScanContext)
		scanContext.StopTriggered.Store(true)
		scanContext.Cancel()
		logMsg = "Stop scan request submitted"
	}

	log.Info().Msgf("%s, scanid:%s", logMsg, scanId)

	return nil
}

func (c *CloudComplianceScan) PublishBenchmarkResults(wg *sync.WaitGroup,
	complianceResults *util.ComplianceGroup, benchmark ctl.CloudComplianceScanBenchmark,
	accountId string, scanId string, outputFile *output.OutputFile) {

	defer wg.Done()

	complianceDocs, complianceSummary, err := c.ParseComplianceResultsForControls([]util.ComplianceGroup{*complianceResults}, accountId)
	if err != nil {
		log.Error().Msgf("Error parsing compliance results for controls: %s", err.Error())
		return
	}

	log.Debug().Msgf("Original compliance benchmark summary: %s benchmark %s - Total=%d Alarm=%d Ok=%d Info=%d Skip=%d Error=%d",
		scanId, benchmark.Id,
		complianceSummary.Total, complianceSummary.Alarm,
		complianceSummary.Ok, complianceSummary.Info,
		complianceSummary.Skip, complianceSummary.Error)

	filteredDocsSummary, err := filterAndPublishDocs(benchmark, complianceDocs, outputFile)
	if err != nil {
		log.Error().Msgf("Error publishing results to management console: %s", err.Error())
		return
	}

	log.Info().Msgf("Compliance benchmark summary: %s benchmark %s - Total=%d Alarm=%d Ok=%d Info=%d Skip=%d Error=%d", scanId, benchmark.Id, filteredDocsSummary.Total, filteredDocsSummary.Alarm,
		filteredDocsSummary.Ok, filteredDocsSummary.Info,
		filteredDocsSummary.Skip, filteredDocsSummary.Error)
}

// ex: removes aws_compliance from aws_compliance.control.control_id
func removeModName(in string) string {
	prefix := strings.Split(in, ".")[0]
	return strings.TrimPrefix(in, prefix+".")
}
