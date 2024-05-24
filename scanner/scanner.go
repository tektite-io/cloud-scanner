package scanner

import (
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

	//"strings"

	cloudmetadata "github.com/deepfence/cloud-scanner/cloud-metadata"
	"github.com/deepfence/cloud-scanner/output"
	"github.com/deepfence/cloud-scanner/util"
	"github.com/sirupsen/logrus"
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
	config  util.Config
	scanMap sync.Map
}

func NewCloudComplianceScan(config util.Config) (*CloudComplianceScan, error) {
	if config.ManagementConsoleUrl == "" {
		config.ManagementConsoleUrl = os.Getenv("MGMT_CONSOLE_URL")
	}
	if config.ManagementConsolePort == "" {
		config.ManagementConsolePort = os.Getenv("MGMT_CONSOLE_PORT")
		if config.ManagementConsolePort == "" {
			config.ManagementConsolePort = "443"
		}
	}
	if config.DeepfenceKey == "" {
		config.DeepfenceKey = os.Getenv("DEEPFENCE_KEY")
	}

	cloudProvider := os.Getenv("CLOUD_PROVIDER")
	cloudAccountID := os.Getenv("CLOUD_ACCOUNT_ID")
	cloudMetadata, err := util.GetCloudMetadata()
	if err == nil {
		cloudProvider = cloudMetadata.CloudProvider
		config.CloudMetadata = cloudMetadata
		if cloudMetadata.ID != "" {
			cloudAccountID = cloudMetadata.ID
		}
	} else {
		config.CloudMetadata = cloudmetadata.CloudMetadata{
			CloudProvider: cloudProvider,
			ID:            cloudAccountID,
		}
	}
	if cloudProvider != util.CloudProviderAWS &&
		cloudProvider != util.CloudProviderGCP &&
		cloudProvider != util.CloudProviderAzure {
		return nil, errors.New("only aws/azure/gcp cloud providers are supported")
	}
	if cloudAccountID == "" {
		return nil, errors.New("env CLOUD_ACCOUNT_ID is not set")
	}

	if config.ComplianceBenchmark != "all" {
		config.ComplianceBenchmark = util.ComplianceBenchmarks[cloudProvider][config.ComplianceBenchmark]
		if config.ComplianceBenchmark == "" {
			availableBenchmarks := []string{"all"}
			for b, _ := range util.ComplianceBenchmarks[cloudProvider] {
				availableBenchmarks = append(availableBenchmarks, b)
			}
			return nil, fmt.Errorf("invalid benchmark, available benchmarks for cloud provider %s: %v", cloudProvider, availableBenchmarks)
		}
	}

	config.NodeId = util.GetNodeId(cloudProvider, cloudAccountID)
	config.NodeName = fmt.Sprintf("%s/%s", cloudProvider, cloudAccountID)
	config.ScanId = fmt.Sprintf("%s_%s", config.NodeId, util.GetDatetimeNow())

	config.CloudProvider = cloudProvider
	return &CloudComplianceScan{
		config:  config,
		scanMap: sync.Map{},
	}, nil
}

func (c *CloudComplianceScan) GetConfig() util.Config {
	return c.config
}

func (c *CloudComplianceScan) RunComplianceScan() (util.ComplianceGroup, error) {
	tempFileName := fmt.Sprintf("/tmp/%s.json", util.RandomString(12))
	defer os.Remove(tempFileName)
	cmd := fmt.Sprintf("cd %s && steampipe check --progress=false --output=none --export=%s %s", cloudProviderPath[c.config.CloudProvider], tempFileName, c.config.ComplianceBenchmark)

	var stdOut []byte
	var stdErr error
	for i := 0; i <= 3; i++ {
		stdOut, stdErr = exec.Command("bash", "-c", cmd).CombinedOutput()
		if stdErr != nil {
			logrus.Errorf("Steampipe check error: %v for query: %s", stdErr, cmd)
			logrus.Error(string(stdOut))
			if strings.Contains(string(stdOut), util.ErrSteampipeDB) || strings.Contains(string(stdOut), util.ErrSteampipeInvalidClientTokenID) {
				util.RestartSteampipeService()
			} else {
				time.Sleep(util.SleepTime)
			}
			os.Remove(tempFileName)
			continue
		} else {
			break
		}
	}

	var complianceResults util.ComplianceGroup
	if _, err := os.Stat(tempFileName); errors.Is(err, os.ErrNotExist) {
		return complianceResults, fmt.Errorf("%s: %v", stdOut, stdErr)
	}
	tempFile, err := os.Open(tempFileName)
	if err != nil {
		return complianceResults, err
	}
	results, err := io.ReadAll(tempFile)
	if err != nil {
		return complianceResults, err
	}
	err = json.Unmarshal(results, &complianceResults)
	if err != nil {
		return complianceResults, err
	}
	return complianceResults, nil
}

func (c *CloudComplianceScan) RunComplianceScanBenchmark(ctx context.Context,
	benchmark util.Benchmark, accountId string) (*util.ComplianceGroup, error) {

	tempFileName := fmt.Sprintf("/tmp/%s.json", util.RandomString(12))
	defer os.Remove(tempFileName)
	//whereClause := fmt.Sprintf("resource_name IN (\"%s\")", strings.Join(benchmark.Controls, "\",\""))
	logrus.Debug("Account ID: ", accountId, "config cloud metadata id: ", c.config.CloudMetadata.ID)

	//cmdStr := fmt.Sprintf("cd %s && steampipe check --progress=false --output=none --export=%s --where=\"%s\" %s", cloudProviderPath[c.config.CloudProvider], tempFileName, whereClause, benchmark.Id)
	cmdStr := fmt.Sprintf("cd %s && steampipe check --progress=false --output=none --export=%s %s",
		cloudProviderPath[c.config.CloudProvider], tempFileName, benchmark.Id)
	if accountId != c.config.CloudMetadata.ID {
		logrus.Info("Steampipe check assuming role for account ", accountId)
		//cmdStr = fmt.Sprintf("cd %s && steampipe check --progress=false --output=none --search-path=aws_%s --export=%s --where=\"%s\" %s", cloudProviderPath[c.config.CloudProvider], accountId, tempFileName, whereClause, benchmark.Id)
		cmdStr = fmt.Sprintf("cd %s && steampipe check --progress=false --output=none --search-path=%s_%s --export=%s %s", cloudProviderPath[c.config.CloudProvider], c.config.CloudProvider, strings.Replace(accountId, "-", "", -1), tempFileName, benchmark.Id)
	}
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

func (c *CloudComplianceScan) PublishResultsToManagementConsole(
	publisher *output.Publisher,
	complianceDocs []util.ComplianceDoc,
	accountId string,
) error {
	err := publisher.IngestComplianceResults(complianceDocs)
	if err != nil {
		logrus.Error(err)
		return err
	}
	return nil
}

func (c *CloudComplianceScan) Scan() error {
	complianceResults, err := c.RunComplianceScan()
	if err != nil {
		return err
	}
	complianceDocs, complianceSummary, err := c.ParseComplianceResults(complianceResults, c.config.CloudMetadata.ID)
	if err != nil {
		return err
	}

	if c.config.Mode == util.ModeService {
		publisher, err := output.NewPublisher(c.config)
		if err != nil {
			return err
		}
		err = c.PublishResultsToManagementConsole(publisher, complianceDocs, c.config.CloudMetadata.ID)
		if err != nil {
			return err
		}
		extras := map[string]interface{}{
			"node_id":      util.GetNodeId(c.config.CloudProvider, c.config.CloudMetadata.ID),
			"result":       complianceSummary,
			"total_checks": complianceSummary.Total,
		}
		publisher.PublishScanStatusMessage(c.config.ScanId, c.config.ComplianceCheckTypes, "", "COMPLETE", extras)
		if !c.config.Quiet {
			err = publisher.Output(complianceDocs, complianceSummary)
			if err != nil {
				return err
			}
		}
	} else {
		publisher, err := output.NewCliPublisher(c.config)
		if err != nil {
			return err
		}
		if !c.config.Quiet {
			err = publisher.Output(complianceDocs, complianceSummary)
			if err != nil {
				return err
			}
		}
		if c.config.FileOutput != "" {
			err = publisher.WriteFile(c.config.FileOutput, complianceDocs)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *CloudComplianceScan) ScanControl(scan *util.PendingScan) error {
	var errorControlIdWhileScan []string
	var publisher *output.Publisher
	publisher, err := output.NewPublisher(c.config)
	if err != nil {
		return err
	}

	logrus.Debugf("pending scan: %v", scan)

	c.config.ScanId = scan.ScanId
	c.config.ComplianceCheckTypes = scan.ScanTypes

	logrus.Infof("Adding to scanMap, scanid:%s", scan.ScanId)
	ctx, cancelFn := context.WithCancel(context.Background())
	c.scanMap.Store(scan.ScanId, cancelFn)
	defer func() {
		logrus.Infof("Removing from scanMap, scanid:%s", scan.ScanId)
		c.scanMap.Delete(scan.ScanId)
	}()

	logrus.Infof("compliance scan started: %s", scan.ScanId)
	extrasForInProgress["node_id"] = util.GetNodeId(c.config.CloudProvider, scan.AccountId)
	publisher.PublishScanStatusMessage(c.config.ScanId,
		c.config.ComplianceCheckTypes, "", "IN_PROGRESS", extrasForInProgress)

	stopped := false
	for _, benchmark := range scan.Benchmarks {
		logrus.Infof("scan started for benchmark %s", benchmark.Id)
		complianceResult, err := c.RunComplianceScanBenchmark(ctx, benchmark, scan.AccountId)
		if err != nil {
			if ctx.Err() == context.Canceled {
				stopped = true
				break
			}
			logrus.Error("scan failed for benchmark ", benchmark.Id, err.Error())
			errorControlIdWhileScan = append(errorControlIdWhileScan, benchmark.Id)
			continue
		}
		if !stopped {
			go c.PublishBenchmarkResults(publisher, complianceResult, benchmark, scan.AccountId, scan.ScanId)
		}
		logrus.Infof("compliance benchmark %s completed for %s", benchmark.Id, scan.ScanId)
	}

	if stopped {
		logrus.Infof("Scan stopped by user request, scanid:%s", scan.ScanId)
		publisher.PublishScanStatusMessage(c.config.ScanId, c.config.ComplianceCheckTypes,
			"Scan stopped by user request", "CANCELLED", extrasForInProgress)
		return nil
	}

	if len(errorControlIdWhileScan) == len(scan.Benchmarks) {
		logrus.Error("compliance scan failed for all possible controls")
		publisher.PublishScanStatusMessage(c.config.ScanId, c.config.ComplianceCheckTypes,
			"compliance scan failed for all possible controls", "ERROR", extrasForInProgress)
		return errors.New("compliance scan failed for all possible controls")
	}

	// scan completed succesfully
	extras := map[string]interface{}{
		"node_id": util.GetNodeId(c.config.CloudProvider, scan.AccountId),
	}
	publisher.PublishScanStatusMessage(c.config.ScanId, c.config.ComplianceCheckTypes, "", "COMPLETE", extras)

	logrus.Infof("scan id %s COMPLETED", scan.ScanId)

	return nil
}

func (c *CloudComplianceScan) PublishBenchmarkResults(
	publisher *output.Publisher, complianceResults *util.ComplianceGroup,
	benchmark util.Benchmark, accountId string, scanId string,
) {

	complianceDocs, complianceSummary, err := c.ParseComplianceResultsForControls([]util.ComplianceGroup{*complianceResults}, accountId)
	if err != nil {
		logrus.Errorf("Error parsing compliance results for controls: %s", err.Error())
		//publisher.PublishScanStatusMessage(c.config.ScanId, c.config.ComplianceCheckTypes, err.Error(), "ERROR", extrasForInProgress)
		return
	}

	logrus.Debugf("Original compliance benchmark summary: %s benchmark %s - Total=%d Alarm=%d Ok=%d Info=%d Skip=%d Error=%d",
		scanId, benchmark.Id,
		complianceSummary.Total, complianceSummary.Alarm,
		complianceSummary.Ok, complianceSummary.Info,
		complianceSummary.Skip, complianceSummary.Error)

	filteredDocs, filteredDocsSummary := filterDocs(benchmark, complianceDocs)

	err = c.PublishResultsToManagementConsole(publisher, filteredDocs, accountId)
	if err != nil {
		logrus.Errorf("Error publishing results to management console: %s", err.Error())
		//publisher.PublishScanStatusMessage(c.config.ScanId, c.config.ComplianceCheckTypes, err.Error(), "ERROR", extrasForInProgress)
		return
	}

	logrus.Infof("Compliance benchmark summary: %s benchmark %s - Total=%d Alarm=%d Ok=%d Info=%d Skip=%d Error=%d",
		scanId, benchmark.Id,
		filteredDocsSummary.Total, filteredDocsSummary.Alarm,
		filteredDocsSummary.Ok, filteredDocsSummary.Info,
		filteredDocsSummary.Skip, filteredDocsSummary.Error)
}

func filterDocs(benchmark util.Benchmark, docs []util.ComplianceDoc) ([]util.ComplianceDoc, util.ComplianceSummary) {

	required := map[string]struct{}{}
	for _, c := range benchmark.Controls {
		required[removeModName(c)] = struct{}{}
	}

	logrus.Debugf("Number of enabled controls for benchmark %s is %d", benchmark.Id, len(required))

	newDocs := []util.ComplianceDoc{}
	newSummary := util.ComplianceSummary{}

	for _, d := range docs {
		if _, found := required[d.ControlID]; found {
			newDocs = append(newDocs, d)
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

	return newDocs, newSummary
}

// ex: removes aws_compliance from aws_compliance.control.control_id
func removeModName(in string) string {
	prefix := strings.Split(in, ".")[0]
	return strings.TrimPrefix(in, prefix+".")
}

func (c *CloudComplianceScan) PublishScanStatus(runningScanMap map[string]struct{}, remainingScansMap util.PendingScanMap) {
	publisher, err := output.NewPublisher(c.config)
	if err != nil {
		logrus.Errorf("Error sending progress status: %v", err)
		return
	}
	for scanId := range runningScanMap {
		extrasForInProgress["node_id"] = util.GetNodeId(c.config.CloudProvider, remainingScansMap[scanId].AccountId)
		publisher.PublishScanStatusMessage(scanId, remainingScansMap[scanId].ScanTypes, "", "IN_PROGRESS", extrasForInProgress)
	}
}

func (c *CloudComplianceScan) StopScan(scanId string) error {
	logrus.Infof("StopScan: %s", scanId)
	cancelFnObj, found := c.scanMap.Load(scanId)
	logMsg := ""
	if !found {
		logMsg = "Failed to Stop scan, may have already completed"
	} else {
		cancelFn := cancelFnObj.(context.CancelFunc)
		cancelFn()
		logMsg = "Stop scan request submitted"
	}

	logrus.Infof("%s, scanid:%s", logMsg, scanId)

	return nil
}
