package output

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/deepfence/ThreatMapper/deepfence_utils/utils"
	"github.com/deepfence/cloud-scanner/internal/deepfence"
	"github.com/deepfence/cloud-scanner/util"
	"github.com/olekukonko/tablewriter"
	"github.com/sirupsen/logrus"
)

type Publisher struct {
	config         util.Config
	dfClient       *deepfence.Client
	stopScanStatus chan bool
}

func NewPublisher(config util.Config) (*Publisher, error) {
	dfClient, err := deepfence.NewClient(config)
	if err != nil {
		return nil, err
	}
	return &Publisher{
		config:         config,
		dfClient:       dfClient,
		stopScanStatus: make(chan bool, 1),
	}, nil
}

func NewCliPublisher(config util.Config) (*Publisher, error) {
	return &Publisher{
		config: config,
	}, nil
}

func (p *Publisher) PublishScanStatusMessage(scanId string, scanTypes []string, message string, status string, extras map[string]interface{}) {

	ccstatus := deepfence.CloudComplianceScanStatus{
		ScanId:               scanId,
		ScanMessage:          message,
		ScanStatus:           status,
		NodeId:               "",
		ComplianceCheckTypes: scanTypes,
		Result:               deepfence.IngestersComplianceStats{},
		TotalChecks:          0,
		Type:                 "",
	}

	utils.FromMap(extras, &ccstatus)

	err := p.dfClient.SendScanStatusToConsole(ccstatus)
	if err != nil {
		logrus.Error(scanId, " ", err.Error())
	}
	logrus.Info(scanId + " " + status)
}

func (p *Publisher) PublishScanError(scanId string, scanType string, errMsg string) {
	p.stopScanStatus <- true
	time.Sleep(3 * time.Second)
	//p.PublishScanStatusMessage(scanId, scanType, errMsg, "ERROR", nil)
}

// func (p *Publisher) PublishScanStatus(scanId string, scanType string, status string) {
//	go func() {
//		p.PublishScanStatusMessage(scanId, scanType, "", status, nil)
//		ticker := time.NewTicker(2 * time.Minute)
//		for {
//			select {
//			case <-ticker.C:
//				p.PublishScanStatusMessage(scanId, scanType, "", status, nil)
//			case <-p.stopScanStatus:
//				return
//			}
//		}
//	}()
//}

func (p *Publisher) StopPublishScanStatus() {
	p.stopScanStatus <- true
	time.Sleep(3 * time.Second)
}

func (p *Publisher) IngestComplianceResults(complianceDocs []util.ComplianceDoc) error {
	return p.dfClient.IngestComplianceResults(complianceDocs)
}

func (p *Publisher) OutputSummary(complianceSummary util.ComplianceSummary) {
	fmt.Println(p.config.NodeName + " - " + p.config.ComplianceBenchmark)
	fmt.Printf("Total Results: %d\n", complianceSummary.Total)
	fmt.Printf("Alarm: %d\n", complianceSummary.Alarm)
	fmt.Printf("Ok: %d\n", complianceSummary.Ok)
	fmt.Printf("Info: %d\n", complianceSummary.Info)
	fmt.Printf("Skip: %d\n", complianceSummary.Skip)
	fmt.Printf("Error: %d\n", complianceSummary.Error)
}

func (p *Publisher) Output(complianceDocs []util.ComplianceDoc, complianceSummary util.ComplianceSummary) error {
	var err error
	if p.config.Output == util.TextOutput {
		p.OutputSummary(complianceSummary)
	} else if p.config.Output == util.JsonOutput {
		var complianceCheck []byte
		for _, complianceDoc := range complianceDocs {
			complianceCheck, err = json.MarshalIndent(complianceDoc, "", "\t")
			if err == nil {
				fmt.Println(string(complianceCheck))
			}
		}
	} else if p.config.Output == util.TableOutput {
		p.OutputSummary(complianceSummary)
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Service", "Group", "Title", "Resource", "Status"})
		table.SetHeaderLine(true)
		table.SetBorder(true)
		table.SetAutoWrapText(true)
		table.SetAutoFormatHeaders(true)
		table.SetColMinWidth(0, 10)
		table.SetColMinWidth(1, 15)
		table.SetColMinWidth(2, 15)
		table.SetColMinWidth(3, 15)
		table.SetColMinWidth(4, 50)
		for _, complianceDoc := range complianceDocs {
			table.Append([]string{
				complianceDoc.Service,
				complianceDoc.Group,
				complianceDoc.Title,
				complianceDoc.Status,
				complianceDoc.Resource,
			})
		}
		table.Render()
	}
	return nil
}

func (p *Publisher) WriteFile(filePath string, complianceDocs []util.ComplianceDoc) error {
	jsonString, err := json.MarshalIndent(complianceDocs, "", "\t")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, jsonString, os.ModePerm)
}
