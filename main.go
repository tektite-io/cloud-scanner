package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/deepfence/cloud-scanner/internal/deepfence"

	"github.com/deepfence/cloud-scanner/scanner"
	"github.com/deepfence/cloud-scanner/service"
	"github.com/deepfence/cloud-scanner/util"
	"github.com/sirupsen/logrus"
)

var (
	mode                  = flag.String("mode", util.ModeCli, "cli or service")
	output                = flag.String("output", util.TextOutput, "Output format: json, table or text")
	benchmark             = flag.String("benchmark", "all", "Benchmarks: cis, gdpr, hipaa, pci, soc2, nist")
	fileOutput            = flag.String("file", "", "File to write the output to")
	quiet                 = flag.Bool("quiet", false, "Don't display any output in stdout")
	managementConsoleUrl  = flag.String("mgmt-console-url", "", "Deepfence Management Console URL")
	managementConsolePort = flag.Int("mgmt-console-port", 443, "Deepfence Management Console Port")
	deepfenceKey          = flag.String("deepfence-key", "", "Deepfence key for auth")
	complianceCheckTypes  = flag.String("compliance-check-types", "all", "Compliance check types separated by comma")
	httpServerRequired    = flag.Bool("http-server-required", false, "HTTP Service required")
	debug                 = flag.String("debug", "false", "set log level to debug")
	multipleAccountIds    = flag.String("multiple-acc-ids", "", "List of comma-separated account ids to monitor")
	orgAccountId          = flag.String("org-acc-id", "", "Account id of parent organization account")
	rolePrefix            = flag.String("role-prefix", "deepfence-cloud-scanner", "Prefix for role to be assumed in monitored accounts")
	roleName              = flag.String("role-name", "SecurityAuditExtended", "Name for role to be assumed in monitored accounts")
	awsAccessKeyID        = flag.String("aws-access-key-id", "", "AWS Access Key ID to for the service account to assume the RoleName in the monitored accounts")
	awsSecretAccessKey    = flag.String("aws-secret-access-key", "", "AWS Secret Access Key to for the service account to assume the RoleName in the monitored accounts")
	successSignalUrl      = flag.String("success-signal-url", "", "URL to send notification for successful deployment of ECS Task")
	cloudAuditLogIDs      = flag.String("cloud-audit-log-ids", "", "Comma separated IDs of CloudTrail/Azure Monitor Logs/Cloud Audit Logs to enable refreshing cloud resources every hour")
	commaSplitRegex       = regexp.MustCompile(`\s*,\s*`)
)

func runOnce(config util.Config) {
	if config.Output != util.TableOutput && config.Output != util.JsonOutput && config.Output != util.TextOutput {
		logrus.Errorf("Error: output should be %s, %s or %s", util.JsonOutput, util.TableOutput, util.TextOutput)
		return
	}
	cloudComplianceScan, err := scanner.NewCloudComplianceScan(config)
	if err != nil {
		logrus.Errorf("Error: %v", err)
		return
	}
	err = cloudComplianceScan.Scan()
	if err != nil {
		logrus.Errorf("Error: %v", err)
		return
	}
}

func runServices(config util.Config) {
	svc, err := service.NewComplianceScanService(config)
	if err != nil {
		logrus.Errorf("Error: %v", err)
		time.Sleep(1 * time.Minute)
		return
	}
	logrus.Info("Registering with Deepfence management console")
	err = svc.RunRegisterServices()
	if err != nil {
		logrus.Errorf("Error: %v", err)
	}
}

func main() {
	flag.Parse()

	customFormatter := new(logrus.TextFormatter)
	customFormatter.FullTimestamp = true
	customFormatter.DisableLevelTruncation = true
	customFormatter.PadLevelText = true
	customFormatter.TimestampFormat = "2006-01-02 15:04:05"
	customFormatter.CallerPrettyfier = func(f *runtime.Frame) (string, string) {
		return "", path.Base(f.File) + ":" + strconv.Itoa(f.Line)
	}

	logrus.SetReportCaller(true)
	logrus.SetFormatter(customFormatter)
	if *debug == "true" {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
	logFile, err := os.OpenFile(service.HomeDirectory+"/.steampipe/logs/cloud_scanner.log", os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		fmt.Printf("error opening file: %v", err)
	}

	defer logFile.Close()
	mw := io.MultiWriter(os.Stdout, logFile)
	logrus.SetOutput(mw)
	if *successSignalUrl != "" {
		deepfence.SendSuccessfulDeploymentSignal(*successSignalUrl)
	}

	var cloudAuditLogsIDs []string
	if *cloudAuditLogIDs != "" {
		cloudAuditLogsIDs = strings.Split(*cloudAuditLogIDs, ",")
	}
	config := util.Config{
		Mode:                  *mode,
		Output:                *output,
		Quiet:                 *quiet,
		ManagementConsoleUrl:  strings.TrimPrefix(*managementConsoleUrl, "https://"),
		ManagementConsolePort: strconv.Itoa(*managementConsolePort),
		DeepfenceKey:          *deepfenceKey,
		ComplianceCheckTypes:  strings.Split(*complianceCheckTypes, ","),
		HttpServerRequired:    *httpServerRequired,
		RolePrefix:            *rolePrefix,
		RoleName:              *roleName,
		AwsAccessKeyId:        *awsAccessKeyID,
		AwsSecretAccessKey:    *awsSecretAccessKey,
		CloudAuditLogsIDs:     cloudAuditLogsIDs,
	}
	if *multipleAccountIds != "" {
		if *orgAccountId == "" {
			logrus.Error("Error: Organization Account ID is mandatory for organization accounts setup")
			return
		}
		config.MultipleAccountIds = commaSplitRegex.Split(*multipleAccountIds, -1)
		config.OrgAccountId = *orgAccountId
		config.IsOrganizationDeployment = true
	}

	if *mode == util.ModeCli {
		config.ComplianceBenchmark = *benchmark
		config.FileOutput = *fileOutput
		runOnce(config)
	} else if *mode == util.ModeService {
		config.ComplianceBenchmark = "all"
		runServices(config)
	} else {
		logrus.Error("Error: invalid mode")
	}
}
