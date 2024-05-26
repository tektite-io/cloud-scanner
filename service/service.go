package service

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Jeffail/tunny"
	cloud_metadata "github.com/deepfence/cloud-scanner/cloud-metadata"
	"github.com/deepfence/cloud-scanner/cloud_resource_changes"
	"github.com/deepfence/cloud-scanner/internal/deepfence"
	"github.com/deepfence/cloud-scanner/query_resource"
	"github.com/deepfence/cloud-scanner/scanner"
	"github.com/deepfence/cloud-scanner/util"
	"github.com/sirupsen/logrus"
)

const DefaultScanConcurrency = 1

var (
	scanConcurrency int
	scanPool        *tunny.Pool
	HomeDirectory   string
)

type CloudResources struct {
	sync.RWMutex
}

type ComplianceScanService struct {
	scanner              *scanner.CloudComplianceScan
	dfClient             *deepfence.Client
	config               util.Config
	accountID            []string
	RemainingScansMap    util.PendingScanMap
	runningScanMap       map[string]struct{}
	refreshResources     bool
	cloudResources       *CloudResources
	CloudTrails          []util.CloudTrailDetails
	CloudResourceChanges cloud_resource_changes.CloudResourceChanges
}

func init() {
	var err error
	scanConcurrency, err = strconv.Atoi(os.Getenv("SCAN_CONCURRENCY"))
	if err != nil {
		scanConcurrency = DefaultScanConcurrency
	}
	scanPool = tunny.NewFunc(scanConcurrency, executeScans)
	HomeDirectory = os.Getenv("HOME_DIR")
	if HomeDirectory == "" {
		HomeDirectory = "/home/deepfence"
	}
}

func NewComplianceScanService(config util.Config) (*ComplianceScanService, error) {
	logrus.Debug("NewComplianceScanService")
	config.Quiet = true
	cloudComplianceScan, err := scanner.NewCloudComplianceScan(config)
	if err != nil {
		logrus.Debugf("scanner.NewCloudComplianceScan error: %s", err.Error())
		return nil, err
	}
	config = cloudComplianceScan.GetConfig()
	dfClient, err := deepfence.NewClient(config)
	if err != nil {
		logrus.Debugf("deepfence.NewClient(config) error: %s", err.Error())
		return nil, err
	}
	if config.CloudMetadata.ID == "" {
		logrus.Debugf("empty cloud metadata id from deepfence.NewClient(config)")
		return nil, errors.New("could not fetch cloud account/subscription id")
	}
	remainingScansMap := make(util.PendingScanMap)
	runningScansMap := make(map[string]struct{})
	cloudTrails := make([]util.CloudTrailDetails, 0)
	cloudResourceChanges, err := cloud_resource_changes.NewCloudResourceChanges(config)
	if err != nil {
		return nil, err
	}
	return &ComplianceScanService{
		scanner:              cloudComplianceScan,
		dfClient:             dfClient,
		config:               config,
		RemainingScansMap:    remainingScansMap,
		runningScanMap:       runningScansMap,
		refreshResources:     false,
		cloudResources:       &CloudResources{},
		CloudTrails:          cloudTrails,
		CloudResourceChanges: cloudResourceChanges,
	}, err
}

func (c *ComplianceScanService) RunRegisterServices() error {
	if c.config.CloudProvider == cloud_metadata.CloudProviderAWS {
		processAwsCredentials(c)
	} else if c.config.CloudProvider == cloud_metadata.CloudProviderGCP {
		err := processGcpCredentials(c)
		if err != nil {
			logrus.Fatal(err)
		}
	} else if c.config.CloudProvider == cloud_metadata.CloudProviderAzure {
		processAzureCredentials()
	}

	util.RestartSteampipeService()

	err := c.CloudResourceChanges.Initialize()
	if err != nil {
		logrus.Warn(err.Error())
	}
	StopScanMap := make(map[string]bool)

	c.RemainingScansMap, c.refreshResources, c.CloudTrails, StopScanMap, err = c.dfClient.RegisterCloudAccount(c.config.CloudProvider, c.config.CloudMetadata.ID, c.config.MultipleAccountIds, &c.config.OrgAccountId, c.RemainingScansMap)
	if err != nil {
		return err
	}

	if c.config.HttpServerRequired {
		go c.runHttpServer()
	}
	go c.queryAndRegisterCloudResources()

	for scanId, _ := range StopScanMap {
		err := c.scanner.StopScan(scanId)
		if err != nil {
			logrus.Error("Error in StopScan:" + err.Error())
		}
	}

	ticker := time.NewTicker(1 * time.Minute)
	dayTicker := time.NewTicker(24 * time.Hour)
	hourTicker := time.NewTicker(1 * time.Hour)

	for {
		select {
		case <-ticker.C:
			c.RemainingScansMap, c.refreshResources, c.CloudTrails, StopScanMap, err = c.dfClient.RegisterCloudAccount(c.config.CloudProvider, c.config.CloudMetadata.ID, c.config.MultipleAccountIds, &c.config.OrgAccountId, c.RemainingScansMap)
			if err != nil {
				logrus.Error(err)
			}

			if c.refreshResources {
				go c.queryAndRegisterCloudResources()
			}

			for scanId, _ := range StopScanMap {
				err := c.scanner.StopScan(scanId)
				if err != nil {
					logrus.Error("Error in StopScan:" + err.Error())
				}
			}

			go scanPool.Process(c)

			go c.scanner.PublishScanStatus(c.runningScanMap, c.RemainingScansMap)
		case <-dayTicker.C:
			go c.queryAndRegisterCloudResources()
		case <-hourTicker.C:
			go c.refreshResourcesFromTrail()
		}
	}
}

func processAzureCredentials() {
	err := os.Remove(HomeDirectory + "/.steampipe/config/azure.spc")
	if err != nil {
		logrus.Warn(err)
	}
	f2, err := os.OpenFile(HomeDirectory+"/.steampipe/config/azure.spc", os.O_WRONLY|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logrus.Fatal(err)
	}
	if _, err = f2.Write([]byte("\nconnection \"azure\" {\n  plugin = \"azure\"\n " +
		"  subscription_id = \"" + os.Getenv("AZURE_SUBSCRIPTION_ID") + "\"\n" +
		"  tenant_id = \"" + os.Getenv("AZURE_TENANT_ID") + "\"\n" +
		"  client_id = \"" + os.Getenv("AZURE_CLIENT_ID") + "\"\n" +
		"  client_secret = \"" + os.Getenv("AZURE_CLIENT_SECRET") + "\"\n" +
		"  ignore_error_codes = [\"AccessDenied\", \"AccessDeniedException\", \"NotAuthorized\", \"UnauthorizedOperation\", \"AuthorizationError\"]\n}\n")); err != nil {
		f2.Close()
		logrus.Fatal(err)
	}
	if err = f2.Close(); err != nil {
		logrus.Fatal(err)
	}
}

func useServiceAccountAwsCredentials(c util.Config) bool {
	return c.AwsAccessKeyId != "" && c.AwsSecretAccessKey != "" && c.RoleName != ""
}

func createServiceAccountAwsConfig(c util.Config) (error, string) {
	if c.AwsAccessKeyId == "" || c.AwsSecretAccessKey == "" {
		return errors.New("aws access key id and aws secret access key cannot be empty"), ""
	}
	serviceAccountConfig := fmt.Sprintf("\n[service_account]\naws_access_key_id = %s\naws_secret_access_key = %s\n", c.AwsAccessKeyId, c.AwsSecretAccessKey)
	return nil, serviceAccountConfig
}

func createAwsProfileConfig(accountId string, roleName string) string {
	profileConfig := fmt.Sprintf("\n[profile_%s]\nrole_arn = arn:aws:iam::%s:role/%s\nsource_profile = service_account\n", accountId, accountId, roleName)
	return profileConfig
}

func processAwsCredentials(c *ComplianceScanService) {
	regionString := "regions = [\"*\"]\n"
	svc := useServiceAccountAwsCredentials(c.config)
	if len(c.config.MultipleAccountIds) > 0 {
		os.MkdirAll(HomeDirectory+"/.aws", os.ModePerm)
		aggr := "connection \"aws_all\" {\n  type = \"aggregator\" \n plugin      = \"aws\" \n  connections = [\"aws_*\"] \n} \n"
		spcFile, err := os.OpenFile(HomeDirectory+"/.steampipe/config/aws.spc", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		defer spcFile.Close()
		if err != nil {
			logrus.Fatal(err)
		}
		if _, err = spcFile.Write([]byte(aggr)); err != nil {
			spcFile.Close()
			logrus.Fatal(err)
		}

		// Delete the existing credentials file
		awsCredentialsFile := HomeDirectory + "/.aws/credentials"

		// if service account credentials are provided
		if svc {
			_, serviceAccountAwsConfig := createServiceAccountAwsConfig(c.config)
			f1, err := os.OpenFile(awsCredentialsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				logrus.Fatal(err)
			}
			if _, err = f1.Write([]byte(serviceAccountAwsConfig)); err != nil {
				f1.Close()
				logrus.Fatal(err)
			}
		}

		for _, accId := range c.config.MultipleAccountIds {
			f1, err := os.OpenFile(awsCredentialsFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				logrus.Fatal(err)
			}

			if svc {
				profileConfig := createAwsProfileConfig(accId, c.config.RoleName)
				if _, err = f1.Write([]byte(profileConfig)); err != nil {
					f1.Close()
					logrus.Fatal(err)
				}
			} else {
				if _, err = f1.Write([]byte("\n[profile_" + accId + "]\nrole_arn = arn:aws:iam::" + accId + ":role/" + c.config.RolePrefix + "-mem-acc-read-only-access\ncredential_source = EcsContainer\n")); err != nil {
					f1.Close()
					logrus.Fatal(err)
				}
			}
			if err = f1.Close(); err != nil {
				logrus.Fatal(err)
			}
			if _, err = spcFile.Write([]byte("\nconnection \"aws_" + accId + "\" {\n  plugin = \"aws\"\n  profile = \"profile_" + accId + "\"\n  " + regionString + "  max_error_retry_attempts = 10\n  ignore_error_codes = [\"AccessDenied\", \"AccessDeniedException\", \"NotAuthorized\", \"UnauthorizedOperation\", \"AuthorizationError\"]\n}\n")); err != nil {
				spcFile.Close()
				logrus.Fatal(err)
			}
		}
		if err = spcFile.Close(); err != nil {
			logrus.Fatal(err)
		}
	} else {
		err := os.Remove(HomeDirectory + "/.steampipe/config/aws.spc")
		if err != nil {
			logrus.Warn(err)
		}
		f2, err := os.OpenFile(HomeDirectory+"/.steampipe/config/aws.spc", os.O_WRONLY|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logrus.Fatal(err)
		}
		if _, err = f2.Write([]byte("\nconnection \"aws\" {\n  plugin = \"aws\"\n  " + regionString + "  max_error_retry_attempts = 10\n  ignore_error_codes = [\"AccessDenied\", \"AccessDeniedException\", \"NotAuthorized\", \"UnauthorizedOperation\", \"AuthorizationError\"]\n}\n")); err != nil {
			f2.Close()
			logrus.Fatal(err)
		}
		if err = f2.Close(); err != nil {
			logrus.Fatal(err)
		}
	}
}

func processGcpCredentials(c *ComplianceScanService) error {
	if len(c.config.MultipleAccountIds) > 0 {
		aggr := "connection \"gcp_all\" {\n  type = \"aggregator\" \n plugin      = \"gcp\" \n  connections = [\"gcp_*\"] \n} \n"
		spcFile, err := os.OpenFile(HomeDirectory+"/.steampipe/config/gcp.spc", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		if _, err = spcFile.Write([]byte(aggr)); err != nil {
			spcFile.Close()
			return err
		}
		for _, accId := range c.config.MultipleAccountIds {
			accString := "connection \"gcp_" + strings.Replace(accId, "-", "", -1) + "\" {\n  plugin  = \"gcp\"\n  project = \"" + accId + "\"\n}\n"
			if _, err = spcFile.Write([]byte(accString)); err != nil {
				spcFile.Close()
				return err
			}
		}
		if err = spcFile.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (c *ComplianceScanService) queryAndRegisterCloudResources() {
	logrus.Info("Querying Resources")
	c.cloudResources.Lock()
	errorsCollected := query_resource.QueryAndRegisterResources(c.config, c.dfClient)
	if len(errorsCollected) > 0 {
		logrus.Errorf("Error in sending resources  %+v", errorsCollected)
	}
	c.cloudResources.Unlock()
}

func (c *ComplianceScanService) refreshResourcesFromTrail() {
	cloudResourceTypesToRefresh, _ := c.CloudResourceChanges.GetResourceTypesToRefresh()
	logrus.Infof("Refreshing resources from trail: %d", len(cloudResourceTypesToRefresh))
	if len(cloudResourceTypesToRefresh) == 0 {
		return
	}

	c.cloudResources.Lock()
	errorsCollected := query_resource.QueryAndUpdateResources(c.config, c.dfClient, cloudResourceTypesToRefresh)
	if len(errorsCollected) > 0 {
		logrus.Errorf("Error in sending resources  %+v", errorsCollected)
	}
	c.cloudResources.Unlock()
}

func executeScans(rInterface interface{}) interface{} {
	c, ok := rInterface.(*ComplianceScanService)
	if !ok {
		logrus.Error("Error processing compliance scan service")
		return false
	}
	logrus.Debugf("c.RemainingScansMap: %+v", c.RemainingScansMap)
	for scanId, scan := range c.RemainingScansMap {
		if _, ok := c.runningScanMap[scanId]; !ok {
			logrus.Info("Running scan with id: ", scanId)
			c.runningScanMap[scanId] = struct{}{}
			err := c.scanner.ScanControl(&scan)
			if err != nil {
				logrus.Error(err.Error())
			}
			c.delayedRemoveFromRunningScanMap(scanId)
		} else {
			logrus.Infof("Scan already running with scanid: %s", scanId)
		}
	}
	return true
}

func (c *ComplianceScanService) delayedRemoveFromRunningScanMap(scanId string) {
	// time.Sleep(5 * time.Minute)
	delete(c.RemainingScansMap, scanId)
	delete(c.runningScanMap, scanId)
}

func (c *ComplianceScanService) runHttpServer() {
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "hello world\n")
	})
	err := http.ListenAndServe(":8080", nil)
	logrus.Error(err)
}
