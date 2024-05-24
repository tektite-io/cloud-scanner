package service

import (
	"github.com/deepfence/cloud-scanner/util"
	"testing"
)

// Verify correct format when valid AWS credentials are provided
func TestCreateServiceAccountAwsConfigSuccess(t *testing.T) {
	config := util.Config{
		AwsAccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
		AwsSecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	err, serviceAccountConfig := createServiceAccountAwsConfig(config)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	expectedConfig := "\n[service_account]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
	if serviceAccountConfig != expectedConfig {
		t.Errorf("Expected %s, got %s", expectedConfig, serviceAccountConfig)
	}
}

// Test with empty strings for AWS access key and secret access key
func TestCreateServiceAccountAwsConfigMissingAccessKey(t *testing.T) {
	config := util.Config{
		AwsAccessKeyId:     "",
		AwsSecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	err, _ := createServiceAccountAwsConfig(config)
	if err == nil {
		t.Error("Expected an error, got none")
	}
	expectedErrorMessage := "aws access key id, aws secret access key cannot be empty"
	if err.Error() != expectedErrorMessage {
		t.Errorf("Expected error message %s, got %s", expectedErrorMessage, err.Error())
	}
}

func TestCreateAwsProfileConfigWithValidInputs(t *testing.T) {
	accountId := "123456789012"
	roleName := "SecurityAuditExtended"
	expected := "\n[profile_123456789012]\nrole_arn = arn:aws:iam::123456789012:role/SecurityAuditExtended\nsource_profile = service_account\n"
	result := createAwsProfileConfig(accountId, roleName)
	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}

func TestCreateAwsProfileConfigWithEmptyStrings(t *testing.T) {
	accountId := ""
	roleName := ""
	expected := "\n[profile_]\nrole_arn = arn:aws:iam:::role/\nsource_profile = service_account\n"
	result := createAwsProfileConfig(accountId, roleName)
	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}
