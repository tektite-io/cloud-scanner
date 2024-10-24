package cloud_resource_changes_aws

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUnmarshalSteamPipeResponse(t *testing.T) {

	jsonData := []byte(`
	{
		"columns": [
			{
				"name": "organization_id",
				"data_type": "text"
			}
		],
		"rows": [
			{
				"organization_id": "o-gmktzqiafl"
			}
		]
	}`)

	// Unmarshal the JSON into GenericStruct
	var genericData SteampipeQueryResponse
	if err := json.Unmarshal(jsonData, &genericData); err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
		return
	}

	// Convert rows to AccountDetails dynamically
	accountDetails, err := ConvertRows[AccountDetails](genericData.Rows)
	if err != nil {
		fmt.Println("Error converting rows to AccountDetails:", err)
		return
	}

	// Print the result
	fmt.Printf("AccountDetails: %+v\n", accountDetails)

	assert.NoError(t, err, "Error converting rows to AccountDetails")

	// Assert the expected result
	assert.Len(t, accountDetails, 1, "Expected one account detail")
	assert.Equal(t, "o-gmktzqiafl", accountDetails[0].OrgId, "Expected org id to be o-gmktzqiafl")

	// Example JSON with rows for S3Details
	jsonData2 := []byte(`
	{
		"columns": [
			{
				"name": "region",
				"data_type": "text"
			}
		],
		"rows": [
			{
				"region": "us-west-2"
			}
		]
	}`)

	var genericData2 SteampipeQueryResponse
	if err := json.Unmarshal(jsonData2, &genericData2); err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
		return
	}

	// Convert rows to S3Details dynamically
	s3Details, err := ConvertRows[S3Details](genericData2.Rows)
	if err != nil {
		fmt.Println("Error converting rows to S3Details:", err)
		return
	}

	fmt.Printf("S3Details: %+v\n", s3Details)

	// Assert the expected result
	assert.Len(t, s3Details, 1, "Expected one s3Detail detail")
	assert.Equal(t, "us-west-2", s3Details[0].Region, "Expected region to be us-west-2")

}
