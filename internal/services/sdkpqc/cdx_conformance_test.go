package sdkpqc

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/aws-samples/cryptamap/internal/output"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestSDKPQCScanners_CBOMSchemaConformance drives the REAL scan() cores of every
// sdkpqc scanner with synthetic inputs, then validates the CBOM their output
// produces against the official CycloneDX 1.7 schema, WITHOUT a live AWS account.
func TestSDKPQCScanners_CBOMSchemaConformance(t *testing.T) {
	if err := output.ValidateCBOMBytes([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)); err != nil {
		t.Skipf("vendored CDX schema unavailable, skipping conformance: %v", err)
	}

	validate := func(t *testing.T, assets []models.CryptoAsset, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		if len(assets) == 0 {
			t.Fatal("expected at least one asset")
		}
		if err := output.ValidateAssetsCBOM(assets); err != nil {
			t.Fatalf("CBOM failed CycloneDX 1.7 schema validation: %v", err)
		}
	}

	t.Run("container_images", func(t *testing.T) {
		client := &fakeContainerImagesClient{
			repoPages: []*ecr.DescribeRepositoriesOutput{
				{
					Repositories: []ecrtypes.Repository{
						{
							RepositoryName: containerimagesStrptr("repo-page1"),
							RepositoryArn:  containerimagesStrptr("arn:aws:ecr:us-east-1:111122223333:repository/repo-page1"),
						},
					},
				},
			},
		}
		assets, err := ContainerImagesScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		validate(t, assets, err)
	})

	t.Run("ec2_ssm", func(t *testing.T) {
		client := &ec2ssmFakeClient{
			pages: []*ssm.DescribeInstanceInformationOutput{
				{
					InstanceInformationList: []ssmtypes.InstanceInformation{
						{
							InstanceId:      ec2ssmStrptr("i-1"),
							PlatformType:    ssmtypes.PlatformTypeLinux,
							PlatformName:    ec2ssmStrptr("Amazon Linux"),
							PlatformVersion: ec2ssmStrptr("2023"),
							AgentVersion:    ec2ssmStrptr("3.2.0.0"),
							PingStatus:      ssmtypes.PingStatusOnline,
						},
					},
				},
			},
		}
		assets, err := EC2SSMScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		validate(t, assets, err)
	})

	t.Run("lambda_runtime", func(t *testing.T) {
		client := &lambdaruntimeFakeClient{
			pages: []*lambda.ListFunctionsOutput{
				{
					Functions: []lambdatypes.FunctionConfiguration{
						{FunctionArn: lambdaruntimeStrptr("arn-fn"), FunctionName: lambdaruntimeStrptr("svc"), Runtime: lambdatypes.RuntimePython312, Version: lambdaruntimeStrptr("$LATEST")},
					},
				},
			},
		}
		assets, err := LambdaRuntimeScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		validate(t, assets, err)
	})
}
