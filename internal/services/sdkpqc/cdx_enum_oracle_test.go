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

// TestSDKPQCScanners_EnumOracleCBOMConformance is a CONTRACT-DRIVEN bug hunt.
//
// Instead of hand-picking a couple of inputs, it iterates AWS's OWN authoritative
// SDK enum value sets via EnumType("").Values() and asserts that each sdkpqc
// scanner produces a schema-valid CycloneDX 1.7 CBOM for EVERY known enum member.
// .Values() is the AWS SDK's own enumeration of the legal values a field can take,
// so it is the most authoritative offline oracle for "what real AWS can return".
//
// A panic OR a CBOM schema-validation failure for ANY single enum value is treated
// as a REAL DEFECT (e.g. a runtime mapped to an empty/invalid crypto component, an
// unknown PlatformType false-safing, an EncryptionType producing an out-of-schema
// algorithm name). The test deliberately does NOT soften or skip values to stay
// green: a failing value is left failing with the enum type, exact value, and the
// jsonschema error captured in the failure message.
//
// Offline + deterministic: context.Background(), account 111122223333,
// region us-east-1, hand-rolled fakes from the sibling *_test.go files.
func TestSDKPQCScanners_EnumOracleCBOMConformance(t *testing.T) {
	// Schema-availability guard: identical to cdx_conformance_test.go. If the
	// vendored CDX schema is unavailable we cannot validate, so skip rather than
	// produce a false pass.
	if err := output.ValidateCBOMBytes([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)); err != nil {
		t.Skipf("vendored CDX schema unavailable, skipping enum-oracle conformance: %v", err)
	}

	// validateNoPanic runs a scan-and-validate closure, converting any panic into a
	// test failure that names the enum context, then asserting schema validity.
	validateNoPanic := func(t *testing.T, enumType, value string, run func() ([]models.CryptoAsset, error)) {
		t.Helper()
		var assets []models.CryptoAsset
		var err error
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC scanning %s=%q: %v", enumType, value, r)
				}
			}()
			assets, err = run()
		}()
		if err != nil {
			t.Fatalf("scan with %s=%q returned error: %v", enumType, value, err)
		}
		if len(assets) == 0 {
			t.Fatalf("scan with %s=%q produced no assets (expected one per synthetic resource)", enumType, value)
		}
		if verr := output.ValidateAssetsCBOM(assets); verr != nil {
			t.Fatalf("CBOM failed CycloneDX 1.7 schema validation for %s=%q: %v", enumType, value, verr)
		}
	}

	// ---- lambda Runtime (lambdatypes.Runtime) ------------------------------
	// The scanner records the runtime string as metadata only and stamps
	// PostureUnknown (no crypto component derived from the runtime). Iterate the
	// FULL .Values() set: every nodejs/python/java/go/dotnet/ruby/provided variant
	// must yield a schema-valid CBOM.
	t.Run("lambda_Runtime", func(t *testing.T) {
		runtimes := lambdatypes.Runtime("").Values()
		if len(runtimes) == 0 {
			t.Fatal("lambdatypes.Runtime(\"\").Values() returned no values; SDK oracle empty")
		}
		t.Logf("iterating %d lambdatypes.Runtime enum values", len(runtimes))
		for _, rt := range runtimes {
			rt := rt
			t.Run(string(rt), func(t *testing.T) {
				client := &lambdaruntimeFakeClient{
					pages: []*lambda.ListFunctionsOutput{
						{
							Functions: []lambdatypes.FunctionConfiguration{
								{
									FunctionArn:  lambdaruntimeStrptr("arn:aws:lambda:us-east-1:111122223333:function:fn-" + string(rt)),
									FunctionName: lambdaruntimeStrptr("fn"),
									Runtime:      rt,
									Version:      lambdaruntimeStrptr("$LATEST"),
								},
							},
						},
					},
				}
				validateNoPanic(t, "lambdatypes.Runtime", string(rt), func() ([]models.CryptoAsset, error) {
					return LambdaRuntimeScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
				})
			})
		}
	})

	// ---- ssm PingStatus (ssmtypes.PingStatus) ------------------------------
	// PingStatus drives the pingStatus flat property. Hold PlatformType fixed
	// (Linux) and iterate every PingStatus value.
	t.Run("ssm_PingStatus", func(t *testing.T) {
		statuses := ssmtypes.PingStatus("").Values()
		if len(statuses) == 0 {
			t.Fatal("ssmtypes.PingStatus(\"\").Values() returned no values; SDK oracle empty")
		}
		t.Logf("iterating %d ssmtypes.PingStatus enum values", len(statuses))
		for _, ps := range statuses {
			ps := ps
			t.Run(string(ps), func(t *testing.T) {
				client := &ec2ssmFakeClient{
					pages: []*ssm.DescribeInstanceInformationOutput{
						{
							InstanceInformationList: []ssmtypes.InstanceInformation{
								{
									InstanceId:      ec2ssmStrptr("i-ping-" + string(ps)),
									PlatformType:    ssmtypes.PlatformTypeLinux,
									PlatformName:    ec2ssmStrptr("Amazon Linux"),
									PlatformVersion: ec2ssmStrptr("2023"),
									AgentVersion:    ec2ssmStrptr("3.2.0.0"),
									PingStatus:      ps,
								},
							},
						},
					},
				}
				validateNoPanic(t, "ssmtypes.PingStatus", string(ps), func() ([]models.CryptoAsset, error) {
					return EC2SSMScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
				})
			})
		}
	})

	// ---- ssm PlatformType (ssmtypes.PlatformType) --------------------------
	// PlatformType drives the platformType flat property. The honesty contract
	// stamps PostureUnknown regardless of platform (a known false-safe risk class:
	// an unrecognized PlatformType must NOT be silently treated as quantum-safe).
	// Hold PingStatus fixed (Online) and iterate every PlatformType value.
	t.Run("ssm_PlatformType", func(t *testing.T) {
		platforms := ssmtypes.PlatformType("").Values()
		if len(platforms) == 0 {
			t.Fatal("ssmtypes.PlatformType(\"\").Values() returned no values; SDK oracle empty")
		}
		t.Logf("iterating %d ssmtypes.PlatformType enum values", len(platforms))
		for _, pt := range platforms {
			pt := pt
			t.Run(string(pt), func(t *testing.T) {
				client := &ec2ssmFakeClient{
					pages: []*ssm.DescribeInstanceInformationOutput{
						{
							InstanceInformationList: []ssmtypes.InstanceInformation{
								{
									InstanceId:      ec2ssmStrptr("i-plat-" + string(pt)),
									PlatformType:    pt,
									PlatformName:    ec2ssmStrptr("os"),
									PlatformVersion: ec2ssmStrptr("1.0"),
									AgentVersion:    ec2ssmStrptr("3.2.0.0"),
									PingStatus:      ssmtypes.PingStatusOnline,
								},
							},
						},
					},
				}
				validateNoPanic(t, "ssmtypes.PlatformType", string(pt), func() ([]models.CryptoAsset, error) {
					return EC2SSMScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
				})
			})
		}
	})

	// ---- ecr EncryptionType (ecrtypes.EncryptionType) ----------------------
	// container_images keys its at-rest CryptoProperties off the repository's
	// EncryptionConfiguration.EncryptionType SDK enum (AES256 -> SSE-S3 AES-256;
	// KMS / KMS_DSSE -> KMS-backed, resolving the key spec via DescribeKey). This
	// is the relevant SDK-typed enum for this scanner, so iterate its full
	// .Values() set. The fake's default DescribeKey (empty describeKeySpec) returns
	// no KeySpec, exercising the SYMMETRIC_DEFAULT degradation path for KMS values.
	t.Run("ecr_EncryptionType", func(t *testing.T) {
		encTypes := ecrtypes.EncryptionType("").Values()
		if len(encTypes) == 0 {
			t.Fatal("ecrtypes.EncryptionType(\"\").Values() returned no values; SDK oracle empty")
		}
		t.Logf("iterating %d ecrtypes.EncryptionType enum values", len(encTypes))
		for _, et := range encTypes {
			et := et
			t.Run(string(et), func(t *testing.T) {
				client := &fakeContainerImagesClient{
					repoPages: []*ecr.DescribeRepositoriesOutput{
						{
							Repositories: []ecrtypes.Repository{
								{
									RepositoryName: containerimagesStrptr("repo-" + string(et)),
									RepositoryArn:  containerimagesStrptr("arn:aws:ecr:us-east-1:111122223333:repository/repo-" + string(et)),
									EncryptionConfiguration: &ecrtypes.EncryptionConfiguration{
										EncryptionType: et,
										KmsKey:         containerimagesStrptr("arn:aws:kms:us-east-1:111122223333:key/abc"),
									},
								},
							},
						},
					},
				}
				validateNoPanic(t, "ecrtypes.EncryptionType", string(et), func() ([]models.CryptoAsset, error) {
					return ContainerImagesScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
				})
			})
		}
	})
}
