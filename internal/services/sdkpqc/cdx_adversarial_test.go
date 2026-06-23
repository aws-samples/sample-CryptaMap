package sdkpqc

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
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

// TestSDKPQCScanners_Adversarial drives the REAL scan() cores of every sdkpqc
// scanner with HOSTILE / edge-case AWS API responses (nil outputs, all-nil
// resource fields, unknown/future raw enum casts, empty + 10k-char strings) and
// asserts ONLY two robustness invariants per case:
//
//	(i)  scan() never PANICS (a per-subtest deferred recover() records the
//	     triggering input + stack instead of crashing the run); and
//	(ii) any returned assets (len>0) pass output.ValidateAssetsCBOM — i.e. an
//	     adversarial input must never produce schema-INVALID CBOM.
//
// 0 assets, or a returned error, on adversarial input is acceptable. A panic, or
// schema-invalid non-empty assets, is a REAL robustness bug and is reported via
// t.Errorf with full detail (input + stack / jsonschema error).
func TestSDKPQCScanners_Adversarial(t *testing.T) {
	if err := output.ValidateCBOMBytes([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)); err != nil {
		t.Skipf("vendored CDX schema unavailable, skipping adversarial: %v", err)
	}

	const big = 10000
	bigStr := strings.Repeat("A", big)
	sp := func(s string) *string { return &s }

	// run executes one adversarial scan under panic capture and schema validation.
	// scanFn must call the scanner's scan() seam and return (assets, err).
	run := func(t *testing.T, desc string, scanFn func() ([]models.CryptoAsset, error)) {
		t.Helper()
		t.Run(desc, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					// A panic on adversarial input is a real robustness bug: record the
					// triggering input and the panic stack, but do NOT re-panic (capture).
					t.Errorf("PANIC on adversarial input %q: %v\n%s", desc, r, debug.Stack())
				}
			}()
			assets, err := scanFn()
			// An error (e.g. propagated API failure) is an acceptable adversarial
			// outcome; only assert the schema invariant when assets were produced.
			_ = err
			if len(assets) == 0 {
				return
			}
			if verr := output.ValidateAssetsCBOM(assets); verr != nil {
				t.Errorf("SCHEMA VIOLATION on adversarial input %q: %d asset(s) failed CycloneDX 1.7 validation: %v", desc, len(assets), verr)
			}
		})
	}

	ctx := context.Background()
	const acct = "111122223333"
	const region = "us-east-1"

	// ------------------------------------------------------------------
	// ContainerImagesScanner (ecrImagesAPI): DescribeRepositories pages of
	// ecrtypes.Repository + EncryptionConfiguration -> at-rest assets.
	// ------------------------------------------------------------------
	t.Run("container_images", func(t *testing.T) {
		ecrScan := func(c *fakeContainerImagesClient) func() ([]models.CryptoAsset, error) {
			return func() ([]models.CryptoAsset, error) {
				return ContainerImagesScanner{}.scan(ctx, c, acct, region)
			}
		}
		page := func(repos ...ecrtypes.Repository) *fakeContainerImagesClient {
			return &fakeContainerImagesClient{
				repoPages: []*ecr.DescribeRepositoriesOutput{{Repositories: repos}},
			}
		}

		// nil top-level output: fake with no pages returns &DescribeRepositoriesOutput{}
		// (empty, non-nil). Drive the genuinely-empty path here.
		run(t, "ecr: no pages (empty account)", ecrScan(&fakeContainerImagesClient{}))
		run(t, "ecr: page with nil Repositories slice", ecrScan(&fakeContainerImagesClient{
			repoPages: []*ecr.DescribeRepositoriesOutput{{Repositories: nil}},
		}))
		run(t, "ecr: page with empty Repositories slice", ecrScan(page()))

		// Repository with ALL pointers nil (no name/arn/encryption-config).
		run(t, "ecr: repo all-nil pointers", ecrScan(page(ecrtypes.Repository{})))

		// Name set, ARN nil -> id falls back to name.
		run(t, "ecr: nil RepositoryArn, name set", ecrScan(page(ecrtypes.Repository{
			RepositoryName: sp("only-name"),
		})))
		// Name nil, ARN set -> repo is skipped (continue), expect 0 assets.
		run(t, "ecr: nil RepositoryName, arn set", ecrScan(page(ecrtypes.Repository{
			RepositoryArn: sp("arn:aws:ecr:us-east-1:111122223333:repository/x"),
		})))
		// Both name & arn empty strings (non-nil).
		run(t, "ecr: empty-string name+arn", ecrScan(page(ecrtypes.Repository{
			RepositoryName: sp(""), RepositoryArn: sp(""),
		})))
		// 10k-char name + arn.
		run(t, "ecr: 10k-char name+arn", ecrScan(page(ecrtypes.Repository{
			RepositoryName: sp(bigStr), RepositoryArn: sp(bigStr),
		})))

		// EncryptionConfiguration: KMS type but KmsKey nil (no key to DescribeKey).
		run(t, "ecr: KMS enc, nil KmsKey", ecrScan(page(ecrtypes.Repository{
			RepositoryName:          sp("kms-no-key"),
			EncryptionConfiguration: &ecrtypes.EncryptionConfiguration{EncryptionType: ecrtypes.EncryptionTypeKms},
		})))
		// KMS_DSSE type, empty-string KmsKey.
		run(t, "ecr: KMS_DSSE enc, empty KmsKey", ecrScan(page(ecrtypes.Repository{
			RepositoryName:          sp("kmsdsse-empty-key"),
			EncryptionConfiguration: &ecrtypes.EncryptionConfiguration{EncryptionType: ecrtypes.EncryptionTypeKmsDsse, KmsKey: sp("")},
		})))
		// UNKNOWN/future EncryptionType raw-cast -> falls to default (AES) branch;
		// raw enum string is copied into encryptionType prop.
		run(t, "ecr: unknown EncryptionType enum", ecrScan(page(ecrtypes.Repository{
			RepositoryName:          sp("future-enc"),
			EncryptionConfiguration: &ecrtypes.EncryptionConfiguration{EncryptionType: ecrtypes.EncryptionType("PQC_KYBER_2099")},
		})))
		// 10k-char raw EncryptionType enum copied into a CBOM field.
		run(t, "ecr: 10k-char EncryptionType enum", ecrScan(page(ecrtypes.Repository{
			RepositoryName:          sp("huge-enc"),
			EncryptionConfiguration: &ecrtypes.EncryptionConfiguration{EncryptionType: ecrtypes.EncryptionType(bigStr)},
		})))
		// KMS with a DescribeKey-returned 10k-char / unknown KeySpec copied into props.
		run(t, "ecr: KMS, DescribeKey returns 10k-char KeySpec", ecrScan(&fakeContainerImagesClient{
			repoPages: []*ecr.DescribeRepositoriesOutput{{Repositories: []ecrtypes.Repository{{
				RepositoryName:          sp("kms-bigspec"),
				EncryptionConfiguration: &ecrtypes.EncryptionConfiguration{EncryptionType: ecrtypes.EncryptionTypeKms, KmsKey: sp("arn:aws:kms:us-east-1:111122223333:key/abc")},
			}}}},
			describeKeySpec: bigStr,
		}))
		run(t, "ecr: KMS, DescribeKey returns unknown KeySpec enum", ecrScan(&fakeContainerImagesClient{
			repoPages: []*ecr.DescribeRepositoriesOutput{{Repositories: []ecrtypes.Repository{{
				RepositoryName:          sp("kms-unknownspec"),
				EncryptionConfiguration: &ecrtypes.EncryptionConfiguration{EncryptionType: ecrtypes.EncryptionTypeKms, KmsKey: sp("arn:k")},
			}}}},
			describeKeySpec: "ML_KEM_9999_FUTURE",
		}))
		// DescribeKey error degrades to SYMMETRIC_DEFAULT (must not panic / drop asset).
		run(t, "ecr: KMS, DescribeKey errors", ecrScan(&fakeContainerImagesClient{
			repoPages: []*ecr.DescribeRepositoriesOutput{{Repositories: []ecrtypes.Repository{{
				RepositoryName:          sp("kms-keyerr"),
				EncryptionConfiguration: &ecrtypes.EncryptionConfiguration{EncryptionType: ecrtypes.EncryptionTypeKms, KmsKey: sp("arn:k")},
			}}}},
			describeKeyErr: fmt.Errorf("AccessDenied"),
		}))
		// DescribeImages errors: must degrade image count only, keep asset.
		run(t, "ecr: DescribeImages errors", ecrScan(&fakeContainerImagesClient{
			repoPages: []*ecr.DescribeRepositoriesOutput{{Repositories: []ecrtypes.Repository{{
				RepositoryName: sp("img-err"),
			}}}},
			imagesErr: fmt.Errorf("AccessDenied"),
		}))
		// Top-level DescribeRepositories error -> returns error, nil assets.
		run(t, "ecr: DescribeRepositories errors", ecrScan(&fakeContainerImagesClient{
			repoErr: fmt.Errorf("Throttling"),
		}))
		// Many repos with mixed hostile fields in one page.
		run(t, "ecr: mixed hostile repos in one page", ecrScan(page(
			ecrtypes.Repository{},
			ecrtypes.Repository{RepositoryName: sp("")},
			ecrtypes.Repository{RepositoryName: sp(bigStr), RepositoryArn: sp("")},
			ecrtypes.Repository{RepositoryName: sp("k"), EncryptionConfiguration: &ecrtypes.EncryptionConfiguration{EncryptionType: ecrtypes.EncryptionType("WAT")}},
		)))
	})

	// ------------------------------------------------------------------
	// EC2SSMScanner (ssmInstanceInfoAPI): DescribeInstanceInformation pages of
	// ssmtypes.InstanceInformation -> protocol assets.
	// ------------------------------------------------------------------
	t.Run("ec2_ssm", func(t *testing.T) {
		ssmScan := func(c *ec2ssmFakeClient) func() ([]models.CryptoAsset, error) {
			return func() ([]models.CryptoAsset, error) {
				return EC2SSMScanner{}.scan(ctx, c, acct, region)
			}
		}
		page := func(insts ...ssmtypes.InstanceInformation) *ec2ssmFakeClient {
			return &ec2ssmFakeClient{pages: []*ssm.DescribeInstanceInformationOutput{{InstanceInformationList: insts}}}
		}

		run(t, "ssm: no pages (empty account)", ssmScan(&ec2ssmFakeClient{}))
		run(t, "ssm: page with nil list", ssmScan(&ec2ssmFakeClient{
			pages: []*ssm.DescribeInstanceInformationOutput{{InstanceInformationList: nil}},
		}))
		run(t, "ssm: page with empty list", ssmScan(page()))

		// Instance with ALL pointers nil (no InstanceId -> skipped).
		run(t, "ssm: instance all-nil pointers", ssmScan(page(ssmtypes.InstanceInformation{})))
		// InstanceId set, every other field nil/zero.
		run(t, "ssm: only InstanceId set", ssmScan(page(ssmtypes.InstanceInformation{
			InstanceId: sp("i-bare"),
		})))
		// Empty-string InstanceId (non-nil) -> emitted with empty id.
		run(t, "ssm: empty-string InstanceId", ssmScan(page(ssmtypes.InstanceInformation{
			InstanceId: sp(""),
		})))
		// 10k-char InstanceId + platform name/version + agent version.
		run(t, "ssm: 10k-char id/platformName/version", ssmScan(page(ssmtypes.InstanceInformation{
			InstanceId: sp(bigStr), PlatformName: sp(bigStr), PlatformVersion: sp(bigStr), AgentVersion: sp(bigStr),
		})))
		// UNKNOWN/future PlatformType raw-cast copied into platformType prop.
		run(t, "ssm: unknown PlatformType enum", ssmScan(page(ssmtypes.InstanceInformation{
			InstanceId: sp("i-os"), PlatformType: ssmtypes.PlatformType("quantumos"),
		})))
		// 10k-char raw PlatformType enum.
		run(t, "ssm: 10k-char PlatformType enum", ssmScan(page(ssmtypes.InstanceInformation{
			InstanceId: sp("i-bigos"), PlatformType: ssmtypes.PlatformType(bigStr),
		})))
		// UNKNOWN/future PingStatus raw-cast copied into pingStatus prop.
		run(t, "ssm: unknown PingStatus enum", ssmScan(page(ssmtypes.InstanceInformation{
			InstanceId: sp("i-ping"), PingStatus: ssmtypes.PingStatus("UNKNOWN_FUTURE"),
		})))
		// 10k-char PingStatus enum.
		run(t, "ssm: 10k-char PingStatus enum", ssmScan(page(ssmtypes.InstanceInformation{
			InstanceId: sp("i-bigping"), PingStatus: ssmtypes.PingStatus(bigStr),
		})))
		// Top-level error -> error, nil assets.
		run(t, "ssm: DescribeInstanceInformation errors", ssmScan(&ec2ssmFakeClient{
			err: fmt.Errorf("AccessDenied"),
		}))
		// Many hostile instances in one page.
		run(t, "ssm: mixed hostile instances in one page", ssmScan(page(
			ssmtypes.InstanceInformation{},
			ssmtypes.InstanceInformation{InstanceId: sp("")},
			ssmtypes.InstanceInformation{InstanceId: sp(bigStr), PlatformType: ssmtypes.PlatformType(bigStr), PingStatus: ssmtypes.PingStatus("WAT")},
		)))
	})

	// ------------------------------------------------------------------
	// LambdaRuntimeScanner (lambdaListFunctionsAPI): ListFunctions pages of
	// lambdatypes.FunctionConfiguration -> runtime-metadata assets.
	// ------------------------------------------------------------------
	t.Run("lambda_runtime", func(t *testing.T) {
		lScan := func(c *lambdaruntimeFakeClient) func() ([]models.CryptoAsset, error) {
			return func() ([]models.CryptoAsset, error) {
				return LambdaRuntimeScanner{}.scan(ctx, c, acct, region)
			}
		}
		page := func(fns ...lambdatypes.FunctionConfiguration) *lambdaruntimeFakeClient {
			return &lambdaruntimeFakeClient{pages: []*lambda.ListFunctionsOutput{{Functions: fns}}}
		}

		run(t, "lambda: no pages (empty account)", lScan(&lambdaruntimeFakeClient{}))
		run(t, "lambda: page with nil Functions slice", lScan(&lambdaruntimeFakeClient{
			pages: []*lambda.ListFunctionsOutput{{Functions: nil}},
		}))
		run(t, "lambda: page with empty Functions slice", lScan(page()))

		// Function with ALL pointers nil (no FunctionArn -> skipped).
		run(t, "lambda: function all-nil pointers", lScan(page(lambdatypes.FunctionConfiguration{})))
		// ARN set, Name/Version nil, zero Runtime.
		run(t, "lambda: only FunctionArn set", lScan(page(lambdatypes.FunctionConfiguration{
			FunctionArn: sp("arn:aws:lambda:us-east-1:111122223333:function:bare"),
		})))
		// Empty-string ARN (non-nil) -> emitted with empty id.
		run(t, "lambda: empty-string FunctionArn", lScan(page(lambdatypes.FunctionConfiguration{
			FunctionArn: sp(""),
		})))
		// 10k-char ARN/name/version.
		run(t, "lambda: 10k-char arn/name/version", lScan(page(lambdatypes.FunctionConfiguration{
			FunctionArn: sp(bigStr), FunctionName: sp(bigStr), Version: sp(bigStr),
		})))
		// UNKNOWN/future Runtime raw-casts copied into runtime prop.
		run(t, "lambda: unknown Runtime python3.99", lScan(page(lambdatypes.FunctionConfiguration{
			FunctionArn: sp("arn:fn:py399"), Runtime: lambdatypes.Runtime("python3.99"),
		})))
		run(t, "lambda: unknown Runtime pqclang1.0", lScan(page(lambdatypes.FunctionConfiguration{
			FunctionArn: sp("arn:fn:pqc"), Runtime: lambdatypes.Runtime("pqclang1.0"),
		})))
		// 10k-char raw Runtime enum.
		run(t, "lambda: 10k-char Runtime enum", lScan(page(lambdatypes.FunctionConfiguration{
			FunctionArn: sp("arn:fn:big"), Runtime: lambdatypes.Runtime(bigStr),
		})))
		// Top-level error on first call -> error, nil assets.
		run(t, "lambda: ListFunctions errors", lScan(&lambdaruntimeFakeClient{
			err: fmt.Errorf("Throttling"), errAt: 0,
		}))
		// Many hostile functions in one page.
		run(t, "lambda: mixed hostile functions in one page", lScan(page(
			lambdatypes.FunctionConfiguration{},
			lambdatypes.FunctionConfiguration{FunctionArn: sp("")},
			lambdatypes.FunctionConfiguration{FunctionArn: sp(bigStr), Runtime: lambdatypes.Runtime("future99"), Version: sp(bigStr)},
		)))
	})
}
