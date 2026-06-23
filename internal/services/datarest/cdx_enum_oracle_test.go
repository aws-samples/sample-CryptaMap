package datarest

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/athena"
	athenatypes "github.com/aws/aws-sdk-go-v2/service/athena/types"
	"github.com/aws/aws-sdk-go-v2/service/dax"
	daxtypes "github.com/aws/aws-sdk-go-v2/service/dax/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/aws-samples/cryptamap/internal/output"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestDatarestScanners_EnumValueCBOMConformance is the CONTRACT-DRIVEN enum
// coverage net. For every AWS-SDK enum field a datarest scanner classifies off
// of, it iterates AWS's OWN authoritative value set (the generated
// EnumType("").Values() method) and asserts the scanner's REAL scan() core emits
// a schema-valid CycloneDX 1.7 CBOM for EVERY enum member — including members the
// scanner does not special-case (which fall through to a default branch).
//
// Why this exists, distinct from cdx_conformance_test.go: the conformance test
// drives one representative HAPPY-PATH value per scanner. This test instead lets
// AWS define the input domain: if AWS adds (or already exposes) an enum member
// the scanner mishandles — e.g. an SSEType/EncryptionOption the classifier maps
// to an empty algorithm name, an out-of-enum CBOM string, or a wrong object
// shape — that member produces a schema-validation failure or a panic here, and
// that is a REAL OUTPUT BUG (left FAILING on purpose, never softened).
//
// Recent fix classes this guards against: empty-string algorithm names, mode
// "xts", protocol "macsec", relatedCryptoMaterial type/state, uniqueItems. The
// likely class here is an SSEType/ServerSideEncryption/EncryptionOption value the
// scanner false-safes to AES or stamps with an invalid CBOM enum.
//
// The fakes and pointer helpers are REUSED from the sibling *_test.go files in
// this package (fakeDynamoDBClient, fakeAthenaClient, fakeDAXClient,
// fakeGlueClient, fakeS3Client, fakeS3KMS, wgSummaries, wgWithEncryption,
// cseStr, cseBool, ddbStrptr). Nothing is redefined here.
func TestDatarestScanners_EnumValueCBOMConformance(t *testing.T) {
	// Same schema-availability guard the existing conformance test uses: skip
	// (don't fail) if the vendored CDX schema is unavailable offline.
	if err := output.ValidateCBOMBytes([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)); err != nil {
		t.Skipf("vendored CDX schema unavailable, skipping enum-oracle conformance: %v", err)
	}

	const acct, region = "111122223333", "us-east-1"

	// validateEnum runs the scanner output through the CDX 1.7 schema and FAILS the
	// subtest on any panic, scan error, or schema violation. A failure here is a
	// real output bug for that exact enum value — the failure message includes the
	// enum type+value so the offending member is unambiguous.
	validateEnum := func(t *testing.T, enumType, value string, assets []models.CryptoAsset, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s=%q: scan returned error: %v", enumType, value, err)
		}
		// scan() must always emit at least one asset for these single-resource
		// happy-path fakes; zero assets would mean the enum value silently dropped
		// the resource (a different but equally real bug).
		if len(assets) == 0 {
			t.Fatalf("%s=%q: scan emitted ZERO assets (resource silently dropped)", enumType, value)
		}
		if verr := output.ValidateAssetsCBOM(assets); verr != nil {
			t.Fatalf("%s=%q: emitted CBOM FAILED CycloneDX 1.7 schema validation: %v", enumType, value, verr)
		}
	}

	// -----------------------------------------------------------------
	// dynamodb: SSEType (AES256, KMS) and SSEStatus (ENABLING, ENABLED,
	// DISABLING, DISABLED, UPDATING). DynamoDB is always-encrypted, so EVERY
	// member must still yield a schema-valid SymmetricOnly asset.
	// -----------------------------------------------------------------
	t.Run("dynamodb_SSEType", func(t *testing.T) {
		for _, v := range ddbtypes.SSEType("").Values() {
			v := v
			t.Run(string(v), func(t *testing.T) {
				client := &fakeDynamoDBClient{
					listPages: []*dynamodb.ListTablesOutput{
						{TableNames: []string{"tbl"}},
					},
					describe: map[string]*dynamodb.DescribeTableOutput{
						"tbl": {Table: &ddbtypes.TableDescription{
							SSEDescription: &ddbtypes.SSEDescription{
								KMSMasterKeyArn: ddbStrptr("arn:aws:kms:us-east-1:111122223333:key/abcd-cmk"),
								SSEType:         v,
								Status:          ddbtypes.SSEStatusEnabled,
							},
						}},
					},
				}
				assets, err := DynamoDBScanner{}.scan(context.Background(), client, acct, region)
				validateEnum(t, "dynamodbtypes.SSEType", string(v), assets, err)
			})
		}
	})

	t.Run("dynamodb_SSEStatus", func(t *testing.T) {
		for _, v := range ddbtypes.SSEStatus("").Values() {
			v := v
			t.Run(string(v), func(t *testing.T) {
				client := &fakeDynamoDBClient{
					listPages: []*dynamodb.ListTablesOutput{
						{TableNames: []string{"tbl"}},
					},
					describe: map[string]*dynamodb.DescribeTableOutput{
						"tbl": {Table: &ddbtypes.TableDescription{
							SSEDescription: &ddbtypes.SSEDescription{
								KMSMasterKeyArn: ddbStrptr("arn:aws:kms:us-east-1:111122223333:key/abcd-cmk"),
								SSEType:         ddbtypes.SSETypeKms,
								Status:          v,
							},
						}},
					},
				}
				assets, err := DynamoDBScanner{}.scan(context.Background(), client, acct, region)
				validateEnum(t, "dynamodbtypes.SSEStatus", string(v), assets, err)
			})
		}
	})

	// -----------------------------------------------------------------
	// s3: ServerSideEncryption (AES256, aws:fsx, aws:kms, aws:kms:dsse). The
	// scanner branches on the SSEAlgorithm string; aws:fsx and aws:kms:dsse are
	// less-common members worth driving through the real classifier+CBOM.
	// -----------------------------------------------------------------
	t.Run("s3_ServerSideEncryption", func(t *testing.T) {
		const b = "my-bucket"
		for _, v := range s3types.ServerSideEncryption("").Values() {
			v := v
			t.Run(string(v), func(t *testing.T) {
				client := &fakeS3Client{
					buckets: []s3types.Bucket{{Name: cseStr(b), BucketRegion: cseStr(region)}},
					enc: map[string]*s3.GetBucketEncryptionOutput{
						b: {ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
							Rules: []s3types.ServerSideEncryptionRule{{
								ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
									SSEAlgorithm:   v,
									KMSMasterKeyID: cseStr("arn:aws:kms:us-east-1:111122223333:key/abc"),
								},
								BucketKeyEnabled: cseBool(true),
							}},
						}},
					},
				}
				assets, err := S3Scanner{}.scan(context.Background(), client, fakeS3KMS{}, acct, region)
				validateEnum(t, "s3types.ServerSideEncryption", string(v), assets, err)
			})
		}
	})

	// -----------------------------------------------------------------
	// glue: CatalogEncryptionMode (DISABLED, SSE-KMS, SSE-KMS-WITH-SERVICE-ROLE).
	// DISABLED yields NoEncryption; the two SSE-KMS modes yield SymmetricOnly —
	// every member must be schema-valid.
	// -----------------------------------------------------------------
	t.Run("glue_CatalogEncryptionMode", func(t *testing.T) {
		for _, v := range gluetypes.CatalogEncryptionMode("").Values() {
			v := v
			t.Run(string(v), func(t *testing.T) {
				client := &fakeGlueClient{
					settings: &gluetypes.DataCatalogEncryptionSettings{
						EncryptionAtRest: &gluetypes.EncryptionAtRest{
							CatalogEncryptionMode: v,
							SseAwsKmsKeyId:        cseStr("arn:aws:kms:us-east-1:111122223333:key/abc-123"),
						},
					},
				}
				assets, err := GlueScanner{}.scan(context.Background(), client, acct, region)
				validateEnum(t, "gluetypes.CatalogEncryptionMode", string(v), assets, err)
			})
		}
	})

	// -----------------------------------------------------------------
	// athena: EncryptionOption (SSE_S3, SSE_KMS, CSE_KMS). All three are
	// SymmetricOnly per the scanner; each must produce a schema-valid CBOM.
	// -----------------------------------------------------------------
	t.Run("athena_EncryptionOption", func(t *testing.T) {
		for _, v := range athenatypes.EncryptionOption("").Values() {
			v := v
			t.Run(string(v), func(t *testing.T) {
				const wg = "wg-enum"
				client := &fakeAthenaClient{
					listPages: []*athena.ListWorkGroupsOutput{
						{WorkGroups: wgSummaries(wg)},
					},
					getWorkGroups: map[string]*athena.GetWorkGroupOutput{
						wg: wgWithEncryption(wg, v, "arn:aws:kms:us-east-1:111122223333:key/abc", true),
					},
				}
				assets, err := AthenaScanner{}.scan(context.Background(), client, acct, region)
				validateEnum(t, "athenatypes.EncryptionOption", string(v), assets, err)
			})
		}
	})

	// -----------------------------------------------------------------
	// dax: SSEStatus (ENABLING, ENABLED, DISABLING, DISABLED). Only ENABLED is
	// SymmetricOnly; the rest are NoEncryption. Every member must be schema-valid.
	// -----------------------------------------------------------------
	t.Run("dax_SSEStatus", func(t *testing.T) {
		for _, v := range daxtypes.SSEStatus("").Values() {
			v := v
			t.Run(string(v), func(t *testing.T) {
				client := &fakeDAXClient{
					pages: []*dax.DescribeClustersOutput{
						{Clusters: []daxtypes.Cluster{
							{
								ClusterName:    cseStr("clu"),
								ClusterArn:     cseStr("arn:aws:dax:us-east-1:111122223333:cache/clu"),
								SSEDescription: &daxtypes.SSEDescription{Status: v},
							},
						}},
					},
				}
				assets, err := DAXScanner{}.scan(context.Background(), client, acct, region)
				validateEnum(t, "daxtypes.SSEStatus", string(v), assets, err)
			})
		}
	})
}

// Enum-field coverage NOTES (fields deliberately not iterated here, and why):
//
//   - sns / sqs : the KMS master key is read from the KmsMasterKeyId ATTRIBUTE
//     string (a free-form ARN/alias), not an SDK enum with a .Values() method, so
//     there is no authoritative value set to iterate. Their happy-path CBOM is
//     covered in cdx_conformance_test.go.
//
//   - The remaining datarest scanners (efs, ebs, rds, redshift, kinesis, firehose,
//     elasticache, memorydb, neptune, documentdb, fsx, etc.) key their at-rest
//     classification off a boolean (Encrypted/StorageEncrypted) plus a free-form
//     KmsKeyId string, NOT an SDK-typed enum exposing .Values(). Firehose's
//     KeyType is read as a string field on a describe response rather than an enum
//     the scanner switches over its full value set. They are therefore outside
//     this contract-driven enum oracle; their happy-path CBOM is covered by
//     cdx_conformance_test.go.
//
// The five named in-scope enum fields are all covered above:
//   dynamodbtypes.SSEType (2), dynamodbtypes.SSEStatus (5),
//   s3types.ServerSideEncryption (4), gluetypes.CatalogEncryptionMode (3),
//   athenatypes.EncryptionOption (3), daxtypes.SSEStatus (4).
