package datarest

// fuzz_invariant_test.go is an ADVERSARIAL property/invariant test that throws
// hostile inputs at the at-rest scanner classification cores and asserts none of
// them produces a fabricated verdict or panics. It complements the per-scanner
// opt-in tests (which a reviewer found could miss a SYSTEMIC mislabel — e.g. the
// AppMesh weakest-wins fold seeded from NoEncryption) by exercising the same
// honesty contract across a CROSS-SECTION of scanners with a single hostile fake.
//
// The four hostile shapes driven against every covered scanner's testable core
// (Scanner{}.scan(ctx, fakeClient, account, region)) are:
//
//	(a) a top-level List/Describe error,
//	(b) a per-resource Describe error (where the core has a per-resource call),
//	(c) nil / empty output structs,
//	(d) empty pages (List returns an empty slice, no NextToken).
//
// The invariants asserted for EVERY case:
//
//	1. No panic (recovered + reported per scanner).
//	2. A top-level List error PROPAGATES (non-nil error, nil/empty assets) — a
//	   failed read must be VISIBLY incomplete, never a clean empty success.
//	3. Every EMITTED asset has a posture in the 7-value enum and a non-empty
//	   Service — no asset escapes the registry/enum.
//	4. No asset that resulted from a FAILED read carries a confident
//	   no-encryption / symmetric-only verdict (the false-alarm / false-safe
//	   honesty contract). A failed per-resource read must be Unknown(+note) or be
//	   propagated/dropped — never a fabricated at-rest verdict.

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/neptune"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// validPostures is the 7-value posture enum every emitted asset must resolve to.
var validPostures = map[models.CryptoPosture]bool{
	models.PostureNoEncryption:    true,
	models.PostureLegacyTLS:       true,
	models.PostureNonPQCClassical: true,
	models.PostureSymmetricOnly:   true,
	models.PosturePQCHybrid:       true,
	models.PosturePQCReady:        true,
	models.PostureUnknown:         true,
}

// assertEmittedAssetsHonest runs the universal per-asset invariants (#3, #4).
// fromFailedRead is true when the assets were produced under a read-failure
// scenario; in that case an emitted asset must NOT carry a confident
// no-encryption / symmetric-only verdict (that would be a fabricated verdict on
// a read we could not complete).
func assertEmittedAssetsHonest(t *testing.T, scanner string, assets []models.CryptoAsset, fromFailedRead bool) {
	t.Helper()
	for i, a := range assets {
		if a.Service == "" {
			t.Errorf("[%s] asset #%d has empty Service (escapes the registry)", scanner, i)
		}
		p := models.CryptoPosture(a.Properties["posture"])
		if !validPostures[p] {
			t.Errorf("[%s] asset #%d has posture %q outside the 7-value enum", scanner, i, p)
		}
		if fromFailedRead && (p == models.PostureNoEncryption || p == models.PostureSymmetricOnly) {
			t.Errorf("[%s] asset #%d produced a confident %q verdict on a FAILED read (fabricated verdict / honesty-contract violation); note=%q",
				scanner, i, p, a.Properties["note"])
		}
	}
}

// runScanCase invokes fn (a scanner core bound to a hostile fake) under a panic
// guard and applies the universal invariants. wantErr asserts the top-level
// error-propagation contract; fromFailedRead drives the per-asset honesty check.
func runScanCase(t *testing.T, scanner, scenario string, wantErr, fromFailedRead bool, fn func() ([]models.CryptoAsset, error)) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("[%s/%s] PANIC on hostile input: %v", scanner, scenario, r)
		}
	}()
	assets, err := fn()
	if wantErr {
		if err == nil {
			t.Errorf("[%s/%s] expected a propagated error (visibly incomplete), got nil (silent empty success)", scanner, scenario)
		}
		if len(assets) != 0 {
			t.Errorf("[%s/%s] expected no assets on a top-level read error, got %d", scanner, scenario, len(assets))
		}
	}
	assertEmittedAssetsHonest(t, scanner, assets, fromFailedRead)
}

// ---- Hostile fakes. Each satisfies one scanner's API interface. errTop forces
// the top-level List/Describe to fail; errResource forces the per-resource
// Describe to fail (the List returns one resource so the per-resource path is
// exercised); with neither set the calls return empty/nil benign output. ----

var errHostile = errors.New("AccessDeniedException: hostile-fuzz denied read")

// dynamodb: ListTables + DescribeTable.
type fuzzDynamoDBClient struct{ errTop, errResource bool }

func (f *fuzzDynamoDBClient) ListTables(ctx context.Context, in *dynamodb.ListTablesInput, _ ...func(*dynamodb.Options)) (*dynamodb.ListTablesOutput, error) {
	if f.errTop {
		return nil, errHostile
	}
	if f.errResource {
		return &dynamodb.ListTablesOutput{TableNames: []string{"t1"}}, nil
	}
	return &dynamodb.ListTablesOutput{}, nil
}
func (f *fuzzDynamoDBClient) DescribeTable(ctx context.Context, in *dynamodb.DescribeTableInput, _ ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
	if f.errResource {
		return nil, errHostile
	}
	return &dynamodb.DescribeTableOutput{}, nil // nil Table -> AWS-owned default tier
}

// sqs: ListQueues + GetQueueAttributes.
type fuzzSQSClient struct{ errTop, errResource bool }

func (f *fuzzSQSClient) ListQueues(ctx context.Context, in *sqs.ListQueuesInput, _ ...func(*sqs.Options)) (*sqs.ListQueuesOutput, error) {
	if f.errTop {
		return nil, errHostile
	}
	if f.errResource {
		return &sqs.ListQueuesOutput{QueueUrls: []string{"https://sqs.us-east-1.amazonaws.com/111122223333/q1"}}, nil
	}
	return &sqs.ListQueuesOutput{}, nil
}
func (f *fuzzSQSClient) GetQueueAttributes(ctx context.Context, in *sqs.GetQueueAttributesInput, _ ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	if f.errResource {
		return nil, errHostile
	}
	return &sqs.GetQueueAttributesOutput{}, nil // nil attrs -> Unknown
}

// kinesis: ListStreams + DescribeStreamSummary.
type fuzzKinesisClient struct{ errTop, errResource bool }

func (f *fuzzKinesisClient) ListStreams(ctx context.Context, in *kinesis.ListStreamsInput, _ ...func(*kinesis.Options)) (*kinesis.ListStreamsOutput, error) {
	if f.errTop {
		return nil, errHostile
	}
	if f.errResource {
		return &kinesis.ListStreamsOutput{StreamNames: []string{"s1"}}, nil
	}
	return &kinesis.ListStreamsOutput{}, nil
}
func (f *fuzzKinesisClient) DescribeStreamSummary(ctx context.Context, in *kinesis.DescribeStreamSummaryInput, _ ...func(*kinesis.Options)) (*kinesis.DescribeStreamSummaryOutput, error) {
	if f.errResource {
		return nil, errHostile
	}
	return &kinesis.DescribeStreamSummaryOutput{}, nil // nil summary
}

// backup: ListBackupVaults + DescribeBackupVault.
type fuzzBackupClient struct{ errTop, errResource bool }

func (f *fuzzBackupClient) ListBackupVaults(ctx context.Context, in *backup.ListBackupVaultsInput, _ ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error) {
	if f.errTop {
		return nil, errHostile
	}
	if f.errResource {
		name := "v1"
		return &backup.ListBackupVaultsOutput{BackupVaultList: []backuptypes.BackupVaultListMember{{BackupVaultName: &name}}}, nil
	}
	return &backup.ListBackupVaultsOutput{}, nil
}
func (f *fuzzBackupClient) DescribeBackupVault(ctx context.Context, in *backup.DescribeBackupVaultInput, _ ...func(*backup.Options)) (*backup.DescribeBackupVaultOutput, error) {
	if f.errResource {
		return nil, errHostile
	}
	return &backup.DescribeBackupVaultOutput{}, nil
}

// rds: DescribeDBInstances (single top-level Describe).
type fuzzRDSClient struct{ errTop bool }

func (f *fuzzRDSClient) DescribeDBInstances(ctx context.Context, in *rds.DescribeDBInstancesInput, _ ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	if f.errTop {
		return nil, errHostile
	}
	return &rds.DescribeDBInstancesOutput{}, nil
}

// elasticache: DescribeReplicationGroups (single top-level Describe).
type fuzzElastiCacheClient struct{ errTop bool }

func (f *fuzzElastiCacheClient) DescribeReplicationGroups(ctx context.Context, in *elasticache.DescribeReplicationGroupsInput, _ ...func(*elasticache.Options)) (*elasticache.DescribeReplicationGroupsOutput, error) {
	if f.errTop {
		return nil, errHostile
	}
	return &elasticache.DescribeReplicationGroupsOutput{}, nil
}

// efs: DescribeFileSystems (single top-level Describe).
type fuzzEFSClient struct{ errTop bool }

func (f *fuzzEFSClient) DescribeFileSystems(ctx context.Context, in *efs.DescribeFileSystemsInput, _ ...func(*efs.Options)) (*efs.DescribeFileSystemsOutput, error) {
	if f.errTop {
		return nil, errHostile
	}
	return &efs.DescribeFileSystemsOutput{}, nil
}

// neptune: DescribeDBClusters (single top-level Describe).
type fuzzNeptuneClient struct{ errTop bool }

func (f *fuzzNeptuneClient) DescribeDBClusters(ctx context.Context, in *neptune.DescribeDBClustersInput, _ ...func(*neptune.Options)) (*neptune.DescribeDBClustersOutput, error) {
	if f.errTop {
		return nil, errHostile
	}
	return &neptune.DescribeDBClustersOutput{}, nil
}

// msk: ListClustersV2 (single top-level List).
type fuzzMSKClient struct{ errTop bool }

func (f *fuzzMSKClient) ListClustersV2(ctx context.Context, in *kafka.ListClustersV2Input, _ ...func(*kafka.Options)) (*kafka.ListClustersV2Output, error) {
	if f.errTop {
		return nil, errHostile
	}
	return &kafka.ListClustersV2Output{}, nil
}

// secretsmanager: ListSecrets (single top-level List).
type fuzzSecretsManagerClient struct{ errTop bool }

func (f *fuzzSecretsManagerClient) ListSecrets(ctx context.Context, in *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	if f.errTop {
		return nil, errHostile
	}
	return &secretsmanager.ListSecretsOutput{}, nil
}

// TestFuzzDataRestScannerInvariants drives the at-rest scanner cores with the
// four hostile shapes and asserts the honesty contract holds for all of them.
func TestFuzzDataRestScannerInvariants(t *testing.T) {
	ctx := context.Background()
	const acct, region = "111122223333", "us-east-1"

	// Scenario (a): top-level List/Describe error -> must propagate.
	t.Run("topLevelError_propagates", func(t *testing.T) {
		runScanCase(t, "dynamodb", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return DynamoDBScanner{}.scan(ctx, &fuzzDynamoDBClient{errTop: true}, acct, region)
		})
		runScanCase(t, "sqs", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return SQSScanner{}.scan(ctx, &fuzzSQSClient{errTop: true}, acct, region)
		})
		runScanCase(t, "kinesis", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return KinesisScanner{}.scan(ctx, &fuzzKinesisClient{errTop: true}, acct, region)
		})
		runScanCase(t, "backup", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return BackupScanner{}.scan(ctx, &fuzzBackupClient{errTop: true}, &fakeBackupKMS{}, acct, region)
		})
		runScanCase(t, "rds", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return RDSScanner{}.scan(ctx, &fuzzRDSClient{errTop: true}, acct, region)
		})
		runScanCase(t, "elasticache", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return ElastiCacheScanner{}.scan(ctx, &fuzzElastiCacheClient{errTop: true}, acct, region)
		})
		runScanCase(t, "efs", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return EFSScanner{}.scan(ctx, &fuzzEFSClient{errTop: true}, acct, region)
		})
		runScanCase(t, "neptune", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return NeptuneScanner{}.scan(ctx, &fuzzNeptuneClient{errTop: true}, acct, region)
		})
		runScanCase(t, "msk", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return MSKScanner{}.scan(ctx, &fuzzMSKClient{errTop: true}, acct, region)
		})
		runScanCase(t, "secretsmanager", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return SecretsManagerScanner{}.scan(ctx, &fuzzSecretsManagerClient{errTop: true}, acct, region)
		})
	})

	// Scenario (b): per-resource Describe error -> the failed resource must be
	// Unknown(+note) or dropped/propagated, NEVER no-encryption/symmetric.
	t.Run("perResourceError_neverFabricatesVerdict", func(t *testing.T) {
		runScanCase(t, "dynamodb", "resErr", false, true, func() ([]models.CryptoAsset, error) {
			return DynamoDBScanner{}.scan(ctx, &fuzzDynamoDBClient{errResource: true}, acct, region)
		})
		runScanCase(t, "sqs", "resErr", false, true, func() ([]models.CryptoAsset, error) {
			return SQSScanner{}.scan(ctx, &fuzzSQSClient{errResource: true}, acct, region)
		})
		runScanCase(t, "kinesis", "resErr", false, true, func() ([]models.CryptoAsset, error) {
			return KinesisScanner{}.scan(ctx, &fuzzKinesisClient{errResource: true}, acct, region)
		})
		runScanCase(t, "backup", "resErr", false, true, func() ([]models.CryptoAsset, error) {
			return BackupScanner{}.scan(ctx, &fuzzBackupClient{errResource: true}, &fakeBackupKMS{}, acct, region)
		})
	})

	// Scenario (c)+(d): nil/empty output structs and empty pages -> no panic, no
	// error, every emitted asset still honest (here typically zero assets).
	t.Run("emptyAndNilOutput_noPanic", func(t *testing.T) {
		runScanCase(t, "dynamodb", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return DynamoDBScanner{}.scan(ctx, &fuzzDynamoDBClient{}, acct, region)
		})
		runScanCase(t, "sqs", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return SQSScanner{}.scan(ctx, &fuzzSQSClient{}, acct, region)
		})
		runScanCase(t, "kinesis", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return KinesisScanner{}.scan(ctx, &fuzzKinesisClient{}, acct, region)
		})
		runScanCase(t, "backup", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return BackupScanner{}.scan(ctx, &fuzzBackupClient{}, &fakeBackupKMS{}, acct, region)
		})
		runScanCase(t, "rds", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return RDSScanner{}.scan(ctx, &fuzzRDSClient{}, acct, region)
		})
		runScanCase(t, "elasticache", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return ElastiCacheScanner{}.scan(ctx, &fuzzElastiCacheClient{}, acct, region)
		})
		runScanCase(t, "efs", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return EFSScanner{}.scan(ctx, &fuzzEFSClient{}, acct, region)
		})
		runScanCase(t, "neptune", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return NeptuneScanner{}.scan(ctx, &fuzzNeptuneClient{}, acct, region)
		})
		runScanCase(t, "msk", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return MSKScanner{}.scan(ctx, &fuzzMSKClient{}, acct, region)
		})
		runScanCase(t, "secretsmanager", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return SecretsManagerScanner{}.scan(ctx, &fuzzSecretsManagerClient{}, acct, region)
		})
	})
}
