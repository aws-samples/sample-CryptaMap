package datarest

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/keyspaces"
	kstypes "github.com/aws/aws-sdk-go-v2/service/keyspaces/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// systemKeyspaces is the set of AWS-managed system keyspaces that Amazon
// Keyspaces exposes but that customers neither create nor control. Their tables
// would otherwise inflate the no-encryption count, so they are skipped during a
// scan. Membership is an EXACT match (not a prefix), so a customer keyspace
// literally named e.g. "system_app" or "systemstore" is NOT skipped.
var systemKeyspaces = map[string]struct{}{
	"system":                  {},
	"system_schema":           {},
	"system_schema_mcs":       {},
	"system_multiregion_info": {},
	"system_auth":             {},
	"system_distributed":      {},
	"system_traces":           {},
	"system_views":            {},
	"system_virtual_schema":   {},
}

// isSystemKeyspace reports whether name is an AWS-managed system keyspace that
// should be skipped. It is a pure, SDK-free exact-match lookup so the skip
// decision can be unit-tested without a Keyspaces client.
func isSystemKeyspace(name string) bool {
	_, ok := systemKeyspaces[name]
	return ok
}

// keyspacesAPI is the minimal slice of the keyspaces client this scanner uses.
// ListKeyspaces and ListTables are NextToken-paginated; defining it as an
// interface keeps the nested pagination + GetTable classification unit-testable
// with a fake (the concrete *keyspaces.Client satisfies it).
type keyspacesAPI interface {
	ListKeyspaces(ctx context.Context, in *keyspaces.ListKeyspacesInput, optFns ...func(*keyspaces.Options)) (*keyspaces.ListKeyspacesOutput, error)
	ListTables(ctx context.Context, in *keyspaces.ListTablesInput, optFns ...func(*keyspaces.Options)) (*keyspaces.ListTablesOutput, error)
	GetTable(ctx context.Context, in *keyspaces.GetTableInput, optFns ...func(*keyspaces.Options)) (*keyspaces.GetTableOutput, error)
}

// KeyspacesScanner inspects Amazon Keyspaces tables for KMS encryption.
type KeyspacesScanner struct{}

// Name returns the canonical service identifier.
func (KeyspacesScanner) Name() string { return "keyspaces" }

// Category returns the primary CryptaMap category.
func (KeyspacesScanner) Category() models.Category { return models.CategoryDataAtRest }

// Scan iterates keyspaces, lists tables in each, and uses GetTable to read the
// EncryptionSpecification.
//
// Keyspaces uses GetTable (not DescribeTable) on the SDK side; either AWS_OWNED
// or CUSTOMER_MANAGED counts as encrypted.
func (s KeyspacesScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := keyspaces.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it iterates keyspaces, lists tables in each, and
// reads each table's EncryptionSpecification via GetTable. A ListKeyspaces error
// is returned (not swallowed) so a denied/throttled scan stays VISIBLY incomplete.
func (s KeyspacesScanner) scan(ctx context.Context, client keyspacesAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var ksToken *string
	for {
		ksOut, err := client.ListKeyspaces(ctx, &keyspaces.ListKeyspacesInput{NextToken: ksToken})
		if err != nil {
			return nil, fmt.Errorf("keyspaces ListKeyspaces: %w", err)
		}
		for _, ks := range ksOut.Keyspaces {
			if ks.KeyspaceName == nil {
				continue
			}
			ksName := *ks.KeyspaceName
			if isSystemKeyspace(ksName) {
				// Skip AWS-managed system keyspaces; their tables are not
				// customer-controlled and would inflate the no-encryption count.
				continue
			}
			var tblToken *string
			for {
				tblOut, terr := client.ListTables(ctx, &keyspaces.ListTablesInput{KeyspaceName: ks.KeyspaceName, NextToken: tblToken})
				if terr != nil {
					fmt.Fprintf(os.Stderr, "keyspaces:%s ListTables: %v\n", ksName, terr)
					break
				}
				for _, t := range tblOut.Tables {
					if t.TableName == nil {
						continue
					}
					tName := *t.TableName
					id := ksName + "/" + tName
					desc, derr := client.GetTable(ctx, &keyspaces.GetTableInput{KeyspaceName: ks.KeyspaceName, TableName: t.TableName})
					// Keyspaces encrypts ALL tables at rest with AES-256 and it cannot be
					// disabled, so posture is unconditionally SymmetricOnly. The
					// EncryptionSpecification only selects the key tier (AWS-owned default
					// vs customer-managed); a nil spec or a GetTable error means the
					// AWS-owned default key, NOT no-encryption.
					kmsKey := "AWS_OWNED_KMS_KEY"
					if derr != nil {
						fmt.Fprintf(os.Stderr, "keyspaces:%s GetTable: %v\n", id, derr)
					} else if spec := desc.EncryptionSpecification; spec != nil {
						if spec.Type == kstypes.EncryptionTypeCustomerManagedKmsKey && spec.KmsKeyIdentifier != nil && *spec.KmsKeyIdentifier != "" {
							kmsKey = *spec.KmsKeyIdentifier
						}
					}
					a := services.NewAsset("keyspaces", models.CategoryDataAtRest, accountID, region, id, "AWS::Cassandra::Table", services.AESAtRest())
					services.PostureProperty(&a, models.PostureSymmetricOnly)
					services.StampDocFactKeyed(&a, "datarest/keyspaces/at-rest-aes256")
					a.Properties["kmsKeyId"] = kmsKey
					assets = append(assets, a)
				}
				if tblOut.NextToken == nil || *tblOut.NextToken == "" {
					break
				}
				tblToken = tblOut.NextToken
			}
		}
		if ksOut.NextToken == nil || *ksOut.NextToken == "" {
			break
		}
		ksToken = ksOut.NextToken
	}
	return assets, nil
}
