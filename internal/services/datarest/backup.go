package datarest

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// Tier string constants for a BackupVault's at-rest key custody.
const (
	tierAWSManagedDefault = "aws-managed-default"
	tierCustomerCMK       = "customer-cmk"
	tierUndetermined      = "kms-key-custody-undetermined"
)

// kmsDescribeKeyAPI is the minimal KMS slice the backup scanner uses to RESOLVE an
// opaque key-id ARN to its custody tier. Defined as an interface so the resolution
// is unit-testable with a fake (the concrete *kms.Client satisfies it).
type kmsDescribeKeyAPI interface {
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

// backupKeyTierByString classifies a BackupVault EncryptionKeyArn from the STRING
// alone (no API call):
//   - empty                          -> aws-managed-default (no key set => aws/backup)
//   - the aws/backup alias (bare or ARN-suffix form) -> aws-managed-default
//   - any other alias (alias/<name>) -> customer-cmk (a named non-default alias)
//   - a raw key-id ARN (.../key/<id>)-> UNDETERMINED: DescribeBackupVault returns the
//     AWS-managed aws/backup key as a key-id ARN (observed live), INDISTINGUISHABLE
//     from a customer CMK by string alone. Asserting customer-cmk here would be a
//     FALSE key-custody positive (the mislabel class fixed in codebuild). The opaque
//     case is RESOLVED by resolveBackupKeyTier via kms:DescribeKey.
func backupKeyTierByString(arn string) string {
	a := strings.ToLower(strings.TrimSpace(arn))
	const alias = "alias/aws/backup"
	switch {
	case a == "":
		return tierAWSManagedDefault
	case a == alias || strings.HasSuffix(a, ":"+alias):
		return tierAWSManagedDefault
	case strings.Contains(a, ":key/"):
		return tierUndetermined
	case strings.Contains(a, ":alias/") || strings.HasPrefix(a, "alias/"):
		return tierCustomerCMK
	default:
		return tierUndetermined
	}
}

// resolveBackupKeyTier returns the definitive custody tier for a vault's
// EncryptionKeyArn. It first tries the string classifier; if that is UNDETERMINED
// (an opaque key-id ARN) AND a KMS client is available, it calls kms:DescribeKey and
// maps KeyMetadata.KeyManager: AWS -> aws-managed-default, CUSTOMER -> customer-cmk.
// If DescribeKey is unavailable or errors (e.g. kms:DescribeKey denied, cross-account
// key), it STAYS undetermined — never guesses custody. Mirrors kms_spec's resolution.
func resolveBackupKeyTier(ctx context.Context, kmsClient kmsDescribeKeyAPI, arn string) string {
	tier := backupKeyTierByString(arn)
	if tier != tierUndetermined || kmsClient == nil || arn == "" {
		return tier
	}
	out, err := kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(arn)})
	if err != nil || out == nil || out.KeyMetadata == nil {
		if err != nil {
			fmt.Fprintf(os.Stderr, "backup: kms DescribeKey %s: %v\n", arn, err)
		}
		return tierUndetermined // could not resolve -> stay honest, do not guess
	}
	switch out.KeyMetadata.KeyManager {
	case kmstypes.KeyManagerTypeAws:
		return tierAWSManagedDefault
	case kmstypes.KeyManagerTypeCustomer:
		return tierCustomerCMK
	default:
		return tierUndetermined
	}
}

// BackupScanner inspects AWS Backup vaults for KMS encryption.
type BackupScanner struct{}

// Name returns the canonical service identifier.
func (BackupScanner) Name() string { return "backup" }

// Category returns the primary CryptaMap category.
func (BackupScanner) Category() models.Category { return models.CategoryDataAtRest }

// backupAPI is the minimal slice of the AWS Backup client this scanner uses.
// ListBackupVaults is NextToken-paginated, so the scanner must loop; a single
// call returns only the first page, silently dropping vaults in dense accounts.
// Defining it as an interface keeps the pagination + per-vault error handling
// unit-testable with a fake (the concrete *backup.Client satisfies it).
type backupAPI interface {
	ListBackupVaults(ctx context.Context, in *backup.ListBackupVaultsInput, optFns ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error)
	DescribeBackupVault(ctx context.Context, in *backup.DescribeBackupVaultInput, optFns ...func(*backup.Options)) (*backup.DescribeBackupVaultOutput, error)
}

// Scan lists vaults, then describes each to read the EncryptionKeyArn. A KMS client
// is supplied so an opaque key-id ARN can be resolved to its custody tier.
func (s BackupScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := backup.NewFromConfig(cfg)
	kmsClient := kms.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, kmsClient, accountID, region)
}

// scan holds the testable core: it paginates ListBackupVaults and describes each
// vault to read the EncryptionKeyArn. A ListBackupVaults error is NOT swallowed —
// it is returned so the engine records this scanner as errored, keeping a
// denied/throttled scan VISIBLY incomplete rather than a clean-looking empty
// success. A per-vault DescribeBackupVault error does NOT drop the vault: it emits
// a PostureUnknown asset with a note so a read failure never reads as a clean
// all-clear by omission.
func (s BackupScanner) scan(ctx context.Context, client backupAPI, kmsClient kmsDescribeKeyAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListBackupVaults(ctx, &backup.ListBackupVaultsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("backup ListBackupVaults: %w", err)
		}
		for _, v := range out.BackupVaultList {
			if v.BackupVaultName == nil {
				continue
			}
			name := *v.BackupVaultName
			desc, derr := client.DescribeBackupVault(ctx, &backup.DescribeBackupVaultInput{BackupVaultName: v.BackupVaultName})
			if derr != nil {
				// Do NOT drop the vault: emit a PostureUnknown asset with a note so a
				// read failure never reads as a clean all-clear by omission (and never
				// as a fabricated NoEncryption false alarm).
				fmt.Fprintf(os.Stderr, "backup:%s DescribeBackupVault: %v\n", name, derr)
				a := services.NewAsset("backup", models.CategoryDataAtRest, accountID, region, name, "AWS::Backup::BackupVault", services.UnknownAtRest())
				services.PostureProperty(&a, models.PostureUnknown)
				a.Properties["note"] = "Could not describe backup vault; at-rest key undetermined."
				assets = append(assets, a)
				continue
			}
			// Every Backup vault is encrypted (AWS Backup encrypts all backups, even
			// when the source resource is unencrypted), so posture is unconditionally
			// SymmetricOnly. An empty EncryptionKeyArn means the AWS-owned default key,
			// NOT no-encryption.
			a := services.NewAsset("backup", models.CategoryDataAtRest, accountID, region, name, "AWS::Backup::BackupVault", services.AESAtRest())
			services.PostureProperty(&a, models.PostureSymmetricOnly)
			services.StampDocFactKeyed(&a, "datarest/backup/at-rest-aes256")
			// Record the key AND its CUSTODY TIER. A vault with no explicit
			// EncryptionKeyArn, OR one set to the AWS-managed aws/backup key, is the
			// AWS-managed default tier (no customer key custody). Any OTHER key ARN is
			// a customer CMK. NOTE (live-validated 2026-06-17): DescribeBackupVault
			// returns the AWS-managed default as a fully-qualified
			// arn:aws:kms:...:key/<id> for the aws/backup alias — so we must NOT treat
			// a populated EncryptionKeyArn as automatically customer-managed (that would
			// be a false key-custody positive for a regulated/BFSI customer, the same
			// class of bug fixed in codebuild). keyTier discriminates honestly.
			kmsKey := "AWS_OWNED_KMS_KEY"
			arnStr := ""
			if desc.EncryptionKeyArn != nil && *desc.EncryptionKeyArn != "" {
				kmsKey = *desc.EncryptionKeyArn
				arnStr = *desc.EncryptionKeyArn
			}
			// Resolve the custody tier. For an opaque key-id ARN this calls
			// kms:DescribeKey -> KeyManager to give a DEFINITIVE tier instead of
			// "undetermined"; it falls back to undetermined (never guesses) if the
			// key can't be resolved.
			keyTier := resolveBackupKeyTier(ctx, kmsClient, arnStr)
			a.Properties["kmsKeyArn"] = kmsKey
			a.Properties["keyTier"] = keyTier
			switch keyTier {
			case tierAWSManagedDefault:
				a.Properties["note"] = "Backup vault is encrypted with the AWS-managed default key (no customer key custody), not a customer CMK."
			case tierUndetermined:
				a.Properties["note"] = "Backup vault is encrypted with a KMS key given as a key-id ARN that could not be resolved via kms:DescribeKey (e.g. access denied / cross-account); custody undetermined."
			}
			assets = append(assets, a)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
