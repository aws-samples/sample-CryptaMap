package keymgmt

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// SecretsRotationScanner discovers Secrets Manager secrets and reports rotation status.
type SecretsRotationScanner struct{}

// Name returns the canonical scanner identifier.
func (SecretsRotationScanner) Name() string { return "secrets_rotation" }

// Category returns the primary category for this scanner.
func (SecretsRotationScanner) Category() models.Category { return models.CategoryKeyManagement }

// secretsRotationAPI is the minimal slice of the secretsmanager client this
// scanner uses. ListSecrets is NextToken-paginated, so the scanner must loop; a
// single call returns only the first page, silently dropping secrets in dense
// accounts. Defining it as an interface keeps the pagination + error propagation
// logic unit-testable with a fake (the concrete *secretsmanager.Client satisfies it).
type secretsRotationAPI interface {
	ListSecrets(ctx context.Context, in *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
}

// secretsRotationKMSAPI is the minimal slice of the kms client used to resolve a
// customer-managed CMK's KeySpec so an asymmetric/PQC CMK can refine the posture.
type secretsRotationKMSAPI interface {
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

// Scan lists secrets and emits one asset per secret with rotation status as a property.
// Pagination via NextToken; capped at services.MaxAssetsPerScanner items.
func (s SecretsRotationScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := secretsmanager.NewFromConfig(cfg)
	kmsClient := kms.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, kmsClient, accountID, region)
}

// scan holds the testable core: it paginates ListSecrets and classifies each
// secret into a CryptoAsset. A ListSecrets error is NOT swallowed — it is
// returned so the engine records this scanner as errored, keeping a
// denied/throttled scan VISIBLY incomplete rather than a clean-looking empty
// success.
func (s SecretsRotationScanner) scan(ctx context.Context, client secretsRotationAPI, kmsClient secretsRotationKMSAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListSecrets(ctx, &secretsmanager.ListSecretsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("secretsmanager ListSecrets: %w", err)
		}
		// Cap the per-page batch to the remaining per-scanner budget so an unbounded
		// secret list can never blow past the cap; signal truncation when exhausted.
		secrets := out.SecretList
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(secrets) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			secrets = secrets[:remaining]
		}
		for _, sec := range secrets {
			if sec.ARN == nil {
				continue
			}
			id := *sec.ARN
			name := ""
			if sec.Name != nil {
				name = *sec.Name
			}
			rotationEnabled := false
			if sec.RotationEnabled != nil {
				rotationEnabled = *sec.RotationEnabled
			}

			// Resolve the encrypting CMK from the SAME ListSecrets page (no extra
			// call). When KmsKeyId is omitted the secret is encrypted with the
			// AWS-managed key aws/secretsmanager (SDK field guarantee).
			kmsKeyId := "aws/secretsmanager"
			if sec.KmsKeyId != nil && *sec.KmsKeyId != "" {
				kmsKeyId = *sec.KmsKeyId
			}

			// relatedCryptoMaterialProperties.type is an ENUM. A Secrets Manager secret
			// is a stored, KMS-encrypted credential value (not a symmetric "secret-key"
			// in the cryptographic sense) → the valid member is "credential". The
			// original "secret" label rides along as cryptamap:materialType.
			props := services.KeyMaterialProps("credential", models.StateActive, 0, kmsKeyId)
			a := services.NewAsset("secrets_rotation", models.CategoryKeyManagement, accountID, region, id, "AWS::SecretsManager::Secret", props)
			a.Properties["materialType"] = "secret"
			a.Properties["secretName"] = name
			a.Properties["rotationEnabled"] = fmt.Sprintf("%t", rotationEnabled)
			a.Properties["kmsKeyId"] = kmsKeyId

			// Rotation cadence + lifecycle dates from the already-fetched entry.
			if sec.RotationRules != nil {
				if sec.RotationRules.AutomaticallyAfterDays != nil {
					a.Properties["rotationAutomaticallyAfterDays"] = fmt.Sprintf("%d", *sec.RotationRules.AutomaticallyAfterDays)
				}
				if sec.RotationRules.ScheduleExpression != nil && *sec.RotationRules.ScheduleExpression != "" {
					a.Properties["rotationScheduleExpression"] = *sec.RotationRules.ScheduleExpression
				}
			}
			if sec.NextRotationDate != nil {
				a.Properties["nextRotationDate"] = sec.NextRotationDate.UTC().Format(time.RFC3339)
			}
			if sec.LastRotatedDate != nil {
				a.Properties["lastRotatedDate"] = sec.LastRotatedDate.UTC().Format(time.RFC3339)
			}
			if sec.LastChangedDate != nil {
				a.Properties["lastChangedDate"] = sec.LastChangedDate.UTC().Format(time.RFC3339)
			}

			// The secret VALUE is AES-256 at rest (symmetric-only, quantum safe) — the
			// correct default. When a customer-managed CMK encrypts it, resolve that
			// key's KeySpec so an asymmetric/PQC CMK refines the posture via the same
			// kmsSpecPosture helper kms_spec uses; otherwise keep SymmetricOnly.
			posture := models.PostureSymmetricOnly
			if sec.KmsKeyId != nil && *sec.KmsKeyId != "" {
				if d, derr := kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: sec.KmsKeyId}); derr != nil {
					fmt.Fprintf(os.Stderr, "secrets_rotation DescribeKey %s: %v\n", *sec.KmsKeyId, derr)
				} else if d.KeyMetadata != nil {
					keySpec := string(d.KeyMetadata.KeySpec)
					a.Properties["kmsKeySpec"] = keySpec
					posture = kmsSpecPosture(keySpec)
				}
			}
			services.PostureProperty(&a, posture)
			assets = append(assets, a)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
