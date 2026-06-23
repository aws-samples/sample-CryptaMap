package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/mgn"
	mgntypes "github.com/aws/aws-sdk-go-v2/service/mgn/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// MGNScanner inspects AWS Application Migration Service (MGN) replication
// configuration templates for the at-rest encryption of their EBS staging
// volumes.
//
// WHY this is an at-rest crypto surface that matters: during a migration MGN
// continuously block-copies the FULL contents of each source production disk
// into EBS staging volumes in the staging-area subnet. That staging copy is a
// complete replica of the production data sitting at rest in the target account
// — exactly the kind of sensitive data a regulator cares about — so its
// encryption posture must be inventoried, not assumed.
//
// EBS volume encryption is AES-256-XTS (the disk/block-encryption mode, two
// 256-bit keys), NOT AES-256-GCM — so we use services.AESXTSAtRest(), matching
// the EBS exemplars. It is symmetric AES-256, quantum-resistant today, hence
// SymmetricOnly — never a no-encryption finding.
//
// HONESTY CONTRACT / no false all-clear: MGN replication staging volumes are
// always encrypted (EBS encryption is always applied to MGN staging disks); the
// EbsEncryption field only selects the KEY TIER, never an off state:
//   - CUSTOM  -> a customer-managed CMK (EbsEncryptionKeyArn), key custody held
//     by the customer.
//   - DEFAULT -> the account's default EBS encryption key (aws/ebs AWS-managed
//     key) — still AES-256, but "no customer key custody", which is NOT a clean
//     all-clear and is recorded as such, not as no-encryption.
//
// There is no per-template "encryption disabled" toggle, so this universal
// always-encrypted guarantee rests on AWS docs and is stamped via StampDocFact.
type MGNScanner struct{}

// mgnAPI is the minimal slice of the mgn client this scanner uses.
// DescribeReplicationConfigurationTemplates is NextToken-paginated; defining it
// as an interface keeps the pagination + per-template classification unit-testable
// with a fake (the concrete *mgn.Client satisfies it).
type mgnAPI interface {
	DescribeReplicationConfigurationTemplates(ctx context.Context, in *mgn.DescribeReplicationConfigurationTemplatesInput, optFns ...func(*mgn.Options)) (*mgn.DescribeReplicationConfigurationTemplatesOutput, error)
}

// Name returns the canonical service identifier.
func (MGNScanner) Name() string { return "mgn" }

// Category returns the primary CryptaMap category.
func (MGNScanner) Category() models.Category { return models.CategoryDataAtRest }

// Scan enumerates replication configuration templates (NextToken pagination)
// and emits one at-rest asset per template. There is no per-resource Describe:
// DescribeReplicationConfigurationTemplates already returns the full template
// (including EbsEncryption + EbsEncryptionKeyArn) in Items, so the template
// object is classified inline.
func (s MGNScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := mgn.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates
// DescribeReplicationConfigurationTemplates and classifies each template inline.
// The list error is returned (not swallowed) so a denied/throttled scan stays
// VISIBLY incomplete.
func (s MGNScanner) scan(ctx context.Context, client mgnAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.DescribeReplicationConfigurationTemplates(ctx, &mgn.DescribeReplicationConfigurationTemplatesInput{
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("mgn DescribeReplicationConfigurationTemplates: %w", err)
		}
		for _, tmpl := range out.Items {
			if remaining := services.MaxAssetsPerScanner - len(assets); remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			assets = append(assets, s.assetFor(accountID, region, tmpl))
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}

// assetFor classifies a single replication configuration template. MGN staging
// volumes are EBS volumes (AES-256-XTS), always encrypted, so the posture is
// unconditionally SymmetricOnly; only the key tier varies (CUSTOM customer CMK
// vs DEFAULT account default EBS key).
func (MGNScanner) assetFor(accountID, region string, tmpl mgntypes.ReplicationConfigurationTemplate) models.CryptoAsset {
	id := ""
	if tmpl.ReplicationConfigurationTemplateID != nil {
		id = *tmpl.ReplicationConfigurationTemplateID
	}

	a := services.NewAsset("mgn", models.CategoryDataAtRest, accountID, region, id,
		"AWS::MGN::ReplicationConfigurationTemplate", services.AESXTSAtRest())
	services.PostureProperty(&a, models.PostureSymmetricOnly)
	// Universal AWS-doc guarantee: MGN replication staging volumes are EBS
	// volumes and are always encrypted (no per-template disable toggle); the
	// field only chooses the key tier. Record provenance for the freshness pass.
	services.StampDocFact(&a, "high",
		"https://docs.aws.amazon.com/mgn/latest/ug/replication-server-settings.html",
		"2026-06-15")

	ebsEncryption := string(tmpl.EbsEncryption)
	a.Properties["ebsEncryption"] = ebsEncryption

	// Key-tier evidence: CUSTOM carries a customer CMK ARN; DEFAULT is the
	// account's default EBS key (aws/ebs AWS-managed default — no customer key
	// custody, still AES-256, never a no-encryption all-clear).
	switch tmpl.EbsEncryption {
	case mgntypes.ReplicationConfigurationEbsEncryptionCustom:
		if tmpl.EbsEncryptionKeyArn != nil && *tmpl.EbsEncryptionKeyArn != "" {
			a.Properties["kmsKeyId"] = *tmpl.EbsEncryptionKeyArn
		} else {
			a.Properties["kmsKeyId"] = "CUSTOM_KEY_UNRESOLVED"
		}
	default:
		// DEFAULT (or unset): account default EBS encryption key.
		a.Properties["kmsKeyId"] = "AWS_DEFAULT_EBS_KEY"
		a.Properties["keyTier"] = "aws-managed-default"
		a.Properties["note"] = "MGN staging volumes use the account default EBS encryption key (aws/ebs); AES-256 at rest but no customer key custody."
	}
	return a
}
