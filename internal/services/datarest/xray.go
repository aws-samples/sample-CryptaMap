package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/xray"
	xraytypes "github.com/aws/aws-sdk-go-v2/service/xray/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// XRayScanner inspects the account+region-level AWS X-Ray at-rest encryption
// configuration.
//
// CRITICAL (modeled exactly like dynamodb.go): X-Ray ALWAYS encrypts trace data
// at rest — encryption cannot be disabled. A single GetEncryptionConfig call
// returns the at-rest config for the whole (account, region). The Type enum only
// distinguishes the KEY TIER, never an on/off state:
//
//   - Type=KMS  -> a customer-supplied KMS CMK (record its KeyId).
//   - Type=NONE -> AWS's free internal default encryption (NOT even the
//     aws/xray managed key). This is still AES-256 symmetric at rest; it is "no
//     customer key custody", NOT no-encryption.
//
// So posture is UNCONDITIONALLY SymmetricOnly with AESAtRest(). We NEVER emit
// PostureNoEncryption and NEVER a "data unencrypted" finding for X-Ray — that
// would be a false alarm against the regulator-honesty contract. Status (ACTIVE/
// UPDATING) is recorded as evidence only; UPDATING is a normal key-switch state,
// not a no-encryption signal. Exactly ONE account-level asset is emitted.
type XRayScanner struct{}

// xrayAPI is the minimal slice of the xray client this scanner uses. Defining it
// as an interface keeps the single-call read + classification unit-testable with
// a fake (the concrete *xray.Client satisfies it).
type xrayAPI interface {
	GetEncryptionConfig(ctx context.Context, in *xray.GetEncryptionConfigInput, optFns ...func(*xray.Options)) (*xray.GetEncryptionConfigOutput, error)
}

// Name returns the canonical service identifier.
func (XRayScanner) Name() string { return "xray" }

// Category returns the primary CryptaMap category.
func (XRayScanner) Category() models.Category { return models.CategoryDataAtRest }

// Scan reads the single (account, region) X-Ray encryption configuration and
// emits one account-level at-rest asset. There is no list/pagination — X-Ray
// exposes exactly one encryption config per region.
func (s XRayScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := xray.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it reads the single (account, region) X-Ray
// encryption config and emits one account-level at-rest asset.
func (s XRayScanner) scan(ctx context.Context, client xrayAPI, accountID, region string) ([]models.CryptoAsset, error) {
	out, err := client.GetEncryptionConfig(ctx, &xray.GetEncryptionConfigInput{})
	if err != nil {
		return nil, fmt.Errorf("xray GetEncryptionConfig: %w", err)
	}

	a := classifyXRayEncryption(out.EncryptionConfig, accountID, region)
	return []models.CryptoAsset{a}, nil
}

// classifyXRayEncryption is the pure (no AWS client, no context) classification
// for the single account+region X-Ray at-rest encryption config. It is the ONE
// source of truth Scan calls so the posture/Property mapping can be table-tested
// without a live X-Ray client.
//
// Invariants (regulator-honesty contract — see the type doc):
//   - Posture is UNCONDITIONALLY models.PostureSymmetricOnly with AESAtRest().
//     X-Ray cannot disable at-rest encryption, so we NEVER emit
//     PostureNoEncryption and NEVER a "data unencrypted" finding for X-Ray.
//   - Type=KMS with a non-empty KeyId -> customer CMK; kmsKeyId is that KeyId.
//   - Type=NONE, any other type, or a nil config -> AWS's free internal default
//     encryption; kmsKeyId is the "AWS_DEFAULT_ENCRYPTION" sentinel and a custody
//     note is stamped making clear this is NOT a clean all-clear.
func classifyXRayEncryption(ec *xraytypes.EncryptionConfig, accountID, region string) models.CryptoAsset {
	// X-Ray always encrypts at rest with AES-256 (universal AWS-doc guarantee),
	// so posture is unconditionally SymmetricOnly regardless of Type.
	a := services.NewAsset("xray", models.CategoryDataAtRest, accountID, region, "encryption-config", "AWS::XRay::EncryptionConfig", services.AESAtRest())
	services.PostureProperty(&a, models.PostureSymmetricOnly)
	services.StampDocFact(&a, "high", "https://docs.aws.amazon.com/xray/latest/devguide/xray-console-encryption.html", "2026-06-15")

	const custodyNote = "X-Ray always encrypts at rest; default is AWS-owned internal encryption, no customer key custody"

	// Distinguish the key tier from the Type enum. Type=KMS is a customer CMK
	// (record its KeyId); Type=NONE (or an absent config) is AWS's free internal
	// default encryption — still AES-256, but no customer key custody. Neither is
	// a no-encryption state.
	kmsKey := "AWS_DEFAULT_ENCRYPTION"
	if ec != nil {
		a.Properties["encryptionType"] = string(ec.Type)
		if ec.Status != "" {
			a.Properties["status"] = string(ec.Status)
		}
		if ec.Type == xraytypes.EncryptionTypeKms && ec.KeyId != nil && *ec.KeyId != "" {
			kmsKey = *ec.KeyId
		} else {
			a.Properties["note"] = custodyNote
		}
	} else {
		a.Properties["note"] = custodyNote
	}
	a.Properties["kmsKeyId"] = kmsKey

	return a
}
