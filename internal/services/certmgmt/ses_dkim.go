package certmgmt

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	sesv2types "github.com/aws/aws-sdk-go-v2/service/sesv2/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// SESDKIMScanner inventories Amazon SES email-identity DKIM signing posture. DKIM
// is a SIGNING dimension (it authenticates the sender of a message), NOT an
// encryption dimension — so this scanner never emits a "no-encryption" finding.
// SES Easy-DKIM signs with RSA (RSA_1024_BIT or RSA_2048_BIT) and BYODKIM
// (EXTERNAL origin) is likewise an RSA key pair you supply; both are CLASSICAL
// digital signatures, quantum-vulnerable under Shor's algorithm, and SES offers
// no post-quantum DKIM option today. So an identity with signing ENABLED is
// NonPQCClassical: an email-authentication quantum-migration target, never an
// "encryption off" finding (mirrors signer.go). When signing is DISABLED there is
// no active signature surface to migrate, so posture is Unknown with an explicit
// note — still never no-encryption, because DKIM is signing, not encryption.
type SESDKIMScanner struct{}

// Name returns the canonical scanner identifier.
func (SESDKIMScanner) Name() string { return "ses_dkim" }

// Category returns the primary category for this scanner.
func (SESDKIMScanner) Category() models.Category { return models.CategoryCertificate }

// Scan lists SES email identities, then GetEmailIdentity for each to read its
// DKIM attributes (signing enabled, key length, attributes origin, status). Each
// identity becomes one signing asset:
//   - SigningEnabled=true  -> NonPQCClassical (RSA DKIM signature, no PQC option)
//   - SigningEnabled=false -> Unknown (no active signature surface; not a finding)
//
// The SigningAttributesOrigin records key custody: AWS_SES is Easy-DKIM (AWS holds
// the private key), EXTERNAL is BYODKIM (customer-supplied key) — neither changes
// the algorithm classification, both are recorded for evidence.
func (s SESDKIMScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := sesv2.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region

	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListEmailIdentities(ctx, &sesv2.ListEmailIdentitiesInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("ses_dkim ListEmailIdentities: %w", err)
		}
		identities := out.EmailIdentities
		// Cap the per-page batch to the remaining per-scanner budget BEFORE the
		// concurrent fan-out, so a pathological region never launches more than the
		// cap's worth of GetEmailIdentity goroutines.
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(identities) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			identities = identities[:remaining]
		}
		page := services.MapConcurrent(ctx, services.DefaultInnerConcurrency, identities,
			func(ctx context.Context, info sesv2types.IdentityInfo) (models.CryptoAsset, bool) {
				if info.IdentityName == nil || *info.IdentityName == "" {
					return models.CryptoAsset{}, false
				}
				name := *info.IdentityName

				g, gerr := client.GetEmailIdentity(ctx, &sesv2.GetEmailIdentityInput{EmailIdentity: &name})
				if gerr != nil {
					fmt.Fprintf(os.Stderr, "ses_dkim:%s GetEmailIdentity: %v\n", name, gerr)
					return models.CryptoAsset{}, false
				}

				return classifySESDKIM(accountID, region, name, info.IdentityType, g.DkimAttributes), true
			})
		assets = append(assets, page...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}

// classifySESDKIM maps one SES email identity's DKIM attributes to the classified
// CryptoAsset. It is a PURE, SDK-types-only function (no AWS client, no context) so
// the DKIM signing classification is the single source of truth and is directly
// unit-testable.
//
// DKIM is a SIGNING surface, not encryption, so this NEVER returns
// PostureNoEncryption. The asset is always shaped as a classical RSA signature
// (mirrors signer.go); posture reflects whether that signature surface is active:
//   - SigningEnabled=true  -> NonPQCClassical (active RSA DKIM, quantum-vulnerable,
//     no PQC option exists today) — the migration target.
//   - SigningEnabled=false -> Unknown (no active signature surface; not a finding).
//   - dkim == nil          -> Unknown (DKIM not configured at all).
//
// identityType (may be empty) and the DKIM SigningAttributesOrigin (AWS_SES =
// Easy-DKIM / AWS holds the key, EXTERNAL = BYODKIM / customer-supplied) are
// recorded as evidence; neither changes the algorithm classification.
func classifySESDKIM(accountID, region, name string, identityType sesv2types.IdentityType, dkim *sesv2types.DkimAttributes) models.CryptoAsset {
	// DKIM is a signature surface. Shape the asset as a classical signature
	// (mirrors signer.go) regardless of enabled state; posture then reflects
	// whether that surface is active.
	props := services.CertProps(name, "", "RSA", time.Time{}, time.Time{})
	if props.AlgorithmProperties == nil {
		props.AlgorithmProperties = &models.AlgorithmProperties{}
	}
	props.AlgorithmProperties.Primitive = models.PrimitiveSignature
	props.AlgorithmProperties.AlgorithmName = "RSA"
	props.AlgorithmProperties.NistQuantumSecurityLevel = 0

	a := services.NewAsset("ses_dkim", models.CategoryCertificate, accountID, region, name, "AWS::SES::EmailIdentity", props)
	if identityType != "" {
		a.Properties["identityType"] = string(identityType)
	}

	if dkim == nil {
		// No DKIM block at all: nothing to classify as a signature.
		services.PostureProperty(&a, models.PostureUnknown)
		a.Properties["signingEnabled"] = "false"
		a.Properties["note"] = "SES identity has no DKIM attributes; DKIM signing is not configured (no active signature surface). DKIM is sender authentication (signing), not encryption."
		return a
	}

	a.Properties["signingEnabled"] = fmt.Sprintf("%t", dkim.SigningEnabled)
	if dkim.SigningAttributesOrigin != "" {
		a.Properties["signingAttributesOrigin"] = string(dkim.SigningAttributesOrigin)
	}
	if dkim.Status != "" {
		a.Properties["dkimStatus"] = string(dkim.Status)
	}
	// CurrentSigningKeyLength is the [Easy DKIM] key in use; record the
	// future-rotation length too when present. Both are RSA key lengths.
	keyLen := string(dkim.CurrentSigningKeyLength)
	if keyLen != "" {
		a.Properties["signingKeyLength"] = keyLen
	}
	if dkim.NextSigningKeyLength != "" {
		a.Properties["nextSigningKeyLength"] = string(dkim.NextSigningKeyLength)
	}

	if dkim.SigningEnabled {
		// Active RSA DKIM signing — classical, quantum-vulnerable, no PQC
		// option. This is the migration target. Per-resource observation.
		services.PostureProperty(&a, models.PostureNonPQCClassical)
		services.StampObserved(&a, "high")
		custody := "Easy-DKIM (AWS_SES): AWS holds the DKIM private key"
		if dkim.SigningAttributesOrigin == sesv2types.DkimSigningAttributesOriginExternal {
			custody = "BYODKIM (EXTERNAL): customer-supplied DKIM key"
		}
		a.Properties["note"] = "SES DKIM signs email with a classical RSA signature (" + keyLenOrDefault(keyLen) + ", quantum-vulnerable under Shor); no post-quantum DKIM option exists today. Key custody: " + custody + "."
	} else {
		// Signing disabled: no active signature surface to migrate. Not a
		// finding, and never no-encryption (DKIM is signing, not encryption).
		services.PostureProperty(&a, models.PostureUnknown)
		services.StampObserved(&a, "high")
		a.Properties["note"] = "SES DKIM signing is NOT enabled for this identity (no active signature surface). DKIM is sender authentication (signing), not encryption; when enabled it uses classical RSA."
	}
	return a
}

// keyLenOrDefault renders the observed RSA key length for the note, defaulting to
// the generic "RSA" descriptor when SES did not report a specific length (e.g. an
// EXTERNAL/BYODKIM identity where CurrentSigningKeyLength is not populated).
func keyLenOrDefault(keyLen string) string {
	if keyLen == "" {
		return "RSA"
	}
	return keyLen
}
