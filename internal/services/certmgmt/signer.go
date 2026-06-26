package certmgmt

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/signer"
	signertypes "github.com/aws/aws-sdk-go-v2/service/signer/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// SignerScanner inventories AWS Signer code-signing profiles. Signing is the
// service's core function; every profile produces a CLASSICAL digital signature
// (RSA or ECDSA) — both quantum-vulnerable under Shor's algorithm — and AWS Signer
// offers no post-quantum signature option. So every profile is NonPQCClassical: a
// code-integrity quantum-migration target, never an "encryption off" finding.
type SignerScanner struct{}

// Name returns the canonical scanner identifier.
func (SignerScanner) Name() string { return "signer" }

// Category returns the primary category for this scanner.
func (SignerScanner) Category() models.Category { return models.CategoryCertificate }

// signerAPI is the minimal slice of the signer client this scanner uses.
// ListSigningProfiles is NextToken-paginated, so the scanner must loop; a single
// call returns only the first page, silently dropping profiles in dense accounts.
// Defining it as an interface keeps the pagination + per-profile classification
// logic unit-testable with a fake (the concrete *signer.Client satisfies it).
type signerAPI interface {
	ListSigningProfiles(ctx context.Context, in *signer.ListSigningProfilesInput, optFns ...func(*signer.Options)) (*signer.ListSigningProfilesOutput, error)
	GetSigningProfile(ctx context.Context, in *signer.GetSigningProfileInput, optFns ...func(*signer.Options)) (*signer.GetSigningProfileOutput, error)
}

// Scan lists signing profiles, then GetSigningProfile for the signature algorithm.
func (s SignerScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := signer.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListSigningProfiles and classifies
// each profile into a CryptoAsset. A ListSigningProfiles error is NOT swallowed —
// it is returned so the engine records this scanner as errored (which surfaces in
// coverage), keeping a denied/throttled scan VISIBLY incomplete rather than a
// clean-looking empty success.
func (s SignerScanner) scan(ctx context.Context, client signerAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListSigningProfiles(ctx, &signer.ListSigningProfilesInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("signer ListSigningProfiles: %w", err)
		}
		profiles := out.Profiles
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(profiles) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			profiles = profiles[:remaining]
		}
		page := services.MapConcurrent(ctx, services.DefaultInnerConcurrency, profiles,
			func(ctx context.Context, p signertypes.SigningProfile) (models.CryptoAsset, bool) {
				if p.ProfileName == nil {
					return models.CryptoAsset{}, false
				}
				name := *p.ProfileName
				id := name
				if p.Arn != nil && *p.Arn != "" {
					id = *p.Arn
				}

				// The signature algorithm comes from GetSigningProfile overrides; if
				// unreadable, the platform still implies a classical algorithm.
				encAlgo, hashAlgo := "", ""
				observed := false
				if g, gerr := client.GetSigningProfile(ctx, &signer.GetSigningProfileInput{ProfileName: &name}); gerr != nil {
					fmt.Fprintf(os.Stderr, "signer GetSigningProfile %s: %v\n", name, gerr)
				} else if g.Overrides != nil && g.Overrides.SigningConfiguration != nil {
					sc := g.Overrides.SigningConfiguration
					encAlgo = string(sc.EncryptionAlgorithm)
					hashAlgo = string(sc.HashAlgorithm)
					observed = encAlgo != ""
				}

				// sigRef is the signatureAlgorithmRef (a CycloneDX refType — must be a
				// genuine algorithm token, never a sentinel). "RSA"/"ECDSA" are real
				// (coarse) signature-family tokens. When the API exposes no algorithm,
				// leave the ref EMPTY rather than emit the "classical signature"
				// sentinel as a (dangling) reference; the descriptive label still rides
				// on AlgorithmName for the detail panel.
				sigRef := ""
				algoLabel := "classical signature"
				switch encAlgo {
				case string(signertypes.EncryptionAlgorithmRsa):
					sigRef, algoLabel = "RSA", "RSA"
				case string(signertypes.EncryptionAlgorithmEcdsa):
					sigRef, algoLabel = "ECDSA", "ECDSA"
				}
				props := services.CertProps(name, "", sigRef, time.Time{}, time.Time{})
				if props.AlgorithmProperties == nil {
					props.AlgorithmProperties = &models.AlgorithmProperties{}
				}
				props.AlgorithmProperties.Primitive = models.PrimitiveSignature
				props.AlgorithmProperties.AlgorithmName = algoLabel
				props.AlgorithmProperties.NistQuantumSecurityLevel = 0

				a := services.NewAsset("signer", models.CategoryCertificate, accountID, region, id, "AWS::Signer::SigningProfile", props)
				services.PostureProperty(&a, models.PostureNonPQCClassical)
				if observed {
					services.StampObserved(&a, "high")
				}
				if p.PlatformId != nil {
					a.Properties["platformId"] = *p.PlatformId
				}
				if encAlgo != "" {
					a.Properties["signatureAlgorithm"] = encAlgo
				}
				if hashAlgo != "" {
					a.Properties["hashAlgorithm"] = hashAlgo
				}
				a.Properties["note"] = "AWS Signer code-signing uses traditional RSA/ECDSA signatures (quantum-vulnerable); no post-quantum option exists today."
				return a, true
			})
		assets = append(assets, page...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
