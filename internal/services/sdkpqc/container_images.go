package sdkpqc

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// ContainerImagesScanner inspects ECR repositories' at-rest encryption.
type ContainerImagesScanner struct{}

// Name returns the canonical scanner identifier.
func (ContainerImagesScanner) Name() string { return "container_images" }

// Category returns the primary category for this scanner. ECR's per-repository
// crypto fact is encryption-AT-REST (DescribeRepositories already returns it);
// there is no inherent per-repository TLS/transit fact to record.
func (ContainerImagesScanner) Category() models.Category { return models.CategoryDataAtRest }

// ecrImagesAPI is the minimal slice of the ECR + KMS clients this scanner uses.
// DescribeRepositories is NextToken-paginated (a single call returns only the
// first page, silently dropping repositories in dense accounts), so the scanner
// must loop. DescribeKey resolves the backing KMS key's spec for KMS-encrypted
// repositories. Defining it as an interface keeps the pagination, per-repository
// error-degradation, and KMS spec-mapping logic unit-testable with a fake (the
// concrete *ecr.Client and *kms.Client satisfy their respective methods).
type ecrImagesAPI interface {
	DescribeRepositories(ctx context.Context, in *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	DescribeImages(ctx context.Context, in *ecr.DescribeImagesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error)
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

// ecrImagesClients adapts the separate ECR and KMS SDK clients into a single
// ecrImagesAPI so the real Scan can delegate to the testable core. The ECR
// methods are promoted from the embedded *ecr.Client; DescribeKey forwards to KMS.
type ecrImagesClients struct {
	*ecr.Client
	kms *kms.Client
}

func (c ecrImagesClients) DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return c.kms.DescribeKey(ctx, in, optFns...)
}

// Scan lists ECR repositories and emits one at-rest asset per repository, read
// from the EncryptionConfiguration already present on each Repository (no extra
// call for the type). In-image library PQC posture is NOT observable from any API
// (real PQC check requires image content inspection), so it is left out of the
// posture; image counts are recorded only as informational metadata.
// Pagination via NextToken; capped at 1000 items.
func (s ContainerImagesScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := ecrImagesClients{Client: ecr.NewFromConfig(cfg), kms: kms.NewFromConfig(cfg)}
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeRepositories and emits one
// at-rest asset per repository. A DescribeRepositories error is NOT swallowed — it
// is returned so the engine records this scanner as errored (a denied/throttled
// scan stays VISIBLY incomplete rather than a clean-looking empty success). A
// per-repository DescribeImages error degrades only the (informational) image
// count and never drops the repository asset.
func (s ContainerImagesScanner) scan(ctx context.Context, client ecrImagesAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	const maxItems = 1000
	var nextToken *string
	for {
		out, err := client.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("ecr DescribeRepositories: %w", err)
		}
		for _, r := range out.Repositories {
			if r.RepositoryName == nil {
				continue
			}
			id := ""
			if r.RepositoryArn != nil {
				id = *r.RepositoryArn
			} else {
				id = *r.RepositoryName
			}
			imageCount := 0
			imgOut, ierr := client.DescribeImages(ctx, &ecr.DescribeImagesInput{RepositoryName: r.RepositoryName})
			if ierr != nil {
				fmt.Fprintf(os.Stderr, "ecr DescribeImages %s: %v\n", *r.RepositoryName, ierr)
			} else {
				imageCount = len(imgOut.ImageDetails)
			}

			// Read the at-rest encryption ECR returned on this very repository (no
			// extra call needed for the type). Branch on EncryptionType, resolving the
			// backing KMS key's spec for KMS/KMS_DSSE — mirrors datarest/s3.go's
			// s3PropsForSSE, including its DescribeKey error-degradation (a DescribeKey
			// failure degrades to SYMMETRIC_DEFAULT, never silently to classical).
			encryptionType := ""
			kmsKey := ""
			kmsKeySpec := ""
			props, posture := ecrAtRestProps(ctx, client, r.EncryptionConfiguration, &encryptionType, &kmsKey, &kmsKeySpec)

			a := services.NewAsset("container_images", models.CategoryDataAtRest, accountID, region, id, "AWS::ECR::Repository", props)
			a.Properties["repositoryName"] = *r.RepositoryName
			a.Properties["imageCount"] = fmt.Sprintf("%d", imageCount)
			if encryptionType != "" {
				a.Properties["encryptionType"] = encryptionType
			}
			if kmsKey != "" {
				a.Properties["kmsKey"] = kmsKey
			}
			if kmsKeySpec != "" {
				a.Properties["kmsKeySpec"] = kmsKeySpec
			}
			services.PostureProperty(&a, posture)
			// At-rest behavior is a universal, definitional guarantee of the ECR
			// EncryptionType enum (AES256 -> SSE-S3 AES-256; KMS/KMS_DSSE -> KMS), so
			// stamp the doc-fact provenance for the symmetric/at-rest classifications.
			if posture == models.PostureSymmetricOnly {
				services.StampDocFactKeyed(&a, "sdkpqc/container_images/ecr-at-rest-encryption")
			}
			assets = append(assets, a)
			if len(assets) >= maxItems {
				return assets, nil
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}

// ecrAtRestProps builds the at-rest CryptoProperties + posture for a repository's
// EncryptionConfiguration. EncryptionType is API-required so it is always present;
// a nil config (older API shapes) is treated as the ECR default (AES256 / SSE-S3).
// For KMS/KMS_DSSE it issues one kms.DescribeKey on the configured key to read its
// KeySpec, then derives posture from the spec. ECR (a KMS-integrated service) uses
// only symmetric encryption keys, so in practice the spec is SYMMETRIC_DEFAULT
// (symmetric-only); RSA_*/ECC_* are handled defensively as classical.
// The encryptionType, kmsKey and resolved kmsKeySpec are returned for flat props.
func ecrAtRestProps(ctx context.Context, kmsClient ecrImagesAPI, ec *ecrtypes.EncryptionConfiguration, outType, outKey, outSpec *string) (models.CryptoProperties, models.CryptoPosture) {
	encType := ecrtypes.EncryptionTypeAes256
	if ec != nil {
		encType = ec.EncryptionType
		if ec.KmsKey != nil {
			*outKey = *ec.KmsKey
		}
	}
	*outType = string(encType)

	switch encType {
	case ecrtypes.EncryptionTypeKms, ecrtypes.EncryptionTypeKmsDsse:
		keySpec := ""
		if outKey != nil && *outKey != "" {
			if d, derr := kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(*outKey)}); derr != nil {
				fmt.Fprintf(os.Stderr, "ecr KMS DescribeKey %s: %v\n", *outKey, derr)
			} else if d.KeyMetadata != nil {
				keySpec = string(d.KeyMetadata.KeySpec)
			}
		}
		if keySpec == "" {
			// AWS-managed (aws/ecr) key or unreadable spec: still a KMS-backed
			// symmetric envelope under the hood; record SYMMETRIC_DEFAULT, never
			// silently classical.
			keySpec = "SYMMETRIC_DEFAULT"
		}
		*outSpec = keySpec
		return services.AESAtRestKMS(keySpec), postureForKeySpec(keySpec)
	default: // EncryptionTypeAes256 (SSE-S3 managed) or unset -> AES-256, quantum-safe at rest
		return services.AESAtRest(), models.PostureSymmetricOnly
	}
}

// postureForKeySpec maps an ECR encryption-key KMS KeySpec to a PQC posture.
// ECR uses only symmetric KMS keys, so the realistic spec is SYMMETRIC_DEFAULT
// (symmetric-only, quantum-safe at rest). RSA_*/ECC_* are handled defensively as
// classical. There is no ML-KEM KMS key spec (the only PQC KMS key type is ML-DSA
// for signing, which a service-side encryption key never uses), so no PQC branch.
//
// A genuinely-unrecognized / future KeySpec must NOT default to symmetric-only:
// doing so would FALSE-SAFE a new asymmetric (quantum-vulnerable) spec as
// quantum-safe. Only specs we positively recognize as symmetric (SYMMETRIC_* /
// HMAC_*) are classified PostureSymmetricOnly; anything else is the conservative
// PostureUnknown. This mirrors keymgmt/kms_spec.go's kmsSpecPosture default.
func postureForKeySpec(keySpec string) models.CryptoPosture {
	a := strings.ToUpper(strings.ReplaceAll(keySpec, "-", "_"))
	switch {
	case strings.HasPrefix(a, "RSA_"), strings.HasPrefix(a, "ECC_"), strings.HasPrefix(a, "SM2"):
		return models.PostureNonPQCClassical
	case strings.HasPrefix(a, "SYMMETRIC"), strings.HasPrefix(a, "HMAC"):
		// Positively recognized symmetric envelope, quantum-safe at rest.
		return models.PostureSymmetricOnly
	default:
		// Unrecognized / future KeySpec: conservative Unknown, never a blind
		// symmetric-only false-safe.
		return models.PostureUnknown
	}
}
