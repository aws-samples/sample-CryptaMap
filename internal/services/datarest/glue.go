package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// GlueScanner inspects the Glue Data Catalog for encryption-at-rest settings.
// Glue exposes one catalog per account/region, so this scanner emits at most
// one asset.
type GlueScanner struct{}

// Name returns the canonical service identifier.
func (GlueScanner) Name() string { return "glue" }

// Category returns the primary CryptaMap category.
func (GlueScanner) Category() models.Category { return models.CategoryDataAtRest }

// glueCatalogAPI is the minimal slice of the glue client this scanner uses.
// Defining it as an interface keeps the error-propagation + posture-mapping
// logic unit-testable with a fake (the concrete *glue.Client satisfies it).
// GetDataCatalogEncryptionSettings returns a single non-paginated response, so
// there is no NextToken loop to guard here.
type glueCatalogAPI interface {
	GetDataCatalogEncryptionSettings(ctx context.Context, in *glue.GetDataCatalogEncryptionSettingsInput, optFns ...func(*glue.Options)) (*glue.GetDataCatalogEncryptionSettingsOutput, error)
}

// Scan reads GetDataCatalogEncryptionSettings.
func (s GlueScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := glue.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it reads the catalog encryption settings and
// classifies them into a single CryptoAsset. A GetDataCatalogEncryptionSettings
// error is NOT swallowed — it is returned so the engine records this scanner as
// errored (visible in coverage), keeping a denied/throttled scan VISIBLY
// incomplete rather than a clean-looking empty success.
func (s GlueScanner) scan(ctx context.Context, client glueCatalogAPI, accountID, region string) ([]models.CryptoAsset, error) {
	out, err := client.GetDataCatalogEncryptionSettings(ctx, &glue.GetDataCatalogEncryptionSettingsInput{})
	if err != nil {
		return nil, fmt.Errorf("glue GetDataCatalogEncryptionSettings: %w", err)
	}
	// Drive posture off the authoritative CatalogEncryptionMode, not the mere
	// presence of an SSE key id. Under SSE-KMS-WITH-SERVICE-ROLE the catalog IS
	// encrypted but SseAwsKmsKeyId can legitimately be absent, so keying off the
	// key id alone produces a false PostureNoEncryption.
	posture := models.PostureNoEncryption
	props := services.NoEncryption()
	var kmsKey, catalogMode, serviceRole string
	var ear *gluetypes.EncryptionAtRest
	if out.DataCatalogEncryptionSettings != nil {
		ear = out.DataCatalogEncryptionSettings.EncryptionAtRest
	}
	if ear != nil {
		catalogMode = string(ear.CatalogEncryptionMode)
		switch ear.CatalogEncryptionMode {
		case gluetypes.CatalogEncryptionModeSsekms, gluetypes.CatalogEncryptionModeSsekmswithservicerole:
			posture = models.PostureSymmetricOnly
			props = services.AESAtRest()
		}
		if ear.SseAwsKmsKeyId != nil && *ear.SseAwsKmsKeyId != "" {
			kmsKey = *ear.SseAwsKmsKeyId
		}
		if ear.CatalogEncryptionServiceRole != nil {
			serviceRole = *ear.CatalogEncryptionServiceRole
		}
	}
	a := services.NewAsset("glue", models.CategoryDataAtRest, accountID, region, "data-catalog", "AWS::Glue::DataCatalog", props)
	services.PostureProperty(&a, posture)
	if kmsKey != "" {
		a.Properties["kmsKeyId"] = kmsKey
	}
	if catalogMode != "" {
		a.Properties["catalogEncryptionMode"] = catalogMode
	}
	if serviceRole != "" {
		a.Properties["catalogEncryptionServiceRole"] = serviceRole
	}
	// Surface the connection-password posture from the same response so the
	// stored-connection-credential encryption is represented for evidence.
	if out.DataCatalogEncryptionSettings != nil {
		if cpe := out.DataCatalogEncryptionSettings.ConnectionPasswordEncryption; cpe != nil {
			a.Properties["connectionPasswordEncrypted"] = fmt.Sprintf("%t", cpe.ReturnConnectionPasswordEncrypted)
			if cpe.AwsKmsKeyId != nil && *cpe.AwsKmsKeyId != "" {
				a.Properties["connectionPasswordKmsKeyId"] = *cpe.AwsKmsKeyId
			}
		}
	}
	return []models.CryptoAsset{a}, nil
}
