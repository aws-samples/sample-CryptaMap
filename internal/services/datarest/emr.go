package datarest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/emr"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// EMRScanner inspects Amazon EMR security configurations for at-rest / in-transit
// encryption.
//
// IMPORTANT (opt-in): EMR encryption is configured via a reusable
// SecurityConfiguration (a separate resource a cluster references by name); it is
// OFF by default. A security configuration with EnableAtRestEncryption=false (or
// no EncryptionConfiguration) is a GENUINE no-encryption finding — never a false
// all-clear. When enabled, EMR at-rest is symmetric AES-256 (SSE-S3/SSE-KMS/
// CSE-KMS for S3, KMS/custom for local disk) and in-transit is classical-cert TLS;
// there is no PQC option anywhere in EMR, so the best posture is SymmetricOnly.
//
// SCOPE: this covers EMR on EC2. EMR Serverless and EMR on EKS are distinct
// services/SDKs and are not scanned here. The DescribeSecurityConfiguration body
// is a raw JSON *string in aws-sdk-go-v2 (not a typed struct), so it is parsed
// below.
type EMRScanner struct{}

// Name returns the canonical service identifier.
func (EMRScanner) Name() string { return "emr" }

// Category returns the primary CryptaMap category.
func (EMRScanner) Category() models.Category { return models.CategoryDataAtRest }

// emrEncryptionConfig is the subset of the EMR SecurityConfiguration JSON body we
// classify on. The body is a free-form JSON string returned by
// DescribeSecurityConfiguration; only these fields drive posture.
type emrEncryptionConfig struct {
	EncryptionConfiguration *struct {
		EnableAtRestEncryption    *bool `json:"EnableAtRestEncryption"`
		EnableInTransitEncryption *bool `json:"EnableInTransitEncryption"`
	} `json:"EncryptionConfiguration"`
}

// emrAPI is the minimal slice of the emr client this scanner uses. Both calls
// matter: ListSecurityConfigurations is Marker-paginated (a single call returns
// only the first page, silently dropping configs in dense accounts) and
// DescribeSecurityConfiguration is the per-config read whose failure must NOT
// silently drop the asset. Defining it as an interface keeps the pagination +
// error-handling + posture logic unit-testable with a fake (the concrete
// *emr.Client satisfies it).
type emrAPI interface {
	ListSecurityConfigurations(ctx context.Context, in *emr.ListSecurityConfigurationsInput, optFns ...func(*emr.Options)) (*emr.ListSecurityConfigurationsOutput, error)
	DescribeSecurityConfiguration(ctx context.Context, in *emr.DescribeSecurityConfigurationInput, optFns ...func(*emr.Options)) (*emr.DescribeSecurityConfigurationOutput, error)
}

// Scan lists EMR security configurations and classifies each by its parsed
// encryption JSON. (Cluster->config linkage is intentionally not enumerated here;
// the security configuration is the encryption chokepoint.)
func (s EMRScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := emr.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListSecurityConfigurations and
// classifies each by its DescribeSecurityConfiguration JSON. A top-level List
// error is propagated (a denied/throttled scan stays VISIBLY incomplete, never a
// clean empty success); a per-config Describe error never drops the asset — it is
// emitted as PostureUnknown with a note.
func (s EMRScanner) scan(ctx context.Context, client emrAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var marker *string
	for {
		out, err := client.ListSecurityConfigurations(ctx, &emr.ListSecurityConfigurationsInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("emr ListSecurityConfigurations: %w", err)
		}
		cfgs := out.SecurityConfigurations
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(cfgs) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			cfgs = cfgs[:remaining]
		}
		for _, sc := range cfgs {
			if sc.Name == nil {
				continue
			}
			name := *sc.Name
			posture := models.PostureUnknown
			props := services.UnknownAtRest()
			atRest, inTransit := "", ""
			parseNote := ""
			desc, derr := client.DescribeSecurityConfiguration(ctx, &emr.DescribeSecurityConfigurationInput{Name: &name})
			if derr != nil {
				fmt.Fprintf(os.Stderr, "emr:%s DescribeSecurityConfiguration: %v\n", name, derr)
				// Never drop the asset on a per-resource read error: emit it as
				// PostureUnknown with a note so it is neither a false all-clear (by
				// omission) nor a false no-encryption alarm.
				parseNote = "EMR security configuration could not be described; posture is unknown."
			} else if desc.SecurityConfiguration != nil {
				var parsed emrEncryptionConfig
				if jerr := json.Unmarshal([]byte(*desc.SecurityConfiguration), &parsed); jerr != nil {
					fmt.Fprintf(os.Stderr, "emr:%s parse SecurityConfiguration JSON: %v\n", name, jerr)
					// Keep PostureUnknown but record that the JSON could not be parsed,
					// so a parser regression is distinguishable from a true unknown.
					parseNote = "EMR SecurityConfiguration JSON could not be parsed; posture is unknown."
				} else if ec := parsed.EncryptionConfiguration; ec == nil {
					// Config exists but defines no encryption block -> nothing encrypted.
					posture = models.PostureNoEncryption
					props = services.NoEncryption()
				} else {
					ar := ec.EnableAtRestEncryption != nil && *ec.EnableAtRestEncryption
					it := ec.EnableInTransitEncryption != nil && *ec.EnableInTransitEncryption
					atRest = fmt.Sprintf("%t", ar)
					inTransit = fmt.Sprintf("%t", it)
					if ar || it {
						// AES-256 symmetric at rest (and/or classical TLS in transit);
						// no PQC option exists in EMR.
						posture = models.PostureSymmetricOnly
						props = services.AESAtRest()
					} else {
						posture = models.PostureNoEncryption
						props = services.NoEncryption()
					}
				}
			}

			a := services.NewAsset("emr", models.CategoryDataAtRest, accountID, region, name, "AWS::EMR::SecurityConfiguration", props)
			services.PostureProperty(&a, posture)
			if atRest != "" {
				a.Properties["enableAtRestEncryption"] = atRest
			}
			if inTransit != "" {
				a.Properties["enableInTransitEncryption"] = inTransit
			}
			if posture == models.PostureNoEncryption {
				a.Properties["note"] = "EMR security configuration has at-rest and in-transit encryption disabled; clusters using it are unencrypted."
			}
			if parseNote != "" {
				a.Properties["note"] = parseNote
			}
			assets = append(assets, a)
		}
		if out.Marker == nil || *out.Marker == "" {
			break
		}
		marker = out.Marker
	}
	return assets, nil
}
