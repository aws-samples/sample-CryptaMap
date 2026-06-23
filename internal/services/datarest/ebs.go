package datarest

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// The AES-256-XTS at-rest cipher fact (KMS Cryptographic Details guide states it
// as a UNIVERSAL guarantee) is the doc-fact "datarest/ebs/at-rest-aes256-xts"
// (internal/pqc knowledge); stamped as an aws-doc fact, not a per-resource read.

// EBSScanner inspects EBS volumes for at-rest encryption.
type EBSScanner struct{}

// Name returns the canonical service identifier.
func (EBSScanner) Name() string { return "ebs" }

// Category returns the primary CryptaMap category.
func (EBSScanner) Category() models.Category { return models.CategoryDataAtRest }

// ebsAPI is the minimal slice of the ec2 + kms clients this scanner uses.
// DescribeVolumes is NextToken-paginated, so the scanner must loop; a single
// call returns only the first page, silently dropping volumes in dense
// accounts. Defining it as an interface keeps the pagination + error
// propagation logic unit-testable with a fake (the concrete *ec2.Client and
// *kms.Client satisfy it).
type ebsAPI interface {
	DescribeVolumes(ctx context.Context, in *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

// Scan paginates DescribeVolumes and emits one asset per volume.
func (s EBSScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := &ebsClient{ec2: ec2.NewFromConfig(cfg), kms: kms.NewFromConfig(cfg)}
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// ebsClient adapts the two concrete AWS SDK clients to the ebsAPI interface so
// Scan can build them from cfg while scan stays driven by the interface.
type ebsClient struct {
	ec2 *ec2.Client
	kms *kms.Client
}

func (c *ebsClient) DescribeVolumes(ctx context.Context, in *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	return c.ec2.DescribeVolumes(ctx, in, optFns...)
}

func (c *ebsClient) DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return c.kms.DescribeKey(ctx, in, optFns...)
}

// scan holds the testable core: it paginates DescribeVolumes and classifies
// each volume's at-rest posture. A DescribeVolumes error is NOT swallowed — it
// is returned so the engine records this scanner as errored, keeping a
// denied/throttled scan VISIBLY incomplete rather than a clean-looking empty
// success. A per-key DescribeKey failure degrades to plain AES-256-XTS (still
// SymmetricOnly, since the XTS cipher is an aws-doc universal guarantee) and
// only loses the key-spec detail — the encryption posture is never lost.
func (s EBSScanner) scan(ctx context.Context, client ebsAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("ebs DescribeVolumes: %w", err)
		}
		for _, v := range out.Volumes {
			if v.VolumeId == nil {
				continue
			}
			id := *v.VolumeId
			encrypted := v.Encrypted != nil && *v.Encrypted
			posture := models.PostureNoEncryption
			// EBS at-rest is AES-256-XTS (two 256-bit keys / 512-bit total) per
			// the KMS Cryptographic Details guide — NOT the GCM block other
			// at-rest services use. Resolve the KMS key spec where readable so the
			// XTS props carry it, then degrade to plain XTS on any DescribeKey
			// failure (ReadOnlyAccess permits kms:DescribeKey).
			props := services.NoEncryption()
			keySpec := ""
			if encrypted {
				posture = models.PostureSymmetricOnly
				if v.KmsKeyId != nil && *v.KmsKeyId != "" {
					if d, derr := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: v.KmsKeyId}); derr != nil {
						fmt.Fprintf(os.Stderr, "ebs:%s DescribeKey %s: %v\n", id, *v.KmsKeyId, derr)
					} else if d.KeyMetadata != nil {
						keySpec = string(d.KeyMetadata.KeySpec)
					}
				}
				props = services.AESXTSAtRest()
				if keySpec != "" {
					props.AlgorithmProperties.KMSKeySpec = keySpec
				}
			}
			a := services.NewAsset("ebs", models.CategoryDataAtRest, accountID, region, id, "AWS::EC2::Volume", props)
			services.PostureProperty(&a, posture)
			if encrypted {
				// The XTS cipher is an aws-doc universal guarantee; the key
				// identity (and spec) below are live per-resource observations.
				services.StampDocFactKeyed(&a, "datarest/ebs/at-rest-aes256-xts")
				if v.KmsKeyId != nil {
					a.Properties["kmsKeyId"] = *v.KmsKeyId
				}
				if keySpec != "" {
					a.Properties["kmsKeySpec"] = keySpec
				}
				// SseType is "Reserved for future use" per the SDK, so stamp it
				// defensively (evidence only) and never rely on it for posture.
				if v.SseType != "" {
					a.Properties["sseType"] = string(v.SseType)
				}
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
