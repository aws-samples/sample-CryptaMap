package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lightsail"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// LightsailScanner emits one informational asset per Lightsail instance.
//
// IMPORTANT: the Lightsail block-storage doc guarantees at-rest encryption for
// ATTACHED DISKS and disk SNAPSHOTS only — it explicitly treats the instance
// SYSTEM (root) disk as a separate thing and does NOT state that it is encrypted
// at rest. Lightsail exposes no per-instance encryption field via the API either.
// So we CANNOT honestly assert that an instance's primary storage is encrypted;
// claiming SymmetricOnly here was a FALSE-SAFE. We emit the instance asset with
// PostureUnknown (the system-disk at-rest state is genuinely undetermined) so the
// resource is accounted for without a fabricated all-clear. Attached Lightsail
// disks, where the encryption guarantee actually holds, would be a separate asset.
type LightsailScanner struct{}

// Name returns the canonical service identifier.
func (LightsailScanner) Name() string { return "lightsail" }

// Category returns the primary CryptaMap category.
func (LightsailScanner) Category() models.Category { return models.CategoryDataAtRest }

// lightsailInstancesAPI is the minimal slice of the lightsail client this
// scanner uses. GetInstances is PageToken-paginated, so the scanner must loop; a
// single call returns only the first page, silently dropping instances in dense
// accounts. Defining it as an interface keeps the pagination + error propagation
// logic unit-testable with a fake (the concrete *lightsail.Client satisfies it).
type lightsailInstancesAPI interface {
	GetInstances(ctx context.Context, in *lightsail.GetInstancesInput, optFns ...func(*lightsail.Options)) (*lightsail.GetInstancesOutput, error)
}

// Scan paginates GetInstances.
func (s LightsailScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := lightsail.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates GetInstances via PageToken and emits
// one PostureUnknown asset per instance. A GetInstances error is NOT swallowed —
// it is returned so the engine records this scanner as errored, keeping a
// denied/throttled scan VISIBLY incomplete rather than a clean-looking empty success.
func (s LightsailScanner) scan(ctx context.Context, client lightsailInstancesAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var pageToken *string
	for {
		out, err := client.GetInstances(ctx, &lightsail.GetInstancesInput{PageToken: pageToken})
		if err != nil {
			return nil, fmt.Errorf("lightsail GetInstances: %w", err)
		}
		for _, inst := range out.Instances {
			if inst.Name == nil {
				continue
			}
			name := *inst.Name
			// No doc guarantee and no API field covers the instance SYSTEM disk's
			// at-rest encryption, so the posture is honestly Unknown — not a stamped
			// SymmetricOnly all-clear. Use a bare (no-AES-claim) at-rest block.
			a := services.NewAsset("lightsail", models.CategoryDataAtRest, accountID, region, name, "AWS::Lightsail::Instance", services.UnknownAtRest())
			services.PostureProperty(&a, models.PostureUnknown)
			a.Properties["atRestEncryption"] = "undetermined"
			a.Properties["note"] = "Lightsail docs guarantee at-rest encryption for attached disks/snapshots only; the instance system disk is not covered and no API field exposes its state."
			assets = append(assets, a)
		}
		if out.NextPageToken == nil || *out.NextPageToken == "" {
			break
		}
		pageToken = out.NextPageToken
	}
	return assets, nil
}
