package datarest

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/workspaces"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// WorkSpacesScanner inspects WorkSpaces root-volume encryption settings.
type WorkSpacesScanner struct{}

// Name returns the canonical service identifier.
func (WorkSpacesScanner) Name() string { return "workspaces" }

// Category returns the primary CryptaMap category.
func (WorkSpacesScanner) Category() models.Category { return models.CategoryDataAtRest }

// workspacesAPI is the minimal slice of the workspaces client this scanner uses.
// DescribeWorkspaces is NextToken-paginated, so the scanner must loop; a single
// call returns only the first page, silently dropping WorkSpaces in dense
// accounts. Defining it as an interface keeps the pagination + error propagation
// logic unit-testable with a fake (the concrete *workspaces.Client satisfies it).
type workspacesAPI interface {
	DescribeWorkspaces(ctx context.Context, in *workspaces.DescribeWorkspacesInput, optFns ...func(*workspaces.Options)) (*workspaces.DescribeWorkspacesOutput, error)
}

// Scan paginates DescribeWorkspaces.
func (s WorkSpacesScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := workspaces.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates DescribeWorkspaces and classifies
// each WorkSpace into a CryptoAsset. A DescribeWorkspaces error is NOT swallowed —
// it is returned so the engine records this scanner as errored, keeping a
// denied/throttled scan VISIBLY incomplete rather than a clean-looking empty
// success.
func (s WorkSpacesScanner) scan(ctx context.Context, client workspacesAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.DescribeWorkspaces(ctx, &workspaces.DescribeWorkspacesInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("workspaces DescribeWorkspaces: %w", err)
		}
		for _, w := range out.Workspaces {
			if w.WorkspaceId == nil {
				continue
			}
			id := *w.WorkspaceId
			// A WorkSpace is encrypted if EITHER its root or user volume is
			// encrypted; keying only off the root volume falsely reports a
			// user-volume-encrypted WorkSpace as NoEncryption.
			rootEnc := w.RootVolumeEncryptionEnabled != nil && *w.RootVolumeEncryptionEnabled
			userEnc := w.UserVolumeEncryptionEnabled != nil && *w.UserVolumeEncryptionEnabled
			encrypted := rootEnc || userEnc
			posture := models.PostureNoEncryption
			props := services.NoEncryption()
			if encrypted {
				posture = models.PostureSymmetricOnly
				props = services.AESAtRest()
			}
			a := services.NewAsset("workspaces", models.CategoryDataAtRest, accountID, region, id, "AWS::WorkSpaces::Workspace", props)
			services.PostureProperty(&a, posture)
			if encrypted {
				// VolumeEncryptionKey is always a symmetric KMS key (no asymmetric
				// support), so AESAtRest()/symmetric posture is correct. Capture
				// the per-resource key ARN and which volumes are encrypted — all
				// from the existing DescribeWorkspaces response, no extra call.
				if w.VolumeEncryptionKey != nil && *w.VolumeEncryptionKey != "" {
					a.Properties["kmsKeyId"] = *w.VolumeEncryptionKey
				}
				a.Properties["rootVolumeEncrypted"] = fmt.Sprintf("%t", rootEnc)
				a.Properties["userVolumeEncrypted"] = fmt.Sprintf("%t", userEnc)
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
