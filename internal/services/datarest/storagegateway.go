package datarest

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/storagegateway"
	sgtypes "github.com/aws/aws-sdk-go-v2/service/storagegateway/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// StorageGatewayScanner inspects AWS Storage Gateway file shares for at-rest
// encryption. (File shares are the clean enumerable crypto surface; cached/stored
// iSCSI volumes are not covered here.)
//
// Storage Gateway file-share data is server-side encrypted in S3 with AES-256 in
// all modes — SSE-S3 (AWS-managed, the default), SSE-KMS, or DSSE-KMS (opt-in
// customer key). All are symmetric and quantum-safe at rest, so posture is
// SymmetricOnly; the EncryptionType only distinguishes the key tier.
type StorageGatewayScanner struct{}

// Name returns the canonical service identifier.
func (StorageGatewayScanner) Name() string { return "storagegateway" }

// Category returns the primary CryptaMap category.
func (StorageGatewayScanner) Category() models.Category { return models.CategoryDataAtRest }

// storageGatewayAPI is the minimal slice of the storagegateway client this
// scanner uses. ListGateways and ListFileShares are Marker-paginated, so the
// scanner must loop; a single call returns only the first page, silently
// dropping gateways/shares in dense accounts. Defining it as an interface keeps
// the pagination + error propagation logic unit-testable with a fake (the
// concrete *storagegateway.Client satisfies it).
type storageGatewayAPI interface {
	ListGateways(ctx context.Context, in *storagegateway.ListGatewaysInput, optFns ...func(*storagegateway.Options)) (*storagegateway.ListGatewaysOutput, error)
	ListFileShares(ctx context.Context, in *storagegateway.ListFileSharesInput, optFns ...func(*storagegateway.Options)) (*storagegateway.ListFileSharesOutput, error)
	DescribeNFSFileShares(ctx context.Context, in *storagegateway.DescribeNFSFileSharesInput, optFns ...func(*storagegateway.Options)) (*storagegateway.DescribeNFSFileSharesOutput, error)
	DescribeSMBFileShares(ctx context.Context, in *storagegateway.DescribeSMBFileSharesInput, optFns ...func(*storagegateway.Options)) (*storagegateway.DescribeSMBFileSharesOutput, error)
}

// Scan enumerates gateways -> file shares -> describes NFS/SMB shares for their
// encryption type.
func (s StorageGatewayScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := storagegateway.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListGateways/ListFileShares and
// describes each share. A ListGateways error is NOT swallowed — it is returned
// so the engine records this scanner as errored, keeping a denied/throttled scan
// VISIBLY incomplete rather than a clean-looking empty success.
func (s StorageGatewayScanner) scan(ctx context.Context, client storageGatewayAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}

	// 1. Enumerate gateways.
	var gwMarker *string
	for {
		gws, err := client.ListGateways(ctx, &storagegateway.ListGatewaysInput{Marker: gwMarker})
		if err != nil {
			return nil, fmt.Errorf("storagegateway ListGateways: %w", err)
		}
		for _, gw := range gws.Gateways {
			if gw.GatewayARN == nil {
				continue
			}
			// 2. List this gateway's file shares.
			var nfsARNs, smbARNs []string
			var fsMarker *string
			for {
				fsOut, ferr := client.ListFileShares(ctx, &storagegateway.ListFileSharesInput{GatewayARN: gw.GatewayARN, Marker: fsMarker})
				if ferr != nil {
					fmt.Fprintf(os.Stderr, "storagegateway ListFileShares %s: %v\n", *gw.GatewayARN, ferr)
					break
				}
				for _, fsi := range fsOut.FileShareInfoList {
					if fsi.FileShareARN == nil {
						continue
					}
					switch fsi.FileShareType {
					case sgtypes.FileShareTypeNfs:
						nfsARNs = append(nfsARNs, *fsi.FileShareARN)
					case sgtypes.FileShareTypeSmb:
						smbARNs = append(smbARNs, *fsi.FileShareARN)
					}
				}
				if fsOut.NextMarker == nil || *fsOut.NextMarker == "" {
					break
				}
				fsMarker = fsOut.NextMarker
			}

			// 3. Describe each share and emit one asset per share. A Describe error
			// does not drop the share — it yields a PostureUnknown asset (see
			// describeNFS/describeSMB), so a read failure never reads as a clean
			// all-clear by omission.
			for _, arn := range nfsARNs {
				assets = append(assets, s.describeNFS(ctx, client, accountID, region, arn))
			}
			for _, arn := range smbARNs {
				assets = append(assets, s.describeSMB(ctx, client, accountID, region, arn))
			}
			if services.TruncationCapReached(len(assets), s.Name(), region) {
				return assets, nil
			}
		}
		if gws.Marker == nil || *gws.Marker == "" {
			break
		}
		gwMarker = gws.Marker
	}
	return assets, nil
}

// sgShareAsset builds a file-share asset from its EncryptionType + KMS key. All
// share encryption modes are symmetric AES-256, so posture is always SymmetricOnly.
func sgShareAsset(accountID, region, arn, shareType string, encType sgtypes.EncryptionType, kmsKey *string) models.CryptoAsset {
	a := services.NewAsset("storagegateway", models.CategoryDataAtRest, accountID, region, arn, "AWS::StorageGateway::"+shareType+"FileShare", services.AESAtRest())
	services.PostureProperty(&a, models.PostureSymmetricOnly)
	tier := string(encType)
	if tier == "" {
		// API returned no EncryptionType. SSE-S3 is the documented default but we
		// did not observe it, so do not synthesize observed-looking evidence:
		// record the tier as unspecified and explain (HONESTY CONTRACT).
		tier = "unspecified"
		a.Properties["note"] = "Storage Gateway did not return an EncryptionType for this file share; SSE-S3 (AES-256) is the documented default but was not confirmed here. Always encrypted at rest, but the key tier could not be observed."
	}
	a.Properties["encryptionType"] = tier
	if kmsKey != nil && *kmsKey != "" {
		a.Properties["kmsKeyId"] = *kmsKey
	} else {
		a.Properties["kmsKeyId"] = "AWS_OWNED_KMS_KEY"
	}
	return a
}

// sgUnknownShareAsset records a file share whose encryption details could not be
// read. A Describe error (or an empty/short Describe response) must NOT silently
// drop the share — that would read as a clean all-clear by omission. Storage
// Gateway file shares are always AES-256 at rest, but the key tier is
// unobservable here, so emit a PostureUnknown asset with a note rather than
// asserting SymmetricOnly (or fabricating a NoEncryption false alarm) on unread
// evidence. (HONESTY CONTRACT)
func sgUnknownShareAsset(accountID, region, arn, shareType, reason string) models.CryptoAsset {
	a := services.NewAsset("storagegateway", models.CategoryDataAtRest, accountID, region, arn, "AWS::StorageGateway::"+shareType+"FileShare", services.UnknownAtRest())
	services.PostureProperty(&a, models.PostureUnknown)
	a.Properties["note"] = reason
	return a
}

func (s StorageGatewayScanner) describeNFS(ctx context.Context, client storageGatewayAPI, accountID, region, arn string) models.CryptoAsset {
	out, err := client.DescribeNFSFileShares(ctx, &storagegateway.DescribeNFSFileSharesInput{FileShareARNList: []string{arn}})
	if err != nil || out == nil || len(out.NFSFileShareInfoList) == 0 {
		if err != nil {
			fmt.Fprintf(os.Stderr, "storagegateway DescribeNFSFileShares %s: %v\n", arn, err)
		}
		return sgUnknownShareAsset(accountID, region, arn, "NFS", "Could not read NFS file-share encryption details; always AES-256 at rest, but the key tier could not be observed.")
	}
	info := out.NFSFileShareInfoList[0]
	return sgShareAsset(accountID, region, arn, "NFS", info.EncryptionType, info.KMSKey)
}

func (s StorageGatewayScanner) describeSMB(ctx context.Context, client storageGatewayAPI, accountID, region, arn string) models.CryptoAsset {
	out, err := client.DescribeSMBFileShares(ctx, &storagegateway.DescribeSMBFileSharesInput{FileShareARNList: []string{arn}})
	if err != nil || out == nil || len(out.SMBFileShareInfoList) == 0 {
		if err != nil {
			fmt.Fprintf(os.Stderr, "storagegateway DescribeSMBFileShares %s: %v\n", arn, err)
		}
		return sgUnknownShareAsset(accountID, region, arn, "SMB", "Could not read SMB file-share encryption details; always AES-256 at rest, but the key tier could not be observed.")
	}
	info := out.SMBFileShareInfoList[0]
	return sgShareAsset(accountID, region, arn, "SMB", info.EncryptionType, info.KMSKey)
}
