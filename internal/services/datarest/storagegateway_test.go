package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/storagegateway"
	sgtypes "github.com/aws/aws-sdk-go-v2/service/storagegateway/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeStorageGatewayClient is a hand-rolled storageGatewayAPI for unit-testing
// the scanner's pagination + error propagation + honesty posture without a live
// AWS client. gatewaysPages and fileSharesPages are returned page-by-page (each
// call consumes the next page) with the Marker wired so the scanner loops
// through every page; the *Err fields force the corresponding call to fail; the
// describe maps key by FileShareARN so per-share Describe outcomes can be driven
// individually (a missing/empty entry exercises the read-failure path).
type fakeStorageGatewayClient struct {
	gatewaysPages []*storagegateway.ListGatewaysOutput
	gatewaysCalls int
	gatewaysErr   error

	fileSharesPages []*storagegateway.ListFileSharesOutput
	fileSharesCalls int
	fileSharesErr   error

	nfsByARN map[string]sgtypes.NFSFileShareInfo
	nfsErr   error

	smbByARN map[string]sgtypes.SMBFileShareInfo
	smbErr   error
}

func (f *fakeStorageGatewayClient) ListGateways(ctx context.Context, in *storagegateway.ListGatewaysInput, optFns ...func(*storagegateway.Options)) (*storagegateway.ListGatewaysOutput, error) {
	if f.gatewaysErr != nil {
		return nil, f.gatewaysErr
	}
	if f.gatewaysCalls >= len(f.gatewaysPages) {
		return &storagegateway.ListGatewaysOutput{}, nil
	}
	out := f.gatewaysPages[f.gatewaysCalls]
	f.gatewaysCalls++
	return out, nil
}

func (f *fakeStorageGatewayClient) ListFileShares(ctx context.Context, in *storagegateway.ListFileSharesInput, optFns ...func(*storagegateway.Options)) (*storagegateway.ListFileSharesOutput, error) {
	if f.fileSharesErr != nil {
		return nil, f.fileSharesErr
	}
	if f.fileSharesCalls >= len(f.fileSharesPages) {
		return &storagegateway.ListFileSharesOutput{}, nil
	}
	out := f.fileSharesPages[f.fileSharesCalls]
	f.fileSharesCalls++
	return out, nil
}

func (f *fakeStorageGatewayClient) DescribeNFSFileShares(ctx context.Context, in *storagegateway.DescribeNFSFileSharesInput, optFns ...func(*storagegateway.Options)) (*storagegateway.DescribeNFSFileSharesOutput, error) {
	if f.nfsErr != nil {
		return nil, f.nfsErr
	}
	out := &storagegateway.DescribeNFSFileSharesOutput{}
	for _, arn := range in.FileShareARNList {
		if info, ok := f.nfsByARN[arn]; ok {
			out.NFSFileShareInfoList = append(out.NFSFileShareInfoList, info)
		}
	}
	return out, nil
}

func (f *fakeStorageGatewayClient) DescribeSMBFileShares(ctx context.Context, in *storagegateway.DescribeSMBFileSharesInput, optFns ...func(*storagegateway.Options)) (*storagegateway.DescribeSMBFileSharesOutput, error) {
	if f.smbErr != nil {
		return nil, f.smbErr
	}
	out := &storagegateway.DescribeSMBFileSharesOutput{}
	for _, arn := range in.FileShareARNList {
		if info, ok := f.smbByARN[arn]; ok {
			out.SMBFileShareInfoList = append(out.SMBFileShareInfoList, info)
		}
	}
	return out, nil
}

func sgPtr(s string) *string { return &s }

func sgAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// TestStorageGatewayScanPaginates verifies BOTH the ListGateways marker loop and
// the per-gateway ListFileShares marker loop: a fake returning 2 gateway pages
// (Marker on page 1) and, for the single gateway, 2 file-share pages (NextMarker
// on page 1) must yield shares from BOTH file-share pages AND the gateway from
// page 2. Without the pagination restore, only the first page survives.
func TestStorageGatewayScanPaginates(t *testing.T) {
	client := &fakeStorageGatewayClient{
		gatewaysPages: []*storagegateway.ListGatewaysOutput{
			{
				Gateways: []sgtypes.GatewayInfo{{GatewayARN: sgPtr("arn:gw:1")}},
				Marker:   sgPtr("gw-page2"),
			},
			{
				Gateways: []sgtypes.GatewayInfo{{GatewayARN: sgPtr("arn:gw:2")}},
				// no Marker -> last page
			},
		},
		// Both gateways share this paginated file-share listing (the fake is not
		// per-gateway), which is sufficient to prove the inner marker loop runs.
		fileSharesPages: []*storagegateway.ListFileSharesOutput{
			{
				FileShareInfoList: []sgtypes.FileShareInfo{
					{FileShareARN: sgPtr("arn:nfs:page1"), FileShareType: sgtypes.FileShareTypeNfs},
				},
				NextMarker: sgPtr("fs-page2"),
			},
			{
				FileShareInfoList: []sgtypes.FileShareInfo{
					{FileShareARN: sgPtr("arn:smb:page2"), FileShareType: sgtypes.FileShareTypeSmb},
				},
			},
		},
		nfsByARN: map[string]sgtypes.NFSFileShareInfo{
			"arn:nfs:page1": {FileShareARN: sgPtr("arn:nfs:page1"), EncryptionType: sgtypes.EncryptionTypeSseS3},
		},
		smbByARN: map[string]sgtypes.SMBFileShareInfo{
			"arn:smb:page2": {FileShareARN: sgPtr("arn:smb:page2"), EncryptionType: sgtypes.EncryptionTypeSseKms, KMSKey: sgPtr("arn:aws:kms:us-east-1:111122223333:key/abc")},
		},
	}

	assets, err := StorageGatewayScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.gatewaysCalls != 2 {
		t.Errorf("expected ListGateways to be called 2 times (paginated), got %d", client.gatewaysCalls)
	}
	// Two gateways each consume the 2 file-share pages from the shared fake.
	if client.fileSharesCalls < 2 {
		t.Errorf("expected ListFileShares to paginate (>=2 calls), got %d", client.fileSharesCalls)
	}
	if _, ok := sgAssetByID(assets, "arn:nfs:page1"); !ok {
		t.Errorf("expected NFS share from file-share page 1 to appear as an asset; assets=%v", assets)
	}
	if _, ok := sgAssetByID(assets, "arn:smb:page2"); !ok {
		t.Errorf("expected SMB share from file-share page 2 to appear as an asset (inner pagination); assets=%v", assets)
	}
}

// TestStorageGatewayListGatewaysErrorPropagates verifies the incompleteness
// decision: a ListGateways failure (denied/rate-limited) must make the scan
// VISIBLY incomplete by returning a non-nil error wrapping the cause — NOT a
// silent empty success.
func TestStorageGatewayListGatewaysErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform storagegateway:ListGateways")
	client := &fakeStorageGatewayClient{gatewaysErr: sentinel}

	assets, err := StorageGatewayScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatalf("expected scan to return a non-nil error when ListGateways fails, got nil with %d assets (silent empty success)", len(assets))
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListGateways failure, got: %v", err)
	}
}

// TestStorageGatewayDescribeErrorNotSilentlyDropped verifies the HONESTY
// CONTRACT: a per-share Describe error (or empty Describe response) must NOT drop
// the share — it must emit a PostureUnknown asset with a note so a read failure
// never reads as a clean all-clear by omission. It must also NOT fabricate a
// NoEncryption false alarm (Storage Gateway shares are always AES-256 at rest).
func TestStorageGatewayDescribeErrorNotSilentlyDropped(t *testing.T) {
	client := &fakeStorageGatewayClient{
		gatewaysPages: []*storagegateway.ListGatewaysOutput{
			{Gateways: []sgtypes.GatewayInfo{{GatewayARN: sgPtr("arn:gw:1")}}},
		},
		fileSharesPages: []*storagegateway.ListFileSharesOutput{
			{FileShareInfoList: []sgtypes.FileShareInfo{
				{FileShareARN: sgPtr("arn:nfs:1"), FileShareType: sgtypes.FileShareTypeNfs},
			}},
		},
		// DescribeNFSFileShares fails for every share.
		nfsErr: errors.New("InternalServerError"),
	}

	assets, err := StorageGatewayScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := sgAssetByID(assets, "arn:nfs:1")
	if !ok {
		t.Fatalf("expected the share to STILL be recorded (not silently dropped) on Describe error; assets=%v", assets)
	}
	if a.Properties["posture"] != string(models.PostureUnknown) {
		t.Errorf("expected PostureUnknown on unreadable Describe, got %q", a.Properties["posture"])
	}
	if a.Properties["posture"] == string(models.PostureNoEncryption) {
		t.Error("must NOT fabricate a NoEncryption false alarm; Storage Gateway shares are always AES-256 at rest")
	}
	if a.Properties["note"] == "" {
		t.Error("expected an explanatory note on the PostureUnknown asset")
	}
}

// TestStorageGatewayHonestyPosture verifies the at-rest posture mapping for the
// scanner's domain: file shares are ALWAYS AES-256 at rest, so posture is
// SymmetricOnly and never NoEncryption. A customer CMK (SSE-KMS/DSSE-KMS) is
// recorded; absence of a CMK records the AWS-owned default key WITHOUT presenting
// it as a different/weaker posture.
func TestStorageGatewayHonestyPosture(t *testing.T) {
	client := &fakeStorageGatewayClient{
		gatewaysPages: []*storagegateway.ListGatewaysOutput{
			{Gateways: []sgtypes.GatewayInfo{{GatewayARN: sgPtr("arn:gw:1")}}},
		},
		fileSharesPages: []*storagegateway.ListFileSharesOutput{
			{FileShareInfoList: []sgtypes.FileShareInfo{
				{FileShareARN: sgPtr("arn:nfs:cmk"), FileShareType: sgtypes.FileShareTypeNfs},
				{FileShareARN: sgPtr("arn:smb:default"), FileShareType: sgtypes.FileShareTypeSmb},
			}},
		},
		nfsByARN: map[string]sgtypes.NFSFileShareInfo{
			// SSE-KMS with a customer CMK present.
			"arn:nfs:cmk": {FileShareARN: sgPtr("arn:nfs:cmk"), EncryptionType: sgtypes.EncryptionTypeSseKms, KMSKey: sgPtr("arn:aws:kms:us-east-1:111122223333:key/cmk-1")},
		},
		smbByARN: map[string]sgtypes.SMBFileShareInfo{
			// SSE-S3 default, no CMK.
			"arn:smb:default": {FileShareARN: sgPtr("arn:smb:default"), EncryptionType: sgtypes.EncryptionTypeSseS3},
		},
	}

	assets, err := StorageGatewayScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}

	cmk, ok := sgAssetByID(assets, "arn:nfs:cmk")
	if !ok {
		t.Fatalf("expected CMK-backed NFS share asset; assets=%v", assets)
	}
	if cmk.Properties["posture"] != string(models.PostureSymmetricOnly) {
		t.Errorf("CMK share: expected SymmetricOnly (always AES-256), got %q", cmk.Properties["posture"])
	}
	if cmk.Properties["posture"] == string(models.PostureNoEncryption) {
		t.Error("CMK share: must never be NoEncryption — Storage Gateway is always encrypted at rest")
	}
	if cmk.Properties["kmsKeyId"] != "arn:aws:kms:us-east-1:111122223333:key/cmk-1" {
		t.Errorf("CMK share: expected the customer CMK to be recorded, got kmsKeyId=%q", cmk.Properties["kmsKeyId"])
	}
	if cmk.Properties["encryptionType"] != "SseKms" {
		t.Errorf("CMK share: expected encryptionType=SseKms, got %q", cmk.Properties["encryptionType"])
	}

	def, ok := sgAssetByID(assets, "arn:smb:default")
	if !ok {
		t.Fatalf("expected default-key SMB share asset; assets=%v", assets)
	}
	if def.Properties["posture"] != string(models.PostureSymmetricOnly) {
		t.Errorf("default share: expected SymmetricOnly, got %q", def.Properties["posture"])
	}
	// Absence of a CMK records the AWS-owned default key, not a weaker posture.
	if def.Properties["kmsKeyId"] != "AWS_OWNED_KMS_KEY" {
		t.Errorf("default share: expected AWS_OWNED_KMS_KEY default recorded, got %q", def.Properties["kmsKeyId"])
	}
	if def.Properties["encryptionType"] != "SseS3" {
		t.Errorf("default share: expected encryptionType=SseS3, got %q", def.Properties["encryptionType"])
	}
}
