package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeEBSClient is a hand-rolled ebsAPI for unit-testing the scanner's
// pagination + error propagation without a live AWS client. volPages is
// returned page-by-page (each DescribeVolumes call consumes the next page) with
// the NextToken wired so the scanner loops through every page; volErr forces a
// DescribeVolumes failure. keyByID drives DescribeKey, and keyErr forces a
// per-key DescribeKey failure.
type fakeEBSClient struct {
	volPages []*ec2.DescribeVolumesOutput
	volCalls int
	volErr   error

	keyByID map[string]string // KeyId -> KeySpec
	keyErr  error
	keyHits int
}

func (f *fakeEBSClient) DescribeVolumes(ctx context.Context, in *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	if f.volErr != nil {
		return nil, f.volErr
	}
	if f.volCalls >= len(f.volPages) {
		return &ec2.DescribeVolumesOutput{}, nil
	}
	out := f.volPages[f.volCalls]
	f.volCalls++
	return out, nil
}

func (f *fakeEBSClient) DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	f.keyHits++
	if f.keyErr != nil {
		return nil, f.keyErr
	}
	spec := ""
	if in.KeyId != nil {
		spec = f.keyByID[*in.KeyId]
	}
	return &kms.DescribeKeyOutput{
		KeyMetadata: &kmstypes.KeyMetadata{KeySpec: kmstypes.KeySpec(spec)},
	}, nil
}

func strptr(s string) *string { return &s }
func boolptr(b bool) *bool    { return &b }

func ebsAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// TestEBSScanPaginatesVolumes verifies the DescribeVolumes NextToken loop: a
// fake returning 2 pages (NextToken on page 1) must yield BOTH pages' volumes
// as assets. Without the pagination loop, only the first page's volume survives
// — the commonest real-world drop in dense accounts.
func TestEBSScanPaginatesVolumes(t *testing.T) {
	client := &fakeEBSClient{
		volPages: []*ec2.DescribeVolumesOutput{
			{
				Volumes:   []ec2types.Volume{{VolumeId: strptr("vol-page1"), Encrypted: boolptr(false)}},
				NextToken: strptr("tok-page2"),
			},
			{
				Volumes: []ec2types.Volume{{VolumeId: strptr("vol-page2"), Encrypted: boolptr(false)}},
				// no NextToken -> last page
			},
		},
	}
	assets, err := EBSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.volCalls != 2 {
		t.Errorf("expected DescribeVolumes to be called 2 times (paginated), got %d", client.volCalls)
	}
	for _, want := range []string{"vol-page1", "vol-page2"} {
		if _, ok := ebsAssetByID(assets, want); !ok {
			t.Errorf("expected volume %q from a paginated page to appear as an asset", want)
		}
	}
}

// TestEBSScanDescribeVolumesErrorPropagates verifies the incompleteness
// decision: a top-level DescribeVolumes failure (denied/rate-limited) must make
// the scan VISIBLY incomplete by returning a non-nil error — NOT a silent empty
// success that masquerades as "no volumes / all clear".
func TestEBSScanDescribeVolumesErrorPropagates(t *testing.T) {
	sentinel := errors.New("UnauthorizedOperation: not authorized to perform ec2:DescribeVolumes")
	client := &fakeEBSClient{volErr: sentinel}
	_, err := EBSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeVolumes fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeVolumes failure, got: %v", err)
	}
}

// TestEBSScanUnencryptedVolume verifies the honesty mapping for a genuinely
// unencrypted volume: posture is NoEncryption (EBS encryption is opt-in, so
// "off" is genuinely off and must be reported as such) and the doc-fact for the
// always-on XTS cipher is NOT stamped (there is no encryption to attest).
func TestEBSScanUnencryptedVolume(t *testing.T) {
	client := &fakeEBSClient{
		volPages: []*ec2.DescribeVolumesOutput{
			{Volumes: []ec2types.Volume{{VolumeId: strptr("vol-plain"), Encrypted: boolptr(false)}}},
		},
	}
	assets, err := EBSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := ebsAssetByID(assets, "vol-plain")
	if !ok {
		t.Fatal("expected an asset for vol-plain")
	}
	if got := a.Properties["posture"]; got != string(models.PostureNoEncryption) {
		t.Errorf("unencrypted volume: expected posture %q, got %q", models.PostureNoEncryption, got)
	}
	if _, present := a.Properties["kmsKeyId"]; present {
		t.Errorf("unencrypted volume should not record a kmsKeyId; got %v", a.Properties["kmsKeyId"])
	}
}

// TestEBSScanEncryptedWithCMK verifies the encrypted-with-CMK happy path: an
// encrypted volume with a readable KMS key is SymmetricOnly (AES-256-XTS is
// quantum-resistant — never NoEncryption), the CMK identity is recorded, and
// the live key spec is captured from DescribeKey.
func TestEBSScanEncryptedWithCMK(t *testing.T) {
	client := &fakeEBSClient{
		volPages: []*ec2.DescribeVolumesOutput{
			{Volumes: []ec2types.Volume{{
				VolumeId:  strptr("vol-enc"),
				Encrypted: boolptr(true),
				KmsKeyId:  strptr("arn:aws:kms:us-east-1:111122223333:key/abc"),
			}}},
		},
		keyByID: map[string]string{
			"arn:aws:kms:us-east-1:111122223333:key/abc": "SYMMETRIC_DEFAULT",
		},
	}
	assets, err := EBSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := ebsAssetByID(assets, "vol-enc")
	if !ok {
		t.Fatal("expected an asset for vol-enc")
	}
	if got := a.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
		t.Errorf("encrypted volume: expected posture %q, got %q", models.PostureSymmetricOnly, got)
	}
	if a.Properties["kmsKeyId"] != "arn:aws:kms:us-east-1:111122223333:key/abc" {
		t.Errorf("encrypted volume should record the bound CMK; got %v", a.Properties["kmsKeyId"])
	}
	if a.Properties["kmsKeySpec"] != "SYMMETRIC_DEFAULT" {
		t.Errorf("expected live key spec SYMMETRIC_DEFAULT to be recorded; got %v", a.Properties["kmsKeySpec"])
	}
	if client.keyHits != 1 {
		t.Errorf("expected DescribeKey to be called once for the CMK, got %d", client.keyHits)
	}
}

// TestEBSScanEncryptedDescribeKeyFailDoesNotDrop verifies the NO-SILENT-DROP
// honesty fix at the per-resource level: when DescribeKey fails (e.g. denied on
// a cross-account / external key), the volume must NOT be dropped and must NOT
// be downgraded to NoEncryption. The AES-256-XTS cipher is an aws-doc universal
// guarantee, so the volume stays SymmetricOnly with the CMK identity recorded;
// only the optional key-spec detail is lost.
func TestEBSScanEncryptedDescribeKeyFailDoesNotDrop(t *testing.T) {
	client := &fakeEBSClient{
		volPages: []*ec2.DescribeVolumesOutput{
			{Volumes: []ec2types.Volume{{
				VolumeId:  strptr("vol-enc-denied"),
				Encrypted: boolptr(true),
				KmsKeyId:  strptr("arn:aws:kms:us-east-1:111122223333:key/denied"),
			}}},
		},
		keyErr: errors.New("AccessDeniedException: not authorized to perform kms:DescribeKey"),
	}
	assets, err := EBSScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("a per-key DescribeKey failure must not fail the whole scan; got error: %v", err)
	}
	a, ok := ebsAssetByID(assets, "vol-enc-denied")
	if !ok {
		t.Fatal("encrypted volume with a denied DescribeKey must NOT be silently dropped")
	}
	if got := a.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
		t.Errorf("DescribeKey failure must keep the always-encrypted posture SymmetricOnly (never NoEncryption); got %q", got)
	}
	if a.Properties["kmsKeyId"] != "arn:aws:kms:us-east-1:111122223333:key/denied" {
		t.Errorf("CMK identity should still be recorded despite DescribeKey failure; got %v", a.Properties["kmsKeyId"])
	}
	if _, present := a.Properties["kmsKeySpec"]; present {
		t.Errorf("key spec should be absent when DescribeKey fails; got %v", a.Properties["kmsKeySpec"])
	}
}
