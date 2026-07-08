package keymgmt

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeEC2KeyPairsClient is a hand-rolled ec2KeyPairsAPI for unit-testing the
// scanner's error propagation + classification without a live AWS client.
// DescribeKeyPairs is unpaginated, so the fake returns a single canned output (or
// a forced error) per call.
type fakeEC2KeyPairsClient struct {
	out  *ec2.DescribeKeyPairsOutput
	err  error
	call int
}

func (f *fakeEC2KeyPairsClient) DescribeKeyPairs(ctx context.Context, in *ec2.DescribeKeyPairsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeKeyPairsOutput, error) {
	f.call++
	if f.err != nil {
		return nil, f.err
	}
	if f.out != nil {
		return f.out, nil
	}
	return &ec2.DescribeKeyPairsOutput{}, nil
}

func ec2keypairsStrptr(s string) *string { return &s }

// ec2keypairsAssetByID locates an emitted asset by its ResourceID.
func ec2keypairsAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// TestEC2KeyPairsScanErrorPropagates verifies the no-silent-drop posture: a
// DescribeKeyPairs failure (denied/throttled) must make the scan VISIBLY
// incomplete by returning a non-nil error wrapping the cause — NOT an empty
// clean-looking success.
func TestEC2KeyPairsScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("UnauthorizedOperation: not authorized to perform ec2:DescribeKeyPairs")
	client := &fakeEC2KeyPairsClient{err: sentinel}

	assets, err := EC2KeyPairsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeKeyPairs fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeKeyPairs failure, got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets on error, got %d", len(assets))
	}
}

// TestEC2KeyPairsScanClassifiesAndIsHonest verifies the honesty posture for the
// SSH key-inventory domain: EVERY discovered key pair (RSA, Ed25519, and even a
// key whose type the API didn't report) must be flagged NonPQCClassical — never
// no-encryption and never quantum-resistant. The unreported-type key must carry the
// classical-unknown note rather than being silently treated as safe. A key pair
// missing its KeyPairId is skipped (cannot identify the resource), but valid
// siblings still emit.
func TestEC2KeyPairsScanClassifiesAndIsHonest(t *testing.T) {
	created := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	client := &fakeEC2KeyPairsClient{
		out: &ec2.DescribeKeyPairsOutput{
			KeyPairs: []ec2types.KeyPairInfo{
				{
					KeyPairId:      ec2keypairsStrptr("key-rsa"),
					KeyName:        ec2keypairsStrptr("rsa-key"),
					KeyType:        ec2types.KeyTypeRsa,
					KeyFingerprint: ec2keypairsStrptr("aa:bb"),
					CreateTime:     &created,
				},
				{
					KeyPairId: ec2keypairsStrptr("key-ed"),
					KeyName:   ec2keypairsStrptr("ed-key"),
					KeyType:   ec2types.KeyTypeEd25519,
				},
				{
					// KeyType not reported by the API -> classical-unknown, never safe.
					KeyPairId: ec2keypairsStrptr("key-unknown"),
					KeyName:   ec2keypairsStrptr("unknown-key"),
				},
				{
					// No KeyPairId -> unidentifiable -> skipped.
					KeyName: ec2keypairsStrptr("orphan"),
				},
			},
		},
	}

	assets, err := EC2KeyPairsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 3 {
		t.Fatalf("expected 3 assets (rsa, ed25519, unknown-type; orphan skipped), got %d", len(assets))
	}

	// Every key pair must be NonPQCClassical — never no-encryption, never quantum-resistant.
	for _, a := range assets {
		posture := a.Properties["posture"]
		if posture != string(models.PostureNonPQCClassical) {
			t.Errorf("asset %q: expected posture %q, got %q", a.ResourceID, models.PostureNonPQCClassical, posture)
		}
		if posture == string(models.PostureNoEncryption) {
			t.Errorf("asset %q: a key pair must never be classified no-encryption", a.ResourceID)
		}
		if a.ResourceType != "AWS::EC2::KeyPair" {
			t.Errorf("asset %q: unexpected resourceType %q", a.ResourceID, a.ResourceType)
		}
	}

	// RSA: classical signature spec mapped, keyType recorded.
	rsa, ok := ec2keypairsAssetByID(assets, "key-rsa")
	if !ok {
		t.Fatal("expected an asset for key-rsa")
	}
	if rsa.Properties["keyType"] != "rsa" {
		t.Errorf("key-rsa: expected keyType=rsa, got %q", rsa.Properties["keyType"])
	}
	if rsa.CryptoProps.AlgorithmProperties == nil {
		t.Fatal("key-rsa: expected AlgorithmProperties to be set")
	}
	if got := rsa.CryptoProps.AlgorithmProperties.KeySizeBits; got != 2048 {
		t.Errorf("key-rsa: expected 2048-bit RSA, got %d", got)
	}
	if rsa.CryptoProps.AlgorithmProperties.Primitive != models.PrimitiveSignature {
		t.Errorf("key-rsa: expected signature primitive, got %q", rsa.CryptoProps.AlgorithmProperties.Primitive)
	}

	// Ed25519: classical EC signature spec mapped.
	ed, ok := ec2keypairsAssetByID(assets, "key-ed")
	if !ok {
		t.Fatal("expected an asset for key-ed")
	}
	if ed.CryptoProps.AlgorithmProperties == nil || ed.CryptoProps.AlgorithmProperties.KeySizeBits != 256 {
		t.Errorf("key-ed: expected 256-bit Ed25519 algorithm props, got %+v", ed.CryptoProps.AlgorithmProperties)
	}

	// Unreported KeyType: classical-unknown with explanatory note, NOT silently
	// treated as quantum-resistant and NOT given a fabricated keyType.
	unk, ok := ec2keypairsAssetByID(assets, "key-unknown")
	if !ok {
		t.Fatal("expected an asset for key-unknown")
	}
	if _, has := unk.Properties["keyType"]; has {
		t.Errorf("key-unknown: must not fabricate a keyType when the API did not report one, got %q", unk.Properties["keyType"])
	}
	if unk.Properties["note"] == "" {
		t.Errorf("key-unknown: expected an explanatory classical-unknown note, got none")
	}
}

// TestEC2KeyPairsRSASizeIsMarkedAssumed guards the imported-key honesty fix:
// DescribeKeyPairs reports only KeyType "rsa" (never the modulus size), and
// IMPORTED key pairs may be RSA-1024/3072/4096, so the 2048-bit figure is an
// assumption about EC2-generated keys — the asset must carry
// keySizeAssumed=true so a weak imported 1024-bit key is never presented as a
// definite, high-confidence RSA-2048 observation. Ed25519 (fixed size by
// definition) must NOT carry the marker.
func TestEC2KeyPairsRSASizeIsMarkedAssumed(t *testing.T) {
	client := &fakeEC2KeyPairsClient{
		out: &ec2.DescribeKeyPairsOutput{
			KeyPairs: []ec2types.KeyPairInfo{
				{KeyPairId: ec2keypairsStrptr("key-rsa"), KeyType: ec2types.KeyTypeRsa},
				{KeyPairId: ec2keypairsStrptr("key-ed"), KeyType: ec2types.KeyTypeEd25519},
			},
		},
	}
	assets, err := EC2KeyPairsScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	byID := map[string]models.CryptoAsset{}
	for _, a := range assets {
		byID[a.ResourceID] = a
	}
	if got := byID["key-rsa"].Properties["keySizeAssumed"]; got != "true" {
		t.Errorf("RSA key pair: expected keySizeAssumed=true (API does not expose the modulus; imported keys may be 1024/3072/4096), got %q", got)
	}
	if got, ok := byID["key-ed"].Properties["keySizeAssumed"]; ok {
		t.Errorf("Ed25519 key pair: keySizeAssumed must be absent (size fixed by definition), got %q", got)
	}
}
