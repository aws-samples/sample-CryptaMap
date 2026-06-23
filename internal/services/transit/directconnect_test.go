package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/directconnect"
	dctypes "github.com/aws/aws-sdk-go-v2/service/directconnect/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeDirectConnectClient is a hand-rolled directConnectAPI for unit-testing the
// scanner's error propagation + posture classification without a live AWS
// client. DescribeConnections is not paginated, so the fake returns the whole
// connection set in one call; describeErr forces a top-level failure.
type fakeDirectConnectClient struct {
	out         *directconnect.DescribeConnectionsOutput
	describeErr error
	calls       int
}

func (f *fakeDirectConnectClient) DescribeConnections(ctx context.Context, in *directconnect.DescribeConnectionsInput, optFns ...func(*directconnect.Options)) (*directconnect.DescribeConnectionsOutput, error) {
	f.calls++
	if f.describeErr != nil {
		return nil, f.describeErr
	}
	if f.out != nil {
		return f.out, nil
	}
	return &directconnect.DescribeConnectionsOutput{}, nil
}

func directconnectStrptr(s string) *string { return &s }
func directconnectBoolptr(b bool) *bool    { return &b }

// directconnectPostureOf returns the classified posture stamped onto the asset
// with the matching ResourceID (PostureProperty stores it in Properties).
func directconnectPostureOf(assets []models.CryptoAsset, resourceID string) (string, bool) {
	for _, a := range assets {
		if a.ResourceID == resourceID {
			return a.Properties["posture"], true
		}
	}
	return "", false
}

// TestDirectConnectScanDescribeErrorPropagates verifies the incompleteness
// posture: a DescribeConnections failure (denied/throttled) must make the scan
// VISIBLY incomplete by returning a non-nil error wrapping the cause — NOT a
// silent empty success.
func TestDirectConnectScanDescribeErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform directconnect:DescribeConnections")
	client := &fakeDirectConnectClient{describeErr: sentinel}
	assets, err := DirectConnectScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeConnections fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeConnections failure, got: %v", err)
	}
	if assets != nil {
		t.Errorf("expected nil assets on error, got %v", assets)
	}
}

// TestDirectConnectScanReturnsAllConnections verifies that all connections in a
// single (non-paginated) DescribeConnections response surface as assets — none
// is silently dropped.
func TestDirectConnectScanReturnsAllConnections(t *testing.T) {
	client := &fakeDirectConnectClient{
		out: &directconnect.DescribeConnectionsOutput{
			Connections: []dctypes.Connection{
				{ConnectionId: directconnectStrptr("dxcon-aaa"), EncryptionMode: directconnectStrptr("must_encrypt")},
				{ConnectionId: directconnectStrptr("dxcon-bbb"), EncryptionMode: directconnectStrptr("no_encrypt")},
				// nil ConnectionId must be skipped, not panic.
				{ConnectionId: nil, EncryptionMode: directconnectStrptr("must_encrypt")},
			},
		},
	}
	assets, err := DirectConnectScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 1 {
		t.Errorf("expected DescribeConnections to be called once, got %d", client.calls)
	}
	got := map[string]bool{}
	for _, a := range assets {
		got[a.ResourceID] = true
	}
	for _, want := range []string{"dxcon-aaa", "dxcon-bbb"} {
		if !got[want] {
			t.Errorf("expected connection %q to appear as an asset; assets=%v", want, got)
		}
	}
	if len(assets) != 2 {
		t.Errorf("expected 2 assets (nil ConnectionId skipped), got %d", len(assets))
	}
}

// TestDirectConnectScanPostureHonesty is the honesty-posture table: MACsec
// AES-GCM is symmetric (quantum-resistant) so enforced/live connections must be
// symmetric-only — NEVER no-encryption and NEVER non-pqc-classical (which would
// false-alarm a symmetric cipher as a migration target). Critically,
// should_encrypt is the DEFAULT that FALLS BACK to cleartext, so it is
// no-encryption UNLESS PortEncryptionStatus proves MACsec is live ("Encryption
// Up") — never silently treated as clean/encrypted.
func TestDirectConnectScanPostureHonesty(t *testing.T) {
	cases := []struct {
		directconnectName string
		directconnectID   string
		encryptionMode    *string
		portStatus        *string
		macSecCapable     *bool
		directconnectWant models.CryptoPosture
	}{
		{
			directconnectName: "must_encrypt -> symmetric-only (enforced AES-GCM)",
			directconnectID:   "dxcon-must",
			encryptionMode:    directconnectStrptr("must_encrypt"),
			macSecCapable:     directconnectBoolptr(true),
			directconnectWant: models.PostureSymmetricOnly,
		},
		{
			directconnectName: "should_encrypt + Encryption Up -> symmetric-only (proven live MACsec)",
			directconnectID:   "dxcon-live",
			encryptionMode:    directconnectStrptr("should_encrypt"),
			portStatus:        directconnectStrptr("Encryption Up"),
			macSecCapable:     directconnectBoolptr(true),
			directconnectWant: models.PostureSymmetricOnly,
		},
		{
			directconnectName: "should_encrypt + Encryption Down -> no-encryption (cleartext fallback, NOT clean)",
			directconnectID:   "dxcon-fallback",
			encryptionMode:    directconnectStrptr("should_encrypt"),
			portStatus:        directconnectStrptr("Encryption Down"),
			macSecCapable:     directconnectBoolptr(true),
			directconnectWant: models.PostureNoEncryption,
		},
		{
			directconnectName: "should_encrypt + absent port status -> no-encryption (cannot prove live)",
			directconnectID:   "dxcon-unknownport",
			encryptionMode:    directconnectStrptr("should_encrypt"),
			macSecCapable:     directconnectBoolptr(true),
			directconnectWant: models.PostureNoEncryption,
		},
		{
			directconnectName: "no_encrypt -> no-encryption",
			directconnectID:   "dxcon-none",
			encryptionMode:    directconnectStrptr("no_encrypt"),
			directconnectWant: models.PostureNoEncryption,
		},
		{
			directconnectName: "nil EncryptionMode -> no-encryption",
			directconnectID:   "dxcon-nilmode",
			encryptionMode:    nil,
			directconnectWant: models.PostureNoEncryption,
		},
	}

	for _, tc := range cases {
		t.Run(tc.directconnectName, func(t *testing.T) {
			client := &fakeDirectConnectClient{
				out: &directconnect.DescribeConnectionsOutput{
					Connections: []dctypes.Connection{
						{
							ConnectionId:         directconnectStrptr(tc.directconnectID),
							EncryptionMode:       tc.encryptionMode,
							PortEncryptionStatus: tc.portStatus,
							MacSecCapable:        tc.macSecCapable,
						},
					},
				},
			}
			assets, err := DirectConnectScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
			if err != nil {
				t.Fatalf("scan returned unexpected error: %v", err)
			}
			posture, ok := directconnectPostureOf(assets, tc.directconnectID)
			if !ok {
				t.Fatalf("connection %q produced no asset", tc.directconnectID)
			}
			if posture != string(tc.directconnectWant) {
				t.Errorf("posture = %q, want %q", posture, tc.directconnectWant)
			}
			// Honesty guard: a MACsec (symmetric) connection must never be
			// flagged as non-pqc-classical, and an unencrypted one must never
			// masquerade as symmetric-only.
			if posture == string(models.PostureNonPQCClassical) {
				t.Errorf("MACsec connection %q wrongly classified non-pqc-classical (symmetric false-alarm)", tc.directconnectID)
			}
		})
	}
}
