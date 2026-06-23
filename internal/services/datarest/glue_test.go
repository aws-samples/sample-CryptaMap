package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeGlueClient is a hand-rolled glueCatalogAPI for unit-testing the scanner's
// posture mapping + error propagation without a live AWS client. settings is
// returned verbatim; err forces a GetDataCatalogEncryptionSettings failure.
type fakeGlueClient struct {
	settings *gluetypes.DataCatalogEncryptionSettings
	err      error
	calls    int
}

func (f *fakeGlueClient) GetDataCatalogEncryptionSettings(ctx context.Context, in *glue.GetDataCatalogEncryptionSettingsInput, optFns ...func(*glue.Options)) (*glue.GetDataCatalogEncryptionSettingsOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &glue.GetDataCatalogEncryptionSettingsOutput{DataCatalogEncryptionSettings: f.settings}, nil
}

// TestGlueScanErrorPropagates verifies the owner's incompleteness decision: a
// GetDataCatalogEncryptionSettings failure (denied/rate-limited) must make the
// scan VISIBLY incomplete by returning a non-nil error — NOT a silent empty
// success that would read as a clean "no catalog" all-clear.
func TestGlueScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform glue:GetDataCatalogEncryptionSettings")
	client := &fakeGlueClient{err: sentinel}

	assets, err := GlueScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when GetDataCatalogEncryptionSettings fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the API failure, got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets on error, got %d", len(assets))
	}
}

// TestGlueScanPostureMapping verifies the HONESTY posture mapping for the Glue
// Data Catalog, which is opt-in SSE (default CatalogEncryptionMode is DISABLED):
//   - DISABLED / nil settings -> PostureNoEncryption only when genuinely off.
//   - SSE-KMS (explicit CMK)  -> PostureSymmetricOnly, CMK recorded.
//   - SSE-KMS-WITH-SERVICE-ROLE (key id legitimately absent) -> still
//     PostureSymmetricOnly, NOT a false NoEncryption — guards the documented bug
//     where keying off SseAwsKmsKeyId presence alone mislabels an encrypted catalog.
func TestGlueScanPostureMapping(t *testing.T) {
	tests := []struct {
		name        string
		settings    *gluetypes.DataCatalogEncryptionSettings
		wantPosture models.CryptoPosture
		wantKMSKey  string // empty => kmsKeyId property must be absent
		wantMode    string
	}{
		{
			name:        "nil settings is genuinely off -> NoEncryption",
			settings:    nil,
			wantPosture: models.PostureNoEncryption,
		},
		{
			name: "DISABLED mode is genuinely off -> NoEncryption",
			settings: &gluetypes.DataCatalogEncryptionSettings{
				EncryptionAtRest: &gluetypes.EncryptionAtRest{
					CatalogEncryptionMode: gluetypes.CatalogEncryptionModeDisabled,
				},
			},
			wantPosture: models.PostureNoEncryption,
			wantMode:    string(gluetypes.CatalogEncryptionModeDisabled),
		},
		{
			name: "SSE-KMS with explicit CMK -> SymmetricOnly, CMK recorded",
			settings: &gluetypes.DataCatalogEncryptionSettings{
				EncryptionAtRest: &gluetypes.EncryptionAtRest{
					CatalogEncryptionMode: gluetypes.CatalogEncryptionModeSsekms,
					SseAwsKmsKeyId:        strptr("arn:aws:kms:us-east-1:111122223333:key/abc-123"),
				},
			},
			wantPosture: models.PostureSymmetricOnly,
			wantKMSKey:  "arn:aws:kms:us-east-1:111122223333:key/abc-123",
			wantMode:    string(gluetypes.CatalogEncryptionModeSsekms),
		},
		{
			name: "SSE-KMS-WITH-SERVICE-ROLE with absent key id is STILL encrypted -> SymmetricOnly, no false NoEncryption",
			settings: &gluetypes.DataCatalogEncryptionSettings{
				EncryptionAtRest: &gluetypes.EncryptionAtRest{
					CatalogEncryptionMode:        gluetypes.CatalogEncryptionModeSsekmswithservicerole,
					CatalogEncryptionServiceRole: strptr("arn:aws:iam::111122223333:role/glue-sse"),
					// SseAwsKmsKeyId intentionally nil
				},
			},
			wantPosture: models.PostureSymmetricOnly,
			wantMode:    string(gluetypes.CatalogEncryptionModeSsekmswithservicerole),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeGlueClient{settings: tc.settings}
			assets, err := GlueScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
			if err != nil {
				t.Fatalf("scan returned unexpected error: %v", err)
			}
			if len(assets) != 1 {
				t.Fatalf("expected exactly 1 catalog asset, got %d", len(assets))
			}
			a := assets[0]
			if got := a.Properties["posture"]; got != string(tc.wantPosture) {
				t.Errorf("posture = %q, want %q", got, tc.wantPosture)
			}
			if a.ResourceType != "AWS::Glue::DataCatalog" {
				t.Errorf("ResourceType = %q, want AWS::Glue::DataCatalog", a.ResourceType)
			}
			gotKey := a.Properties["kmsKeyId"]
			if gotKey != tc.wantKMSKey {
				t.Errorf("kmsKeyId = %q, want %q", gotKey, tc.wantKMSKey)
			}
			if tc.wantMode != "" && a.Properties["catalogEncryptionMode"] != tc.wantMode {
				t.Errorf("catalogEncryptionMode = %q, want %q", a.Properties["catalogEncryptionMode"], tc.wantMode)
			}
		})
	}
}
