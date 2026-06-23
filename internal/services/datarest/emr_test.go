package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/emr"
	emrtypes "github.com/aws/aws-sdk-go-v2/service/emr/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeEMRClient is a hand-rolled emrAPI for unit-testing the scanner's
// pagination + per-resource error handling + posture mapping without a live AWS
// client. listPages is returned page-by-page (each call consumes the next page)
// with the Marker wired so the scanner loops through every page; listErr forces a
// top-level ListSecurityConfigurations failure; describeBodies maps a security
// configuration name to the raw JSON body DescribeSecurityConfiguration returns
// and describeErrs maps a name to a per-config Describe error.
type fakeEMRClient struct {
	listPages      []*emr.ListSecurityConfigurationsOutput
	listCalls      int
	listErr        error
	describeBodies map[string]string
	describeErrs   map[string]error
}

func (f *fakeEMRClient) ListSecurityConfigurations(ctx context.Context, in *emr.ListSecurityConfigurationsInput, optFns ...func(*emr.Options)) (*emr.ListSecurityConfigurationsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listCalls >= len(f.listPages) {
		return &emr.ListSecurityConfigurationsOutput{}, nil
	}
	out := f.listPages[f.listCalls]
	f.listCalls++
	return out, nil
}

func (f *fakeEMRClient) DescribeSecurityConfiguration(ctx context.Context, in *emr.DescribeSecurityConfigurationInput, optFns ...func(*emr.Options)) (*emr.DescribeSecurityConfigurationOutput, error) {
	name := ""
	if in.Name != nil {
		name = *in.Name
	}
	if f.describeErrs != nil {
		if err, ok := f.describeErrs[name]; ok {
			return nil, err
		}
	}
	if f.describeBodies != nil {
		if body, ok := f.describeBodies[name]; ok {
			b := body
			return &emr.DescribeSecurityConfigurationOutput{SecurityConfiguration: &b}, nil
		}
	}
	return &emr.DescribeSecurityConfigurationOutput{}, nil
}

func emrStrptr(s string) *string { return &s }

// scSummaries builds the ListSecurityConfigurations Items from a set of names.
func scSummaries(names ...string) []emrtypes.SecurityConfigurationSummary {
	out := make([]emrtypes.SecurityConfigurationSummary, 0, len(names))
	for _, n := range names {
		n := n
		out = append(out, emrtypes.SecurityConfigurationSummary{Name: &n})
	}
	return out
}

// emrAssetByID indexes scanned assets by ResourceID for easy lookup in assertions.
func emrAssetByID(assets []models.CryptoAsset) map[string]models.CryptoAsset {
	m := map[string]models.CryptoAsset{}
	for _, a := range assets {
		m[a.ResourceID] = a
	}
	return m
}

// TestEMRScanPaginatesSecurityConfigurations verifies the ListSecurityConfigurations
// Marker loop: a fake returning 2 pages (Marker on page 1) must yield BOTH pages'
// security configurations as assets. Without the pagination loop, only the first
// page's config survives — the commonest real bug.
func TestEMRScanPaginatesSecurityConfigurations(t *testing.T) {
	client := &fakeEMRClient{
		listPages: []*emr.ListSecurityConfigurationsOutput{
			{
				SecurityConfigurations: scSummaries("sc-page1"),
				Marker:                 emrStrptr("marker-page2"),
			},
			{
				SecurityConfigurations: scSummaries("sc-page2"),
				// no Marker -> last page
			},
		},
		describeBodies: map[string]string{
			"sc-page1": `{"EncryptionConfiguration":{"EnableAtRestEncryption":true,"EnableInTransitEncryption":false}}`,
			"sc-page2": `{"EncryptionConfiguration":{"EnableAtRestEncryption":true,"EnableInTransitEncryption":true}}`,
		},
	}
	assets, err := EMRScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.listCalls != 2 {
		t.Errorf("expected ListSecurityConfigurations to be called 2 times (paginated), got %d", client.listCalls)
	}
	got := emrAssetByID(assets)
	for _, want := range []string{"sc-page1", "sc-page2"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected security configuration %q from a paginated page to appear as an asset; got %v", want, emrKeysOf(got))
		}
	}
}

// TestEMRScanListErrorPropagates verifies that a top-level
// ListSecurityConfigurations failure (denied/rate-limited) makes the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success.
func TestEMRScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform elasticmapreduce:ListSecurityConfigurations")
	client := &fakeEMRClient{listErr: sentinel}
	_, err := EMRScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListSecurityConfigurations fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListSecurityConfigurations failure, got: %v", err)
	}
}

// TestEMRScanDescribeErrorNotSilentlyDropped verifies the batch-1 honesty fix: a
// per-config DescribeSecurityConfiguration error must NOT silently drop the
// config. Instead the scanner emits a PostureUnknown asset with a note, so a read
// failure is neither a false all-clear by omission nor a fabricated NoEncryption
// false alarm. A second config that reads fine must still be classified normally.
func TestEMRScanDescribeErrorNotSilentlyDropped(t *testing.T) {
	client := &fakeEMRClient{
		listPages: []*emr.ListSecurityConfigurationsOutput{
			{SecurityConfigurations: scSummaries("sc-broken", "sc-ok")},
		},
		describeErrs: map[string]error{
			"sc-broken": errors.New("ThrottlingException: rate exceeded"),
		},
		describeBodies: map[string]string{
			"sc-ok": `{"EncryptionConfiguration":{"EnableAtRestEncryption":true,"EnableInTransitEncryption":false}}`,
		},
	}
	assets, err := EMRScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	got := emrAssetByID(assets)
	broken, ok := got["sc-broken"]
	if !ok {
		t.Fatal("expected the config with a DescribeSecurityConfiguration error to still appear as an asset (not silently dropped)")
	}
	if broken.Properties["posture"] != string(models.PostureUnknown) {
		t.Errorf("expected Describe-errored config to be PostureUnknown, got %q", broken.Properties["posture"])
	}
	if broken.Properties["note"] == "" {
		t.Error("expected a note explaining the undetermined state on the errored config")
	}
	if _, ok := got["sc-ok"]; !ok {
		t.Error("expected the healthy config to still be classified despite a sibling's read error")
	}
}

// TestEMRScanPostureMapping verifies the honesty posture mapping for EMR's opt-in
// SecurityConfiguration encryption:
//   - at-rest and/or in-transit enabled -> PostureSymmetricOnly (AES-256 / classical
//     TLS; EMR has no PQC option), NEVER NoEncryption.
//   - EnableAtRestEncryption=false AND EnableInTransitEncryption=false -> a GENUINE
//     PostureNoEncryption with a note (clusters using it are unencrypted), never a
//     false all-clear.
//   - no EncryptionConfiguration block at all -> PostureNoEncryption with a note
//     (genuine: the config defines nothing encrypted).
//   - unparseable JSON -> PostureUnknown with a note (a parser regression must be
//     distinguishable from a true unknown, never collapse to NoEncryption).
func TestEMRScanPostureMapping(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantPosture models.CryptoPosture
		wantAtRest  string
		wantInTrans string
		wantNote    bool
	}{
		{
			name:        "at-rest-only-enabled",
			body:        `{"EncryptionConfiguration":{"EnableAtRestEncryption":true,"EnableInTransitEncryption":false}}`,
			wantPosture: models.PostureSymmetricOnly,
			wantAtRest:  "true",
			wantInTrans: "false",
		},
		{
			name:        "both-enabled",
			body:        `{"EncryptionConfiguration":{"EnableAtRestEncryption":true,"EnableInTransitEncryption":true}}`,
			wantPosture: models.PostureSymmetricOnly,
			wantAtRest:  "true",
			wantInTrans: "true",
		},
		{
			name:        "both-disabled-genuine-no-encryption",
			body:        `{"EncryptionConfiguration":{"EnableAtRestEncryption":false,"EnableInTransitEncryption":false}}`,
			wantPosture: models.PostureNoEncryption,
			wantAtRest:  "false",
			wantInTrans: "false",
			wantNote:    true,
		},
		{
			name:        "no-encryption-block",
			body:        `{"InstanceMetadataServiceConfiguration":{}}`,
			wantPosture: models.PostureNoEncryption,
			wantNote:    true,
		},
		{
			name:        "unparseable-json",
			body:        `{not valid json`,
			wantPosture: models.PostureUnknown,
			wantNote:    true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeEMRClient{
				listPages: []*emr.ListSecurityConfigurationsOutput{
					{SecurityConfigurations: scSummaries(tc.name)},
				},
				describeBodies: map[string]string{tc.name: tc.body},
			}
			assets, err := EMRScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
			if err != nil {
				t.Fatalf("scan returned unexpected error: %v", err)
			}
			if len(assets) != 1 {
				t.Fatalf("expected exactly 1 asset, got %d", len(assets))
			}
			a := assets[0]
			if a.Properties["posture"] != string(tc.wantPosture) {
				t.Errorf("posture: want %q, got %q", tc.wantPosture, a.Properties["posture"])
			}
			// Guard the most dangerous false-clear: an enabled config must never read as NoEncryption.
			if tc.wantPosture == models.PostureSymmetricOnly && a.Properties["posture"] == string(models.PostureNoEncryption) {
				t.Error("enabled EMR config must never collapse to NoEncryption (false alarm)")
			}
			if tc.wantAtRest != "" && a.Properties["enableAtRestEncryption"] != tc.wantAtRest {
				t.Errorf("enableAtRestEncryption: want %q, got %q", tc.wantAtRest, a.Properties["enableAtRestEncryption"])
			}
			if tc.wantInTrans != "" && a.Properties["enableInTransitEncryption"] != tc.wantInTrans {
				t.Errorf("enableInTransitEncryption: want %q, got %q", tc.wantInTrans, a.Properties["enableInTransitEncryption"])
			}
			if tc.wantNote && a.Properties["note"] == "" {
				t.Error("expected an explanatory note for this posture")
			}
		})
	}
}

func emrKeysOf(m map[string]models.CryptoAsset) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
