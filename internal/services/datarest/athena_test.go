package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/athena"
	athenatypes "github.com/aws/aws-sdk-go-v2/service/athena/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeAthenaClient is a hand-rolled athenaAPI for unit-testing the scanner's
// pagination + per-resource error handling + posture mapping without a live AWS
// client. listPages is returned page-by-page (each call consumes the next page)
// with the NextToken wired so the scanner loops through every page; listErr
// forces a top-level ListWorkGroups failure; getWorkGroups maps a workgroup name
// to the GetWorkGroup output (or error) it should return.
type fakeAthenaClient struct {
	listPages     []*athena.ListWorkGroupsOutput
	listCalls     int
	listErr       error
	getWorkGroups map[string]*athena.GetWorkGroupOutput
	getErrs       map[string]error
}

func (f *fakeAthenaClient) ListWorkGroups(ctx context.Context, in *athena.ListWorkGroupsInput, optFns ...func(*athena.Options)) (*athena.ListWorkGroupsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listCalls >= len(f.listPages) {
		return &athena.ListWorkGroupsOutput{}, nil
	}
	out := f.listPages[f.listCalls]
	f.listCalls++
	return out, nil
}

func (f *fakeAthenaClient) GetWorkGroup(ctx context.Context, in *athena.GetWorkGroupInput, optFns ...func(*athena.Options)) (*athena.GetWorkGroupOutput, error) {
	name := ""
	if in.WorkGroup != nil {
		name = *in.WorkGroup
	}
	if f.getErrs != nil {
		if err, ok := f.getErrs[name]; ok {
			return nil, err
		}
	}
	if f.getWorkGroups != nil {
		if out, ok := f.getWorkGroups[name]; ok {
			return out, nil
		}
	}
	return &athena.GetWorkGroupOutput{}, nil
}

func athStrptr(s string) *string { return &s }

func athBoolptr(b bool) *bool { return &b }

// wgSummaries builds the ListWorkGroups Items from a set of names.
func wgSummaries(names ...string) []athenatypes.WorkGroupSummary {
	out := make([]athenatypes.WorkGroupSummary, 0, len(names))
	for _, n := range names {
		n := n
		out = append(out, athenatypes.WorkGroupSummary{Name: &n})
	}
	return out
}

// wgWithEncryption builds a GetWorkGroup output whose result-config carries the
// given SSE option (empty option -> no EncryptionConfiguration at all).
func wgWithEncryption(name string, opt athenatypes.EncryptionOption, kmsKey string, enforce bool) *athena.GetWorkGroupOutput {
	cfg := &athenatypes.WorkGroupConfiguration{
		EnforceWorkGroupConfiguration: athBoolptr(enforce),
		ResultConfiguration:           &athenatypes.ResultConfiguration{},
	}
	if opt != "" {
		enc := &athenatypes.EncryptionConfiguration{EncryptionOption: opt}
		if kmsKey != "" {
			enc.KmsKey = athStrptr(kmsKey)
		}
		cfg.ResultConfiguration.EncryptionConfiguration = enc
	}
	return &athena.GetWorkGroupOutput{
		WorkGroup: &athenatypes.WorkGroup{
			Name:          athStrptr(name),
			Configuration: cfg,
		},
	}
}

// athAssetByID indexes scanned assets by ResourceID for easy lookup in assertions.
func athAssetByID(assets []models.CryptoAsset) map[string]models.CryptoAsset {
	m := map[string]models.CryptoAsset{}
	for _, a := range assets {
		m[a.ResourceID] = a
	}
	return m
}

// TestAthenaScanPaginatesWorkGroups verifies the ListWorkGroups NextToken loop:
// a fake returning 2 pages (NextToken on page 1) must yield BOTH pages'
// workgroups as assets. Without the pagination loop, only the first page's
// workgroup survives — the commonest real bug.
func TestAthenaScanPaginatesWorkGroups(t *testing.T) {
	client := &fakeAthenaClient{
		listPages: []*athena.ListWorkGroupsOutput{
			{
				WorkGroups: wgSummaries("wg-page1"),
				NextToken:  athStrptr("tok-page2"),
			},
			{
				WorkGroups: wgSummaries("wg-page2"),
				// no NextToken -> last page
			},
		},
		getWorkGroups: map[string]*athena.GetWorkGroupOutput{
			"wg-page1": wgWithEncryption("wg-page1", athenatypes.EncryptionOptionSseS3, "", true),
			"wg-page2": wgWithEncryption("wg-page2", athenatypes.EncryptionOptionSseS3, "", true),
		},
	}
	assets, err := AthenaScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.listCalls != 2 {
		t.Errorf("expected ListWorkGroups to be called 2 times (paginated), got %d", client.listCalls)
	}
	got := athAssetByID(assets)
	for _, want := range []string{"wg-page1", "wg-page2"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected workgroup %q from a paginated page to appear as an asset; got %v", want, athKeysOf(got))
		}
	}
}

// TestAthenaScanListErrorPropagates verifies that a top-level ListWorkGroups
// failure (denied/rate-limited) makes the scan VISIBLY incomplete by returning a
// non-nil error — NOT a silent empty success.
func TestAthenaScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform athena:ListWorkGroups")
	client := &fakeAthenaClient{listErr: sentinel}
	_, err := AthenaScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListWorkGroups fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListWorkGroups failure, got: %v", err)
	}
}

// TestAthenaScanGetWorkGroupErrorNotSilentlyDropped verifies the batch-1 honesty
// fix: a per-workgroup GetWorkGroup error must NOT silently drop the workgroup.
// Instead the scanner emits a PostureUnknown asset with a note, so a read failure
// is neither a false all-clear by omission nor a fabricated NoEncryption false
// alarm. A second workgroup that reads fine must still be classified normally.
func TestAthenaScanGetWorkGroupErrorNotSilentlyDropped(t *testing.T) {
	client := &fakeAthenaClient{
		listPages: []*athena.ListWorkGroupsOutput{
			{WorkGroups: wgSummaries("wg-broken", "wg-ok")},
		},
		getErrs: map[string]error{
			"wg-broken": errors.New("ThrottlingException: rate exceeded"),
		},
		getWorkGroups: map[string]*athena.GetWorkGroupOutput{
			"wg-ok": wgWithEncryption("wg-ok", athenatypes.EncryptionOptionSseKms, "arn:aws:kms:us-east-1:111122223333:key/abc", true),
		},
	}
	assets, err := AthenaScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	got := athAssetByID(assets)
	broken, ok := got["wg-broken"]
	if !ok {
		t.Fatal("expected the workgroup with a GetWorkGroup error to still appear as an asset (not silently dropped)")
	}
	if broken.Properties["posture"] != string(models.PostureUnknown) {
		t.Errorf("expected GetWorkGroup-errored workgroup to be PostureUnknown, got %q", broken.Properties["posture"])
	}
	if broken.Properties["note"] == "" {
		t.Error("expected a note explaining the undetermined state on the errored workgroup")
	}
	if _, ok := got["wg-ok"]; !ok {
		t.Error("expected the healthy workgroup to still be classified despite a sibling's read error")
	}
}

// TestAthenaScanPostureMapping verifies the honesty posture mapping for Athena's
// opt-in (Type-B) result encryption:
//   - no EncryptionConfiguration -> PostureNoEncryption with a note (genuine
//     no-encryption: query results land unencrypted in S3, never a false clear).
//   - SSE_S3 / SSE_KMS / CSE_KMS -> PostureSymmetricOnly (AES-256, never
//     NoEncryption); a present CMK is recorded.
func TestAthenaScanPostureMapping(t *testing.T) {
	cases := []struct {
		name        string
		opt         athenatypes.EncryptionOption
		kmsKey      string
		wantPosture models.CryptoPosture
		wantSSE     string
		wantKMS     string
		wantNote    bool
	}{
		{
			name:        "unencrypted-primary",
			opt:         "", // no EncryptionConfiguration -> genuinely off
			wantPosture: models.PostureNoEncryption,
			wantNote:    true,
		},
		{
			name:        "sse-s3",
			opt:         athenatypes.EncryptionOptionSseS3,
			wantPosture: models.PostureSymmetricOnly,
			wantSSE:     string(athenatypes.EncryptionOptionSseS3),
		},
		{
			name:        "sse-kms-with-cmk",
			opt:         athenatypes.EncryptionOptionSseKms,
			kmsKey:      "arn:aws:kms:us-east-1:111122223333:key/cmk-1",
			wantPosture: models.PostureSymmetricOnly,
			wantSSE:     string(athenatypes.EncryptionOptionSseKms),
			wantKMS:     "arn:aws:kms:us-east-1:111122223333:key/cmk-1",
		},
		{
			name:        "cse-kms",
			opt:         athenatypes.EncryptionOptionCseKms,
			kmsKey:      "arn:aws:kms:us-east-1:111122223333:key/cmk-2",
			wantPosture: models.PostureSymmetricOnly,
			wantSSE:     string(athenatypes.EncryptionOptionCseKms),
			wantKMS:     "arn:aws:kms:us-east-1:111122223333:key/cmk-2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeAthenaClient{
				listPages: []*athena.ListWorkGroupsOutput{
					{WorkGroups: wgSummaries(tc.name)},
				},
				getWorkGroups: map[string]*athena.GetWorkGroupOutput{
					tc.name: wgWithEncryption(tc.name, tc.opt, tc.kmsKey, true),
				},
			}
			assets, err := AthenaScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
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
			if tc.wantSSE != "" && a.Properties["sseAlgorithm"] != tc.wantSSE {
				t.Errorf("sseAlgorithm: want %q, got %q", tc.wantSSE, a.Properties["sseAlgorithm"])
			}
			if tc.wantKMS != "" && a.Properties["kmsKeyId"] != tc.wantKMS {
				t.Errorf("kmsKeyId: want %q, got %q", tc.wantKMS, a.Properties["kmsKeyId"])
			}
			if tc.wantNote && a.Properties["note"] == "" {
				t.Error("expected a no-encryption note on an unencrypted workgroup")
			}
		})
	}
}

func athKeysOf(m map[string]models.CryptoAsset) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
