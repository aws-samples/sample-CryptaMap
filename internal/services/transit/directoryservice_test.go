package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/directoryservice"
	dstypes "github.com/aws/aws-sdk-go-v2/service/directoryservice/types"
	"github.com/aws/smithy-go"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// directoryserviceAPIErr is a minimal smithy.APIError implementation so the fake
// can drive the UnsupportedOperationException -> NotApplicable branch (matched by
// errors.As against smithy.APIError in the scanner) without a live AWS client.
type directoryserviceAPIErr struct{ code string }

func (e directoryserviceAPIErr) Error() string                 { return e.code }
func (e directoryserviceAPIErr) ErrorCode() string             { return e.code }
func (e directoryserviceAPIErr) ErrorMessage() string          { return e.code }
func (e directoryserviceAPIErr) ErrorFault() smithy.ErrorFault { return smithy.FaultServer }

// directoryserviceFakeClient is a hand-rolled directoryServiceAPI for unit-testing
// pagination + error propagation + per-directory LDAPS posture without a live AWS
// client. dirPages is returned page-by-page (each call consumes the next page)
// with NextToken wired so the scanner loops through every page; dirErr forces a
// DescribeDirectories failure. ldapsByID maps a directory id to the LDAPS result
// (or error) DescribeLDAPSSettings returns for it.
type directoryserviceFakeClient struct {
	dirPages  []*directoryservice.DescribeDirectoriesOutput
	dirCalls  int
	dirErr    error
	ldapsByID map[string]directoryserviceLDAPSResult
}

type directoryserviceLDAPSResult struct {
	status dstypes.LDAPSStatus
	hasRow bool
	err    error
}

func (f *directoryserviceFakeClient) DescribeDirectories(ctx context.Context, in *directoryservice.DescribeDirectoriesInput, optFns ...func(*directoryservice.Options)) (*directoryservice.DescribeDirectoriesOutput, error) {
	if f.dirErr != nil {
		return nil, f.dirErr
	}
	if f.dirCalls >= len(f.dirPages) {
		return &directoryservice.DescribeDirectoriesOutput{}, nil
	}
	out := f.dirPages[f.dirCalls]
	f.dirCalls++
	return out, nil
}

func (f *directoryserviceFakeClient) DescribeLDAPSSettings(ctx context.Context, in *directoryservice.DescribeLDAPSSettingsInput, optFns ...func(*directoryservice.Options)) (*directoryservice.DescribeLDAPSSettingsOutput, error) {
	id := ""
	if in.DirectoryId != nil {
		id = *in.DirectoryId
	}
	res, ok := f.ldapsByID[id]
	if !ok {
		return &directoryservice.DescribeLDAPSSettingsOutput{}, nil
	}
	if res.err != nil {
		return nil, res.err
	}
	out := &directoryservice.DescribeLDAPSSettingsOutput{}
	if res.hasRow {
		out.LDAPSSettingsInfo = []dstypes.LDAPSSettingInfo{{LDAPSStatus: res.status}}
	}
	return out, nil
}

func directoryserviceStrptr(s string) *string { return &s }

func directoryserviceAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// TestDirectoryServiceScanPaginates verifies the DescribeDirectories NextToken
// loop: a fake returning 2 pages (NextToken on page 1) must yield BOTH pages'
// directories as assets. Without the pagination loop, only page 1 survives.
func TestDirectoryServiceScanPaginates(t *testing.T) {
	client := &directoryserviceFakeClient{
		dirPages: []*directoryservice.DescribeDirectoriesOutput{
			{
				DirectoryDescriptions: []dstypes.DirectoryDescription{
					{DirectoryId: directoryserviceStrptr("d-page1"), Type: dstypes.DirectoryTypeMicrosoftAd},
				},
				NextToken: directoryserviceStrptr("tok-page2"),
			},
			{
				DirectoryDescriptions: []dstypes.DirectoryDescription{
					{DirectoryId: directoryserviceStrptr("d-page2"), Type: dstypes.DirectoryTypeMicrosoftAd},
				},
			},
		},
		ldapsByID: map[string]directoryserviceLDAPSResult{
			"d-page1": {status: dstypes.LDAPSStatusEnabled, hasRow: true},
			"d-page2": {status: dstypes.LDAPSStatusEnabled, hasRow: true},
		},
	}
	assets, err := DirectoryServiceScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.dirCalls != 2 {
		t.Errorf("expected DescribeDirectories to be called 2 times (paginated), got %d", client.dirCalls)
	}
	for _, want := range []string{"d-page1", "d-page2"} {
		if _, ok := directoryserviceAssetByID(assets, want); !ok {
			t.Errorf("expected directory %q from a paginated page to appear as an asset; assets=%v", want, assets)
		}
	}
}

// TestDirectoryServiceScanDescribeDirectoriesErrorPropagates verifies the
// incompleteness posture: a DescribeDirectories failure (denied/rate-limited)
// must make the scan VISIBLY incomplete by returning a non-nil error — NOT a
// silent empty success.
func TestDirectoryServiceScanDescribeDirectoriesErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform ds:DescribeDirectories")
	client := &directoryserviceFakeClient{dirErr: sentinel}
	_, err := DirectoryServiceScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeDirectories fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeDirectories failure, got: %v", err)
	}
}

// TestDirectoryServiceScanPostures verifies the honesty posture for each LDAPS
// state. LDAPS Enabled -> NonPQCClassical (encrypted, quantum-vulnerable; never
// no-encryption since it IS encrypted). LDAPS Disabled -> NoEncryption (a genuine
// finding; never a clean all-clear). Unsupported (SimpleAD) -> Unknown with a
// NotApplicable status (never Disabled, never safe). A non-Unsupported per-
// directory LDAPS error must NOT silently drop the directory — it stays an
// Unknown asset.
func TestDirectoryServiceScanPostures(t *testing.T) {
	client := &directoryserviceFakeClient{
		dirPages: []*directoryservice.DescribeDirectoriesOutput{
			{
				DirectoryDescriptions: []dstypes.DirectoryDescription{
					{DirectoryId: directoryserviceStrptr("d-enabled"), Type: dstypes.DirectoryTypeMicrosoftAd},
					{DirectoryId: directoryserviceStrptr("d-disabled"), Type: dstypes.DirectoryTypeMicrosoftAd},
					{DirectoryId: directoryserviceStrptr("d-simplead"), Type: dstypes.DirectoryTypeSimpleAd},
					{DirectoryId: directoryserviceStrptr("d-transienterr"), Type: dstypes.DirectoryTypeMicrosoftAd},
				},
			},
		},
		ldapsByID: map[string]directoryserviceLDAPSResult{
			"d-enabled":  {status: dstypes.LDAPSStatusEnabled, hasRow: true},
			"d-disabled": {status: dstypes.LDAPSStatusDisabled, hasRow: true},
			"d-simplead": {err: directoryserviceAPIErr{code: "UnsupportedOperationException"}},
			// Transient/unknown per-directory error: must NOT drop the directory;
			// posture stays Unknown rather than masquerading as safe.
			"d-transienterr": {err: errors.New("ThrottlingException: rate exceeded")},
		},
	}
	assets, err := DirectoryServiceScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 4 {
		t.Fatalf("expected 4 assets (no silent drop), got %d: %v", len(assets), assets)
	}

	cases := []struct {
		id          string
		wantPosture models.CryptoPosture
		wantStatus  string
		wantNote    bool
	}{
		{"d-enabled", models.PostureNonPQCClassical, "Enabled", false},
		{"d-disabled", models.PostureNoEncryption, "Disabled", true},
		{"d-simplead", models.PostureUnknown, "NotApplicable", true},
		{"d-transienterr", models.PostureUnknown, "Unknown", true},
	}
	for _, tc := range cases {
		a, ok := directoryserviceAssetByID(assets, tc.id)
		if !ok {
			t.Errorf("%s: expected an asset, none found", tc.id)
			continue
		}
		if got := models.CryptoPosture(a.Properties["posture"]); got != tc.wantPosture {
			t.Errorf("%s: posture = %q, want %q", tc.id, got, tc.wantPosture)
		}
		if got := a.Properties["ldapsStatus"]; got != tc.wantStatus {
			t.Errorf("%s: ldapsStatus = %q, want %q", tc.id, got, tc.wantStatus)
		}
		_, hasNote := a.Properties["note"]
		if hasNote != tc.wantNote {
			t.Errorf("%s: hasNote = %v, want %v", tc.id, hasNote, tc.wantNote)
		}
	}
}
