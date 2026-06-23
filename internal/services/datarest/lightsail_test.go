package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/lightsail"
	lightsailtypes "github.com/aws/aws-sdk-go-v2/service/lightsail/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeLightsailClient is a hand-rolled lightsailInstancesAPI for unit-testing the
// scanner's pagination + error propagation without a live AWS client. pages is
// returned page-by-page (each call consumes the next page) and the NextPageToken
// is wired so the scanner loops through every page; err forces a GetInstances
// failure on the first call.
type fakeLightsailClient struct {
	pages []*lightsail.GetInstancesOutput
	calls int
	err   error
}

func (f *fakeLightsailClient) GetInstances(ctx context.Context, in *lightsail.GetInstancesInput, optFns ...func(*lightsail.Options)) (*lightsail.GetInstancesOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &lightsail.GetInstancesOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func lsStrptr(s string) *string { return &s }

// TestLightsailScanPaginates verifies the GetInstances PageToken loop: a fake that
// returns 2 pages (NextPageToken on page 1) must yield BOTH pages' instances as
// assets. Without the pagination loop, only the first page's instance survives —
// the commonest real-world drop in dense accounts.
func TestLightsailScanPaginates(t *testing.T) {
	client := &fakeLightsailClient{
		pages: []*lightsail.GetInstancesOutput{
			{
				Instances:     []lightsailtypes.Instance{{Name: lsStrptr("inst-page1")}},
				NextPageToken: lsStrptr("tok-page2"),
			},
			{
				Instances: []lightsailtypes.Instance{{Name: lsStrptr("inst-page2")}},
				// no NextPageToken -> last page
			},
		},
	}
	assets, err := LightsailScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.calls; c != 2 {
		t.Errorf("expected GetInstances to be called 2 times (paginated), got %d", c)
	}
	got := map[string]bool{}
	for _, a := range assets {
		got[a.ResourceID] = true
	}
	for _, want := range []string{"inst-page1", "inst-page2"} {
		if !got[want] {
			t.Errorf("expected instance %q from a paginated page to appear as an asset; assets=%v", want, got)
		}
	}
}

// TestLightsailScanErrorPropagates verifies the owner's incompleteness decision:
// a GetInstances failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success.
func TestLightsailScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform lightsail:GetInstances")
	client := &fakeLightsailClient{err: sentinel}
	assets, err := LightsailScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when GetInstances fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the GetInstances failure, got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets on a top-level List error, got %d", len(assets))
	}
}

// TestLightsailScanHonestPosture verifies the anti-false-safe contract: the
// Lightsail instance system disk's at-rest encryption is genuinely undetermined
// (no doc guarantee, no API field). The scanner MUST emit PostureUnknown with the
// "undetermined" marker and an explanatory note — NOT a fabricated SymmetricOnly
// all-clear and NOT NoEncryption (which would falsely allege the disk is plaintext).
func TestLightsailScanHonestPosture(t *testing.T) {
	client := &fakeLightsailClient{
		pages: []*lightsail.GetInstancesOutput{
			{Instances: []lightsailtypes.Instance{{Name: lsStrptr("inst-1")}}},
		},
	}
	assets, err := LightsailScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected exactly 1 asset, got %d", len(assets))
	}
	a := assets[0]
	if a.ResourceType != "AWS::Lightsail::Instance" {
		t.Errorf("expected resourceType AWS::Lightsail::Instance, got %q", a.ResourceType)
	}
	if p := a.Properties["posture"]; p != string(models.PostureUnknown) {
		t.Errorf("expected posture %q (honest undetermined), got %q", models.PostureUnknown, p)
	}
	if p := a.Properties["posture"]; p == string(models.PostureSymmetricOnly) {
		t.Errorf("posture must NOT be a fabricated SymmetricOnly all-clear")
	}
	if p := a.Properties["posture"]; p == string(models.PostureNoEncryption) {
		t.Errorf("posture must NOT be NoEncryption — that would falsely allege a plaintext disk")
	}
	if v := a.Properties["atRestEncryption"]; v != "undetermined" {
		t.Errorf("expected atRestEncryption=undetermined, got %q", v)
	}
	if a.Properties["note"] == "" {
		t.Error("expected an explanatory note documenting why the at-rest state is undetermined")
	}
}

// TestLightsailScanSkipsNilName verifies instances with a nil Name are skipped
// (no panic, no empty-ID asset).
func TestLightsailScanSkipsNilName(t *testing.T) {
	client := &fakeLightsailClient{
		pages: []*lightsail.GetInstancesOutput{
			{Instances: []lightsailtypes.Instance{{Name: nil}, {Name: lsStrptr("inst-ok")}}},
		},
	}
	assets, err := LightsailScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 1 || assets[0].ResourceID != "inst-ok" {
		t.Errorf("expected only the named instance to yield an asset, got %+v", assets)
	}
}
