package sdkpqc

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// ec2ssmFakeClient is a hand-rolled ssmInstanceInfoAPI for unit-testing the
// scanner's pagination + error propagation without a live AWS client. pages is
// returned page-by-page (each call consumes the next page) and the NextToken is
// wired so the scanner loops through every page; err forces a top-level
// DescribeInstanceInformation failure.
type ec2ssmFakeClient struct {
	pages []*ssm.DescribeInstanceInformationOutput
	calls int
	err   error
}

func (f *ec2ssmFakeClient) DescribeInstanceInformation(ctx context.Context, in *ssm.DescribeInstanceInformationInput, optFns ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &ssm.DescribeInstanceInformationOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func ec2ssmStrptr(s string) *string { return &s }

// ec2ssmAssetByID returns the asset with the given ResourceID, or nil.
func ec2ssmAssetByID(assets []models.CryptoAsset, id string) *models.CryptoAsset {
	for i := range assets {
		if assets[i].ResourceID == id {
			return &assets[i]
		}
	}
	return nil
}

// ec2ssmPostureOf returns the posture property value stamped on the asset, or "".
func ec2ssmPostureOf(a *models.CryptoAsset) string {
	if a == nil {
		return ""
	}
	return a.Properties["posture"]
}

// TestEC2SSMScanPaginates verifies the DescribeInstanceInformation NextToken
// loop: a fake that returns 2 pages (NextToken on page 1) must yield BOTH pages'
// instances as assets. Without the pagination loop, only the first page's
// instance survives, silently dropping managed instances in dense accounts.
func TestEC2SSMScanPaginates(t *testing.T) {
	client := &ec2ssmFakeClient{
		pages: []*ssm.DescribeInstanceInformationOutput{
			{
				InstanceInformationList: []ssmtypes.InstanceInformation{
					{InstanceId: ec2ssmStrptr("i-page1")},
				},
				NextToken: ec2ssmStrptr("tok-page2"),
			},
			{
				InstanceInformationList: []ssmtypes.InstanceInformation{
					{InstanceId: ec2ssmStrptr("i-page2")},
				},
				// no NextToken -> last page
			},
		},
	}
	assets, err := EC2SSMScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Errorf("expected DescribeInstanceInformation to be called 2 times (paginated), got %d", client.calls)
	}
	for _, want := range []string{"i-page1", "i-page2"} {
		if ec2ssmAssetByID(assets, want) == nil {
			t.Errorf("expected instance %q from a paginated page to appear as an asset; got %d assets", want, len(assets))
		}
	}
}

// TestEC2SSMScanErrorPropagates verifies the incompleteness decision: a
// DescribeInstanceInformation failure (denied/rate-limited) must make the scan
// VISIBLY incomplete by returning a non-nil error — NOT a silent empty success.
func TestEC2SSMScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform ssm:DescribeInstanceInformation")
	client := &ec2ssmFakeClient{err: sentinel}
	assets, err := EC2SSMScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeInstanceInformation fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeInstanceInformation failure, got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets on a top-level error, got %d", len(assets))
	}
}

// TestEC2SSMScanSkipsNilInstanceID verifies that an instance with a nil
// InstanceId is skipped (cannot key an asset) rather than panicking, while
// valid instances on the same page are still emitted — no silent drop of the
// valid neighbor.
func TestEC2SSMScanSkipsNilInstanceID(t *testing.T) {
	client := &ec2ssmFakeClient{
		pages: []*ssm.DescribeInstanceInformationOutput{
			{
				InstanceInformationList: []ssmtypes.InstanceInformation{
					{InstanceId: nil},
					{InstanceId: ec2ssmStrptr("i-valid")},
				},
			},
		},
	}
	assets, err := EC2SSMScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected exactly 1 asset (nil-ID skipped, valid kept), got %d", len(assets))
	}
	if ec2ssmAssetByID(assets, "i-valid") == nil {
		t.Errorf("expected the valid instance %q to survive alongside a skipped nil-ID instance", "i-valid")
	}
}

// TestEC2SSMScanHonestyPosture verifies the honesty posture for this SDK/library
// scanner: DescribeInstanceInformation exposes NO TLS version/cipher for the
// instance's own outbound crypto, so the posture MUST be Unknown — never a
// fabricated classical or a no-encryption verdict. The only crypto claim is the
// doc-backed control-plane TLS-1.2 floor (protocol=tls, version 1.2, NO cipher
// suite, stamped source=aws-doc).
func TestEC2SSMScanHonestyPosture(t *testing.T) {
	client := &ec2ssmFakeClient{
		pages: []*ssm.DescribeInstanceInformationOutput{
			{
				InstanceInformationList: []ssmtypes.InstanceInformation{
					{
						InstanceId:      ec2ssmStrptr("i-honest"),
						PlatformType:    ssmtypes.PlatformTypeLinux,
						PlatformName:    ec2ssmStrptr("Amazon Linux"),
						PlatformVersion: ec2ssmStrptr("2023"),
						AgentVersion:    ec2ssmStrptr("3.2.0.0"),
						PingStatus:      ssmtypes.PingStatusOnline,
					},
				},
			},
		},
	}
	assets, err := EC2SSMScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a := ec2ssmAssetByID(assets, "i-honest")
	if a == nil {
		t.Fatal("expected instance i-honest to be emitted as an asset")
	}

	// Posture must be Unknown — the instance's own outbound crypto is not
	// observable here. It must NOT masquerade as classical or no-encryption.
	if p := ec2ssmPostureOf(a); p != string(models.PostureUnknown) {
		t.Errorf("expected posture %q (own crypto not observable), got %q", models.PostureUnknown, p)
	}
	if p := ec2ssmPostureOf(a); p == string(models.PostureNonPQCClassical) {
		t.Errorf("posture must NOT be fabricated classical %q for an unobservable instance", models.PostureNonPQCClassical)
	}

	// The only crypto claim is the control-plane floor: protocol=tls, version 1.2.
	if a.CryptoProps.AssetType != models.AssetTypeProtocol {
		t.Errorf("expected assetType %q, got %q", models.AssetTypeProtocol, a.CryptoProps.AssetType)
	}
	if a.CryptoProps.ProtocolProperties == nil {
		t.Fatal("expected protocolProperties to carry the control-plane TLS floor, got nil")
	}
	if v := a.CryptoProps.ProtocolProperties.Version; v != "1.2" {
		t.Errorf("expected documented control-plane TLS floor 1.2, got %q", v)
	}
	if typ := a.CryptoProps.ProtocolProperties.Type; typ != "tls" {
		t.Errorf("expected protocol type \"tls\", got %q", typ)
	}
	// No AWS doc names a guaranteed cipher suite, so none must be invented.
	if len(a.CryptoProps.ProtocolProperties.CipherSuites) != 0 {
		t.Errorf("expected NO cipher suite invented (none doc-guaranteed), got %v", a.CryptoProps.ProtocolProperties.CipherSuites)
	}

	// Metadata round-trips so downstream evidence is intact.
	if a.Properties["platformType"] != string(ssmtypes.PlatformTypeLinux) {
		t.Errorf("expected platformType %q, got %q", ssmtypes.PlatformTypeLinux, a.Properties["platformType"])
	}
}
