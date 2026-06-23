package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/vpclattice"
	vltypes "github.com/aws/aws-sdk-go-v2/service/vpclattice/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeVPCLatticeClient is a hand-rolled vpcLatticeAPI for unit-testing the
// scanner's pagination + error propagation without a live AWS client.
// servicesPages is returned page-by-page (each ListServices call consumes the
// next page) with NextToken wired so the scanner loops. listenersByService maps
// a service Id to that service's listener pages (also paginated). servicesErr
// forces a top-level ListServices failure; listenersErr forces a per-service
// ListListeners failure.
type fakeVPCLatticeClient struct {
	servicesPages      []*vpclattice.ListServicesOutput
	servicesCalls      int
	servicesErr        error
	listenersByService map[string][]*vpclattice.ListListenersOutput
	listenersCalls     map[string]int
	listenersErr       error
	certByService      map[string]string
}

func (f *fakeVPCLatticeClient) ListServices(ctx context.Context, in *vpclattice.ListServicesInput, optFns ...func(*vpclattice.Options)) (*vpclattice.ListServicesOutput, error) {
	if f.servicesErr != nil {
		return nil, f.servicesErr
	}
	if f.servicesCalls >= len(f.servicesPages) {
		return &vpclattice.ListServicesOutput{}, nil
	}
	out := f.servicesPages[f.servicesCalls]
	f.servicesCalls++
	return out, nil
}

func (f *fakeVPCLatticeClient) GetService(ctx context.Context, in *vpclattice.GetServiceInput, optFns ...func(*vpclattice.Options)) (*vpclattice.GetServiceOutput, error) {
	out := &vpclattice.GetServiceOutput{}
	if in.ServiceIdentifier != nil {
		if arn, ok := f.certByService[*in.ServiceIdentifier]; ok && arn != "" {
			out.CertificateArn = vpclatticeStrptr(arn)
		}
	}
	return out, nil
}

func (f *fakeVPCLatticeClient) ListListeners(ctx context.Context, in *vpclattice.ListListenersInput, optFns ...func(*vpclattice.Options)) (*vpclattice.ListListenersOutput, error) {
	if f.listenersErr != nil {
		return nil, f.listenersErr
	}
	if in.ServiceIdentifier == nil {
		return &vpclattice.ListListenersOutput{}, nil
	}
	svc := *in.ServiceIdentifier
	if f.listenersCalls == nil {
		f.listenersCalls = map[string]int{}
	}
	pages := f.listenersByService[svc]
	idx := f.listenersCalls[svc]
	if idx >= len(pages) {
		return &vpclattice.ListListenersOutput{}, nil
	}
	f.listenersCalls[svc]++
	return pages[idx], nil
}

func vpclatticeStrptr(s string) *string { return &s }

// vpclatticeAssetByID returns the asset with the given ResourceID, or nil.
func vpclatticeAssetByID(assets []models.CryptoAsset, id string) *models.CryptoAsset {
	for i := range assets {
		if assets[i].ResourceID == id {
			return &assets[i]
		}
	}
	return nil
}

// vpclatticePostureOf reads the posture property stamped on an asset.
func vpclatticePostureOf(a *models.CryptoAsset) string {
	if a == nil {
		return ""
	}
	if v, ok := a.Properties["posture"]; ok {
		return v
	}
	return ""
}

// TestVPCLatticeScanPaginatesServicesAndListeners verifies BOTH NextToken loops:
// ListServices returns 2 pages, and each service's ListListeners also returns 2
// pages. Every listener across every page must surface as an asset. Without the
// pagination restore, later pages are silently dropped.
func TestVPCLatticeScanPaginatesServicesAndListeners(t *testing.T) {
	client := &fakeVPCLatticeClient{
		servicesPages: []*vpclattice.ListServicesOutput{
			{
				Items:     []vltypes.ServiceSummary{{Id: vpclatticeStrptr("svc-1")}},
				NextToken: vpclatticeStrptr("svc-tok-2"),
			},
			{
				Items: []vltypes.ServiceSummary{{Id: vpclatticeStrptr("svc-2")}},
			},
		},
		listenersByService: map[string][]*vpclattice.ListListenersOutput{
			"svc-1": {
				{
					Items: []vltypes.ListenerSummary{
						{Arn: vpclatticeStrptr("arn:l:svc1-listener1"), Protocol: vltypes.ListenerProtocolHttps},
					},
					NextToken: vpclatticeStrptr("l-tok-2"),
				},
				{
					Items: []vltypes.ListenerSummary{
						{Arn: vpclatticeStrptr("arn:l:svc1-listener2"), Protocol: vltypes.ListenerProtocolHttps},
					},
				},
			},
			"svc-2": {
				{
					Items: []vltypes.ListenerSummary{
						{Arn: vpclatticeStrptr("arn:l:svc2-listener1"), Protocol: vltypes.ListenerProtocolTlsPassthrough},
					},
				},
			},
		},
	}

	assets, err := VPCLatticeScanner{}.scan(context.Background(), client, newACMCertResolver(aws.Config{}), "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.servicesCalls != 2 {
		t.Errorf("expected ListServices to be called 2 times (paginated), got %d", client.servicesCalls)
	}
	if client.listenersCalls["svc-1"] != 2 {
		t.Errorf("expected ListListeners for svc-1 to be called 2 times (paginated), got %d", client.listenersCalls["svc-1"])
	}
	for _, want := range []string{"arn:l:svc1-listener1", "arn:l:svc1-listener2", "arn:l:svc2-listener1"} {
		if vpclatticeAssetByID(assets, want) == nil {
			t.Errorf("expected listener %q from a paginated page to appear as an asset; got %d assets", want, len(assets))
		}
	}
}

// TestVPCLatticeScanListServicesErrorPropagates verifies the incompleteness
// posture: a top-level ListServices failure (denied/throttled) must make the scan
// VISIBLY incomplete by returning a non-nil error wrapping the cause — NOT a
// silent empty success.
func TestVPCLatticeScanListServicesErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform vpc-lattice:ListServices")
	client := &fakeVPCLatticeClient{servicesErr: sentinel}

	assets, err := VPCLatticeScanner{}.scan(context.Background(), client, newACMCertResolver(aws.Config{}), "111122223333", "us-east-1")
	if err == nil {
		t.Fatalf("expected scan to return a non-nil error when ListServices fails, got nil with %d assets (silent empty success)", len(assets))
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListServices failure, got: %v", err)
	}
}

// TestVPCLatticeScanHonestyPosture verifies the domain honesty contract:
//   - an HTTPS listener -> NonPQCClassical (quantum-vulnerable handshake), NEVER
//     reported as no-encryption;
//   - an HTTP listener -> NoEncryption (a VERIFIED plaintext finding with a note),
//     NEVER masked as encrypted/clean.
func TestVPCLatticeScanHonestyPosture(t *testing.T) {
	client := &fakeVPCLatticeClient{
		servicesPages: []*vpclattice.ListServicesOutput{
			{Items: []vltypes.ServiceSummary{{Id: vpclatticeStrptr("svc-mix")}}},
		},
		listenersByService: map[string][]*vpclattice.ListListenersOutput{
			"svc-mix": {
				{
					Items: []vltypes.ListenerSummary{
						{Arn: vpclatticeStrptr("arn:l:https"), Protocol: vltypes.ListenerProtocolHttps},
						{Arn: vpclatticeStrptr("arn:l:http"), Protocol: vltypes.ListenerProtocolHttp},
					},
				},
			},
		},
		certByService: map[string]string{
			"svc-mix": "arn:aws:acm:us-east-1:111122223333:certificate/abc",
		},
	}

	assets, err := VPCLatticeScanner{}.scan(context.Background(), client, newACMCertResolver(aws.Config{}), "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}

	httpsAsset := vpclatticeAssetByID(assets, "arn:l:https")
	if httpsAsset == nil {
		t.Fatal("expected HTTPS listener to appear as an asset")
	}
	if p := vpclatticePostureOf(httpsAsset); p != string(models.PostureNonPQCClassical) {
		t.Errorf("HTTPS listener: expected posture NonPQCClassical, got %q", p)
	}
	if p := vpclatticePostureOf(httpsAsset); p == string(models.PostureNoEncryption) {
		t.Error("HTTPS listener must NOT be reported as NoEncryption (it terminates/forwards TLS)")
	}
	if got := httpsAsset.Properties["certificateArn"]; got == "" {
		t.Error("HTTPS listener: expected the resolved service certificateArn to be attached as evidence")
	}

	httpAsset := vpclatticeAssetByID(assets, "arn:l:http")
	if httpAsset == nil {
		t.Fatal("expected HTTP listener to appear as an asset")
	}
	if p := vpclatticePostureOf(httpAsset); p != string(models.PostureNoEncryption) {
		t.Errorf("HTTP listener: expected posture NoEncryption (verified plaintext), got %q", p)
	}
	if note := httpAsset.Properties["note"]; note == "" {
		t.Error("HTTP listener: expected an explanatory plaintext note, got empty")
	}
}
