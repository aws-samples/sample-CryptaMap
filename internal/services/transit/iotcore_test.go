package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iot"
	iottypes "github.com/aws/aws-sdk-go-v2/service/iot/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

func iotcoreStrptr(s string) *string { return &s }

// fakeIoTCoreClient is a hand-rolled iotCoreAPI for unit-testing the scanner's
// pagination + error propagation + classification without a live AWS client.
//   - dcPages is returned page-by-page from ListDomainConfigurations (each call
//     consumes the next page; the Marker/NextMarker is wired so the scanner loops
//     through every page).
//   - describeByName maps a DomainConfigurationName to its
//     DescribeDomainConfiguration output (the implicit "iot:Data-ATS" endpoint is
//     described too unless it appeared in the list pages).
//   - dcErr forces a ListDomainConfigurations failure; describeErr forces a
//     DescribeDomainConfiguration failure; thingsOut/thingsErr drive ListThings.
type fakeIoTCoreClient struct {
	dcPages        []*iot.ListDomainConfigurationsOutput
	dcCalls        int
	dcErr          error
	describeByName map[string]*iot.DescribeDomainConfigurationOutput
	describeErr    error
	describeCalls  []string
	thingsOut      *iot.ListThingsOutput
	thingsErr      error
	thingsCalls    int
}

func (f *fakeIoTCoreClient) ListDomainConfigurations(ctx context.Context, in *iot.ListDomainConfigurationsInput, optFns ...func(*iot.Options)) (*iot.ListDomainConfigurationsOutput, error) {
	if f.dcErr != nil {
		return nil, f.dcErr
	}
	if f.dcCalls >= len(f.dcPages) {
		return &iot.ListDomainConfigurationsOutput{}, nil
	}
	out := f.dcPages[f.dcCalls]
	f.dcCalls++
	return out, nil
}

func (f *fakeIoTCoreClient) DescribeDomainConfiguration(ctx context.Context, in *iot.DescribeDomainConfigurationInput, optFns ...func(*iot.Options)) (*iot.DescribeDomainConfigurationOutput, error) {
	name := ""
	if in.DomainConfigurationName != nil {
		name = *in.DomainConfigurationName
	}
	f.describeCalls = append(f.describeCalls, name)
	if f.describeErr != nil {
		return nil, f.describeErr
	}
	if out, ok := f.describeByName[name]; ok {
		return out, nil
	}
	// No stub for this name -> simulate "cannot describe" (AWS error path).
	return nil, errors.New("ResourceNotFoundException: " + name)
}

func (f *fakeIoTCoreClient) ListThings(ctx context.Context, in *iot.ListThingsInput, optFns ...func(*iot.Options)) (*iot.ListThingsOutput, error) {
	f.thingsCalls++
	if f.thingsErr != nil {
		return nil, f.thingsErr
	}
	if f.thingsOut != nil {
		return f.thingsOut, nil
	}
	return &iot.ListThingsOutput{}, nil
}

// iotcoreDCPolicy builds a DescribeDomainConfiguration output with the given TLS
// security policy (empty string => no TlsConfig, exercising the doc-default path).
func iotcoreDCPolicy(policy string) *iot.DescribeDomainConfigurationOutput {
	out := &iot.DescribeDomainConfigurationOutput{}
	if policy != "" {
		out.TlsConfig = &iottypes.TlsConfig{SecurityPolicy: iotcoreStrptr(policy)}
	}
	return out
}

// iotcoreAssetByID returns the first asset with the given ResourceID, or false.
func iotcoreAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// TestIoTCoreScanPaginatesDomainConfigs verifies the ListDomainConfigurations
// Marker loop: a fake returning 2 pages (NextMarker on page 1) must describe and
// emit BOTH pages' domain configurations. Without the pagination restore, only the
// first page's config would survive.
func TestIoTCoreScanPaginatesDomainConfigs(t *testing.T) {
	client := &fakeIoTCoreClient{
		dcPages: []*iot.ListDomainConfigurationsOutput{
			{
				DomainConfigurations: []iottypes.DomainConfigurationSummary{
					{DomainConfigurationName: iotcoreStrptr("dc-page1")},
				},
				NextMarker: iotcoreStrptr("marker-page2"),
			},
			{
				DomainConfigurations: []iottypes.DomainConfigurationSummary{
					{DomainConfigurationName: iotcoreStrptr("dc-page2")},
				},
				// no NextMarker -> last page
			},
		},
		describeByName: map[string]*iot.DescribeDomainConfigurationOutput{
			"dc-page1":     iotcoreDCPolicy("IoTSecurityPolicy_TLS13_1_2_2022_10"),
			"dc-page2":     iotcoreDCPolicy("IoTSecurityPolicy_TLS12_1_2_2019_07"),
			"iot:Data-ATS": iotcoreDCPolicy("IoTSecurityPolicy_TLS13_1_2_2022_10"),
		},
		thingsOut: &iot.ListThingsOutput{},
	}
	assets, err := IoTCoreScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.dcCalls != 2 {
		t.Errorf("expected ListDomainConfigurations to be called 2 times (paginated), got %d", client.dcCalls)
	}
	for _, want := range []string{"dc-page1", "dc-page2"} {
		if _, ok := iotcoreAssetByID(assets, want); !ok {
			t.Errorf("expected domain config %q from a paginated page to appear as an asset", want)
		}
	}
}

// TestIoTCoreScanListDomainConfigsErrorDoesNotBlockEndpoint verifies the original
// behavior: a ListDomainConfigurations failure breaks the loop (logged, not
// returned) but the implicit "iot:Data-ATS" endpoint and Things are still
// attempted, so a transient list failure does not produce a silent empty success
// when other signal exists.
func TestIoTCoreScanListDomainConfigsErrorDoesNotBlockEndpoint(t *testing.T) {
	client := &fakeIoTCoreClient{
		dcErr: errors.New("ThrottlingException: rate exceeded"),
		describeByName: map[string]*iot.DescribeDomainConfigurationOutput{
			"iot:Data-ATS": iotcoreDCPolicy("IoTSecurityPolicy_TLS13_1_2_2022_10"),
		},
		thingsOut: &iot.ListThingsOutput{},
	}
	assets, err := IoTCoreScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan should not return an error when ListDomainConfigurations fails but the endpoint is describable: %v", err)
	}
	if _, ok := iotcoreAssetByID(assets, "iot:Data-ATS"); !ok {
		t.Errorf("expected the implicit iot:Data-ATS endpoint to still be emitted after a ListDomainConfigurations failure; assets=%v", assets)
	}
}

// TestIoTCoreScanListThingsErrorPropagatesWhenNoOtherSignal verifies the
// no-silent-drop posture: when Things is the only would-be signal (no domain
// configs, endpoint not describable) a ListThings failure is surfaced as a
// non-nil error rather than a clean empty success.
func TestIoTCoreScanListThingsErrorPropagatesWhenNoOtherSignal(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform iot:ListThings")
	client := &fakeIoTCoreClient{
		dcPages:        []*iot.ListDomainConfigurationsOutput{{}},
		describeByName: map[string]*iot.DescribeDomainConfigurationOutput{
			// no "iot:Data-ATS" stub -> describe returns error -> no asset
		},
		thingsErr: sentinel,
	}
	_, err := IoTCoreScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListThings fails and nothing else was found (silent empty success would mask a denied scan)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListThings failure, got: %v", err)
	}
}

// TestIoTCoreScanListThingsErrorDoesNotDropDomainConfigs verifies the inverse: a
// ListThings failure must NOT drop already-collected domain-config assets — those
// are the primary signal. The error is logged and the assets returned.
func TestIoTCoreScanListThingsErrorDoesNotDropDomainConfigs(t *testing.T) {
	client := &fakeIoTCoreClient{
		dcPages: []*iot.ListDomainConfigurationsOutput{
			{DomainConfigurations: []iottypes.DomainConfigurationSummary{
				{DomainConfigurationName: iotcoreStrptr("dc-keep")},
			}},
		},
		describeByName: map[string]*iot.DescribeDomainConfigurationOutput{
			"dc-keep":      iotcoreDCPolicy("IoTSecurityPolicy_TLS13_1_2_2022_10"),
			"iot:Data-ATS": iotcoreDCPolicy("IoTSecurityPolicy_TLS13_1_2_2022_10"),
		},
		thingsErr: errors.New("AccessDeniedException"),
	}
	assets, err := IoTCoreScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("ListThings failure must not error out when domain-config assets exist: %v", err)
	}
	if _, ok := iotcoreAssetByID(assets, "dc-keep"); !ok {
		t.Errorf("expected domain-config asset dc-keep to survive a ListThings failure; assets=%v", assets)
	}
}

// TestIoTCoreClassificationHonesty asserts the domain's honesty posture:
//   - An observed TLS 1.3 policy => TLS 1.3 / NonPQCClassical, stamped observed,
//     and is NEVER misreported as "no encryption".
//   - The legacy-vintage TLS12_1_0 cipher set negotiates under TLS 1.2 (IoT has no
//     TLS 1.0/1.1 endpoint) and must NOT be flagged as legacy TLS 1.0 — that was a
//     known false-alarm.
//   - An empty/missing TlsConfig falls back to the AWS-doc default (TLS 1.3) but is
//     tagged as a doc-fact, not asserted observed.
//   - Things stay inventory-only with no fabricated TLS posture.
func TestIoTCoreClassificationHonesty(t *testing.T) {
	client := &fakeIoTCoreClient{
		dcPages: []*iot.ListDomainConfigurationsOutput{
			{DomainConfigurations: []iottypes.DomainConfigurationSummary{
				{DomainConfigurationName: iotcoreStrptr("dc-tls13")},
				{DomainConfigurationName: iotcoreStrptr("dc-tls12-vintage")},
				{DomainConfigurationName: iotcoreStrptr("dc-no-policy")},
			}},
		},
		describeByName: map[string]*iot.DescribeDomainConfigurationOutput{
			"dc-tls13":         iotcoreDCPolicy("IoTSecurityPolicy_TLS13_1_2_2022_10"),
			"dc-tls12-vintage": iotcoreDCPolicy("IoTSecurityPolicy_TLS12_1_0_2022_10"),
			"dc-no-policy":     iotcoreDCPolicy(""), // no TlsConfig
			"iot:Data-ATS":     iotcoreDCPolicy("IoTSecurityPolicy_TLS13_1_2_2022_10"),
		},
		thingsOut: &iot.ListThingsOutput{
			Things: []iottypes.ThingAttribute{
				{ThingName: iotcoreStrptr("thing-1")},
			},
		},
	}
	assets, err := IoTCoreScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}

	// Observed TLS 1.3 config.
	tls13, ok := iotcoreAssetByID(assets, "dc-tls13")
	if !ok {
		t.Fatal("expected dc-tls13 asset")
	}
	if tls13.Properties["posture"] != string(models.PostureNonPQCClassical) {
		t.Errorf("dc-tls13: expected posture %q, got %q", models.PostureNonPQCClassical, tls13.Properties["posture"])
	}
	if tls13.Properties["posture"] == string(models.PostureNoEncryption) {
		t.Error("dc-tls13: a TLS-1.3 IoT endpoint must NEVER be reported as no-encryption")
	}
	if tls13.Properties["securityPolicy"] != "IoTSecurityPolicy_TLS13_1_2_2022_10" {
		t.Errorf("dc-tls13: expected observed securityPolicy recorded, got %q", tls13.Properties["securityPolicy"])
	}

	// Legacy-vintage TLS12_1_0 cipher set must classify as TLS 1.2, NOT legacy 1.0.
	vintage, ok := iotcoreAssetByID(assets, "dc-tls12-vintage")
	if !ok {
		t.Fatal("expected dc-tls12-vintage asset")
	}
	if vintage.Properties["posture"] == string(models.PostureLegacyTLS) {
		t.Error("dc-tls12-vintage: TLS12_1_0 is a TLS-1.2 cipher-set vintage, NOT legacy TLS 1.0 — must not be flagged as legacy (false-alarm)")
	}
	if vintage.Properties["posture"] != string(models.PostureNonPQCClassical) {
		t.Errorf("dc-tls12-vintage: expected posture %q, got %q", models.PostureNonPQCClassical, vintage.Properties["posture"])
	}
	if mv := vintage.CryptoProps.ProtocolProperties; mv == nil || mv.TLSMinVersion != "1.2" {
		t.Errorf("dc-tls12-vintage: expected TLS floor 1.2, got %+v", vintage.CryptoProps.ProtocolProperties)
	}

	// No-policy config: doc-default 1.3, not asserted observed (no securityPolicy prop).
	noPol, ok := iotcoreAssetByID(assets, "dc-no-policy")
	if !ok {
		t.Fatal("expected dc-no-policy asset")
	}
	if noPol.Properties["posture"] != string(models.PostureNonPQCClassical) {
		t.Errorf("dc-no-policy: expected doc-default posture %q, got %q", models.PostureNonPQCClassical, noPol.Properties["posture"])
	}
	if noPol.Properties["securityPolicy"] != "" {
		t.Errorf("dc-no-policy: an unobserved (doc-default) config must NOT record an observed securityPolicy, got %q", noPol.Properties["securityPolicy"])
	}

	// Thing stays inventory-only: no posture/TLS classification fabricated.
	thing, ok := iotcoreAssetByID(assets, "thing-1")
	if !ok {
		t.Fatal("expected thing-1 inventory asset")
	}
	if thing.ResourceType != "AWS::IoT::Thing" {
		t.Errorf("thing-1: expected AWS::IoT::Thing, got %q", thing.ResourceType)
	}
	if thing.Properties["inventory"] != "true" {
		t.Errorf("thing-1: expected inventory=true marker, got %q", thing.Properties["inventory"])
	}
	if thing.Properties["posture"] != "" {
		t.Errorf("thing-1: a Thing is not a TLS endpoint — no posture must be fabricated, got %q", thing.Properties["posture"])
	}
}
