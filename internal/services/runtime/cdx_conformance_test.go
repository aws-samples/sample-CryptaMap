package runtime

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/aws-samples/cryptamap/internal/output"
)

// TestCloudTrailEvidenceScanner_CBOMSchemaConformance drives the REAL scan() core
// of the CloudTrail runtime-evidence scanner through the official CycloneDX 1.7
// schema validator using synthetic CloudTrail events (no live AWS account). This
// scanner is the highest schema-shape risk in the runtime package because it
// emits BOTH an algorithm-evidence asset (Sign/Encrypt primitives) AND a TLS
// transit asset whose protocolProperties carry the observed cipherSuite +
// keyExchange group — protocol type / cipherSuites are exactly where
// CycloneDX-shape bugs live. A schema FAILURE here is a REAL output bug.
func TestCloudTrailEvidenceScanner_CBOMSchemaConformance(t *testing.T) {
	if err := output.ValidateCBOMBytes([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)); err != nil {
		t.Skipf("vendored CDX schema unavailable, skipping conformance: %v", err)
	}

	// Pass 1 (algorithm evidence) filters by eventName; pass 2 (PQ-TLS) is
	// unfiltered. The fake returns the Sign event only on a "Sign"-filtered call
	// and the PQ-TLS event only on an unfiltered call, so both passes emit >=1
	// asset and the combined CBOM is validated.
	const signEvent = `{"eventName":"Sign","requestParameters":{"keyId":"abc","signingAlgorithm":"ML_DSA_SHAKE_256"}}`
	const tlsEvent = `{"eventSource":"secretsmanager.amazonaws.com","userIdentity":{"type":"IAMUser"},"tlsDetails":{"tlsVersion":"TLSv1.3","cipherSuite":"TLS_AES_128_GCM_SHA256","clientProvidedHostHeader":"secretsmanager.us-east-1.amazonaws.com","keyExchange":"X25519MLKEM768"}}`

	client := &fakeCloudTrailClient{
		filteredEvents:  map[string]string{"Sign": signEvent},
		unfilteredEvent: tlsEvent,
	}

	assets, err := CloudTrailEvidenceScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(assets) == 0 {
		t.Fatal("expected at least one asset (algorithm-evidence + PQ-TLS)")
	}
	if verr := output.ValidateAssetsCBOM(assets); verr != nil {
		t.Fatalf("CBOM failed CycloneDX 1.7 schema validation: %v", verr)
	}
}

// fakeCloudTrailClient is a hand-rolled cloudTrailEvidenceAPI. For a call that
// filters on an event name present in filteredEvents it returns that one event;
// for an unfiltered call (pass 2) it returns the single unfilteredEvent. Each
// canned event is returned only once (no NextToken) so pagination terminates.
type fakeCloudTrailClient struct {
	filteredEvents  map[string]string // eventName -> CloudTrailEvent JSON
	unfilteredEvent string            // CloudTrailEvent JSON for the unfiltered TLS pass

	servedFiltered   map[string]bool
	servedUnfiltered bool
}

func (f *fakeCloudTrailClient) LookupEvents(ctx context.Context, in *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	// Determine the event-name filter, if any.
	var filterName string
	for _, attr := range in.LookupAttributes {
		if attr.AttributeKey == cttypes.LookupAttributeKeyEventName && attr.AttributeValue != nil {
			filterName = *attr.AttributeValue
		}
	}

	if filterName != "" {
		if f.servedFiltered == nil {
			f.servedFiltered = map[string]bool{}
		}
		blob, ok := f.filteredEvents[filterName]
		if !ok || f.servedFiltered[filterName] {
			return &cloudtrail.LookupEventsOutput{}, nil
		}
		f.servedFiltered[filterName] = true
		return &cloudtrail.LookupEventsOutput{
			Events: []cttypes.Event{{CloudTrailEvent: aws.String(blob)}},
		}, nil
	}

	// Unfiltered call (pass 2).
	if f.servedUnfiltered || f.unfilteredEvent == "" {
		return &cloudtrail.LookupEventsOutput{}, nil
	}
	f.servedUnfiltered = true
	return &cloudtrail.LookupEventsOutput{
		Events: []cttypes.Event{{CloudTrailEvent: aws.String(f.unfilteredEvent)}},
	}, nil
}
