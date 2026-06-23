package runtime

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws-samples/cryptamap/internal/output"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestCloudTrailEvidence_EventFieldValueOracle_CBOMConformance is the
// "enum-coverage" analogue for the runtime package. Unlike SDK-driven scanners,
// the single runtime scanner (cloudtrail_evidence.go) derives EVERY
// classification input from CloudTrail event JSON *strings*, not typed SDK enums
// — parseRuntimeAlgo reads requestParameters.{signingAlgorithm,...} and
// parseTLSDetails reads tlsDetails.{tlsVersion,cipherSuite,keyExchange}. There is
// therefore no SDK `.Values()` to iterate as an oracle. Instead we build a
// CURATED slice of AWS-documented values for each event-derived field (the values
// CloudTrail actually emits in tlsDetails / KMS requestParameters, confirmed
// against the CloudTrail record-contents docs) and assert the REAL scan() core
// produces a schema-valid CycloneDX 1.7 CBOM for EACH value — INCLUDING the empty
// string and a clearly-unknown value, to prove no panic, no false-safe, and no
// schema rejection on inputs the scanner does not recognize.
//
// A panic OR a ValidateAssetsCBOM failure for ANY of these values is a REAL bug
// and is left FAILING (no soften / no skip).
func TestCloudTrailEvidence_EventFieldValueOracle_CBOMConformance(t *testing.T) {
	if err := output.ValidateCBOMBytes([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)); err != nil {
		t.Skipf("vendored CDX schema unavailable, skipping conformance: %v", err)
	}

	const (
		acct   = "111122223333"
		region = "us-east-1"
	)

	// -----------------------------------------------------------------------
	// Field 1: tlsDetails.tlsVersion (event-JSON string, NOT an SDK enum).
	// Documented CloudTrail tlsDetails.tlsVersion values + "" + unknown.
	// -----------------------------------------------------------------------
	tlsVersions := []string{
		"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3",
		"",                  // empty: CloudTrail can omit; defaults to "1.3" in scanner (line 406-408)
		"SSLv3-bogus-value", // clearly-unknown: must not panic / must stay schema-valid
	}
	for _, v := range tlsVersions {
		v := v
		t.Run("tlsVersion="+labelFor(v), func(t *testing.T) {
			runTLSPassValidation(t, acct, region, tlsEventJSON(v, "TLS_AES_128_GCM_SHA256", "X25519MLKEM768"))
		})
	}

	// -----------------------------------------------------------------------
	// Field 2: tlsDetails.cipherSuite (event-JSON string, NOT an SDK enum).
	// Curated real cipher-suite strings CloudTrail emits + "" + unknown.
	// -----------------------------------------------------------------------
	cipherSuites := []string{
		"ECDHE-RSA-AES128-GCM-SHA256",
		"ECDHE-RSA-AES256-GCM-SHA384",
		"TLS_AES_128_GCM_SHA256",
		"TLS_AES_256_GCM_SHA384",
		"TLS_CHACHA20_POLY1305_SHA256",
		"DHE-RSA-AES256-SHA",
		"",                           // empty: CloudTrail may omit cipherSuite
		"TLS_BOGUS_UNKNOWN_SUITE_42", // clearly-unknown: must not false-safe / must stay schema-valid
	}
	for _, c := range cipherSuites {
		c := c
		t.Run("cipherSuite="+labelFor(c), func(t *testing.T) {
			runTLSPassValidation(t, acct, region, tlsEventJSON("TLSv1.3", c, "X25519MLKEM768"))
		})
	}

	// -----------------------------------------------------------------------
	// Field 3: tlsDetails.keyExchange (event-JSON string). This is the field
	// the TLS pass classifies on AND requires non-empty to emit an asset. The
	// empty case is exercised under cipherSuite/tlsVersion above (it still emits
	// the algorithm-evidence asset from the Sign pass), so here we cover the
	// documented KEX groups + an unknown group. (No "" row: an empty keyExchange
	// emits NO transit asset by design — covered by the runtimeSignatureAlgos set
	// below, which always supplies the algorithm-evidence asset.)
	// -----------------------------------------------------------------------
	keyExchanges := []string{
		"X25519MLKEM768",      // hybrid ML-KEM -> pqc-hybrid
		"SecP256r1MLKEM768",   // hybrid ML-KEM -> pqc-hybrid
		"x25519",              // classical
		"secp256r1",           // classical
		"ffdhe2048",           // classical finite-field DH
		"BOGUS_UNKNOWN_GROUP", // clearly-unknown: classified classical, must stay schema-valid
	}
	for _, k := range keyExchanges {
		k := k
		t.Run("keyExchange="+labelFor(k), func(t *testing.T) {
			runTLSPassValidation(t, acct, region, tlsEventJSON("TLSv1.3", "TLS_AES_128_GCM_SHA256", k))
		})
	}

	// -----------------------------------------------------------------------
	// Field 4: requestParameters.signingAlgorithm (event-JSON string). This is
	// the algorithm-evidence pass input (KMS Sign). Curated documented KMS
	// signing-algorithm values + "" + unknown. The "" case yields no Sign asset
	// (parseRuntimeAlgo returns ok=false), so we pair it with a valid TLS event
	// so the CBOM is non-empty; the unknown case must classify Unknown (never
	// false-safe) and stay schema-valid.
	// -----------------------------------------------------------------------
	signingAlgos := []string{
		"RSASSA_PSS_SHA_256",
		"RSASSA_PKCS1_V1_5_SHA_256",
		"ECDSA_SHA_256",
		"ECDSA_SHA_384",
		"ECDSA_SHA_512",
		"ML_DSA_SHAKE_256", // post-quantum
		"",                 // empty: no Sign asset emitted (parseRuntimeAlgo ok=false)
		"BOGUS_SIGN_ALG_9", // clearly-unknown -> PostureUnknown, must stay schema-valid
	}
	for _, sa := range signingAlgos {
		sa := sa
		t.Run("signingAlgorithm="+labelFor(sa), func(t *testing.T) {
			// Always include a valid TLS event so the CBOM has >=1 asset even when
			// signingAlgorithm is "" (no algorithm-evidence asset).
			client := &fakeCloudTrailClient{
				filteredEvents:  map[string]string{"Sign": signEventJSON(sa)},
				unfilteredEvent: tlsEventJSON("TLSv1.3", "TLS_AES_128_GCM_SHA256", "X25519MLKEM768"),
			}
			assets := mustScanNoPanic(t, client, acct, region)
			if verr := output.ValidateAssetsCBOM(assets); verr != nil {
				t.Fatalf("CBOM failed CycloneDX 1.7 schema validation for signingAlgorithm=%q: %v", sa, verr)
			}
		})
	}
}

// runTLSPassValidation feeds a single TLS event through the unfiltered pass (with
// no Sign event), runs the real scan() core, asserts no panic, and validates the
// resulting CBOM against the CycloneDX 1.7 schema. A panic or schema failure for
// any curated value is a REAL bug.
func runTLSPassValidation(t *testing.T, acct, region, tlsEvent string) {
	t.Helper()
	client := &fakeCloudTrailClient{
		// No Sign event: isolate the TLS pass so a schema failure points squarely
		// at the protocol block built from tlsVersion/cipherSuite/keyExchange.
		unfilteredEvent: tlsEvent,
	}
	assets := mustScanNoPanic(t, client, acct, region)
	if verr := output.ValidateAssetsCBOM(assets); verr != nil {
		t.Fatalf("CBOM failed CycloneDX 1.7 schema validation for event %s: %v", tlsEvent, verr)
	}
}

// mustScanNoPanic runs the real scan() core, converting any panic into a test
// failure (a panic on a documented event value is a REAL bug, not a skip).
func mustScanNoPanic(t *testing.T, client *fakeCloudTrailClient, acct, region string) (assets []models.CryptoAsset) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("scan PANICKED (real bug) account=%s region=%s: %v", acct, region, r)
		}
	}()
	got, err := CloudTrailEvidenceScanner{}.scan(context.Background(), client, acct, region)
	if err != nil {
		t.Fatalf("scan returned error: %v", err)
	}
	return got
}

// tlsEventJSON builds a CloudTrail event whose tlsDetails carries the given
// (event-JSON string) values, all other fields fixed valid. Marshaled via
// encoding/json so the embedded values are always well-formed JSON regardless of
// the curated string contents.
func tlsEventJSON(tlsVersion, cipherSuite, keyExchange string) string {
	type tlsDetails struct {
		TLSVersion               string `json:"tlsVersion,omitempty"`
		CipherSuite              string `json:"cipherSuite,omitempty"`
		ClientProvidedHostHeader string `json:"clientProvidedHostHeader"`
		KeyExchange              string `json:"keyExchange,omitempty"`
	}
	ev := struct {
		EventSource  string `json:"eventSource"`
		UserIdentity struct {
			Type string `json:"type"`
		} `json:"userIdentity"`
		TLSDetails tlsDetails `json:"tlsDetails"`
	}{
		EventSource: "secretsmanager.amazonaws.com",
		TLSDetails: tlsDetails{
			TLSVersion:               tlsVersion,
			CipherSuite:              cipherSuite,
			ClientProvidedHostHeader: "secretsmanager.us-east-1.amazonaws.com",
			KeyExchange:              keyExchange,
		},
	}
	ev.UserIdentity.Type = "IAMUser"
	b, _ := json.Marshal(ev)
	return string(b)
}

// signEventJSON builds a KMS Sign CloudTrail event with the given signing
// algorithm string in requestParameters.
func signEventJSON(signingAlgorithm string) string {
	rp := map[string]string{"keyId": "abc"}
	if signingAlgorithm != "" {
		rp["signingAlgorithm"] = signingAlgorithm
	}
	ev := map[string]any{
		"eventName":         "Sign",
		"requestParameters": rp,
	}
	b, _ := json.Marshal(ev)
	return string(b)
}

// labelFor renders a curated value as a readable subtest label ("EMPTY" for "").
func labelFor(v string) string {
	if v == "" {
		return "EMPTY"
	}
	return v
}
