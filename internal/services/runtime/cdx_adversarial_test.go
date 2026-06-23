package runtime

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/aws-samples/cryptamap/internal/output"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestCloudTrailEvidenceScanner_Adversarial hardens the CloudTrail runtime-evidence
// scanner against HOSTILE / future / malformed CloudTrail event JSON. The scanner
// is the highest schema-shape risk in the runtime package: it copies observed
// strings (signingAlgorithm, tlsVersion, cipherSuite, keyExchange) into CBOM
// fields (algorithmProperties, protocolProperties.cipherSuites[].name,
// keyExchangeGroup, version) without an enum mapping, so a future/garbage value
// could either (a) panic the parse/type-assert path or (b) break the official
// CycloneDX 1.7 schema once it is serialized.
//
// Contract asserted PER SUBTEST (and ONLY this):
//
//	(i)  scan() NEVER panics — a deferred recover() turns any panic into a
//	     t.Errorf with the triggering input + stack (we do not crash the run).
//	(ii) when scan() returns a non-empty asset slice, that slice MUST pass
//	     output.ValidateAssetsCBOM. 0 assets or a returned error on garbage is
//	     FINE — only a panic OR a schema failure on non-empty assets is a bug.
//
// The fake (fakeCloudTrailClient, defined in cdx_conformance_test.go) is reused
// verbatim: filteredEvents[eventName]=blob drives pass-1 (algorithm evidence,
// filtered by eventName) and unfilteredEvent=blob drives pass-2 (PQ-TLS).
func TestCloudTrailEvidenceScanner_Adversarial(t *testing.T) {
	if err := output.ValidateCBOMBytes([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)); err != nil {
		t.Skipf("vendored CDX schema unavailable, skipping adversarial conformance: %v", err)
	}

	const big = 10000 // 10k-char stress string length

	bigStr := strings.Repeat("A", big)

	// Each case sets either a filtered Sign event (pass-1 algorithm evidence)
	// and/or the unfiltered TLS event (pass-2 PQ-TLS). "Sign" is the event name
	// pass-1 filters on (it is first in cryptoEventNames and routes signingAlgorithm
	// -> AlgorithmName/KMSKeySpec). We also exercise Encrypt/GenerateDataKey to hit
	// the encryptionAlgorithm / keySpec branches of parseRuntimeAlgo + the KEM /
	// symmetric primitive selection in runtimeAlgoProps.
	cases := []struct {
		name     string
		filtered map[string]string
		unfilt   string
	}{
		// ---- malformed JSON (both passes must tolerate non-JSON gracefully) ----
		{name: "malformed_open_brace", filtered: map[string]string{"Sign": "{"}, unfilt: "{"},
		{name: "malformed_empty_string", filtered: map[string]string{"Sign": ""}, unfilt: ""},
		{name: "malformed_not_json", filtered: map[string]string{"Sign": "not json"}, unfilt: "not json"},
		{name: "malformed_truncated", filtered: map[string]string{"Sign": `{"requestParameters":{"signingAlgorithm":"ML`}, unfilt: `{"tlsDetails":{"keyExchange":"X25`},

		// ---- valid JSON but structurally empty / missing blocks ----
		{name: "empty_object", filtered: map[string]string{"Sign": "{}"}, unfilt: "{}"},
		{name: "missing_requestParameters", filtered: map[string]string{"Sign": `{"eventName":"Sign"}`}, unfilt: `{"eventSource":"kms.amazonaws.com"}`},
		{name: "missing_tlsDetails", unfilt: `{"eventSource":"kms.amazonaws.com","userIdentity":{"type":"IAMUser"}}`},
		{name: "null_tlsDetails", unfilt: `{"tlsDetails":null}`},
		{name: "null_requestParameters", filtered: map[string]string{"Sign": `{"requestParameters":null}`}},
		{name: "null_fields_in_blocks", filtered: map[string]string{"Sign": `{"requestParameters":{"signingAlgorithm":null,"keySpec":null}}`}, unfilt: `{"tlsDetails":{"tlsVersion":null,"cipherSuite":null,"keyExchange":null}}`},

		// ---- UNKNOWN / FUTURE signingAlgorithm (lands in AlgorithmName + KMSKeySpec) ----
		{name: "future_signingAlgo_ML_DSA_99", filtered: map[string]string{"Sign": `{"requestParameters":{"signingAlgorithm":"ML_DSA_99_FUTURE"}}`}},
		{name: "future_signingAlgo_FALCON", filtered: map[string]string{"Sign": `{"requestParameters":{"signingAlgorithm":"FALCON_1024"}}`}},
		{name: "empty_signingAlgo", filtered: map[string]string{"Sign": `{"requestParameters":{"signingAlgorithm":""}}`}},
		// encryptionAlgorithm + keySpec branches (KEM / symmetric primitive selection)
		{name: "future_encryptionAlgo", filtered: map[string]string{"Encrypt": `{"requestParameters":{"encryptionAlgorithm":"RSAES_FUTURE_9000"}}`}},
		{name: "future_keyspec_GDK", filtered: map[string]string{"GenerateDataKey": `{"requestParameters":{"keySpec":"AES_99999"}}`}},
		{name: "weird_keypairspec_GDKP", filtered: map[string]string{"GenerateDataKeyPair": `{"requestParameters":{"keyPairSpec":"ML_KEM_FUTURE"}}`}},

		// ---- UNKNOWN / FUTURE TLS fields (raw-copied into protocolProperties) ----
		{name: "future_tlsVersion", unfilt: `{"tlsDetails":{"tlsVersion":"TLSv9.9","cipherSuite":"TLS_AES_128_GCM_SHA256","keyExchange":"X25519MLKEM768"}}`},
		{name: "empty_tlsVersion_defaults", unfilt: `{"tlsDetails":{"tlsVersion":"","cipherSuite":"TLS_AES_128_GCM_SHA256","keyExchange":"X25519"}}`},
		{name: "future_cipherSuite", unfilt: `{"tlsDetails":{"tlsVersion":"TLSv1.3","cipherSuite":"TLS_FUTURE_PQC","keyExchange":"X25519MLKEM768"}}`},
		{name: "empty_cipherSuite", unfilt: `{"tlsDetails":{"tlsVersion":"TLSv1.3","cipherSuite":"","keyExchange":"X25519MLKEM768"}}`},
		{name: "future_keyExchange", unfilt: `{"tlsDetails":{"tlsVersion":"TLSv1.3","cipherSuite":"TLS_AES_128_GCM_SHA256","keyExchange":"MLKEM9999"}}`},
		// keyExchange empty -> pass-2 skips the event (emits nothing); still must not panic
		{name: "empty_keyExchange_skipped", unfilt: `{"tlsDetails":{"tlsVersion":"TLSv1.3","cipherSuite":"TLS_AES_128_GCM_SHA256","keyExchange":""}}`},

		// ---- 10k-char strings in every copied field ----
		{name: "huge_signingAlgo", filtered: map[string]string{"Sign": fmt.Sprintf(`{"requestParameters":{"signingAlgorithm":%q}}`, bigStr)}},
		{name: "huge_cipherSuite", unfilt: fmt.Sprintf(`{"tlsDetails":{"tlsVersion":"TLSv1.3","cipherSuite":%q,"keyExchange":"X25519MLKEM768"}}`, bigStr)},
		{name: "huge_keyExchange", unfilt: fmt.Sprintf(`{"tlsDetails":{"tlsVersion":"TLSv1.3","cipherSuite":"TLS_AES_128_GCM_SHA256","keyExchange":%q}}`, bigStr)},
		{name: "huge_host", unfilt: fmt.Sprintf(`{"tlsDetails":{"tlsVersion":"TLSv1.3","cipherSuite":"TLS_AES_128_GCM_SHA256","keyExchange":"X25519MLKEM768","clientProvidedHostHeader":%q}}`, bigStr)},

		// ---- WRONG TYPES (stress unmarshal / would panic a naive type-assert) ----
		{name: "wrong_type_tlsDetails_string", unfilt: `{"tlsDetails":"astring"}`},
		{name: "wrong_type_requestParameters_array", filtered: map[string]string{"Sign": `{"requestParameters":[]}`}},
		{name: "wrong_type_signingAlgo_number", filtered: map[string]string{"Sign": `{"requestParameters":{"signingAlgorithm":12345}}`}},
		{name: "wrong_type_keyExchange_object", unfilt: `{"tlsDetails":{"keyExchange":{"nested":"x"},"cipherSuite":"x"}}`},
		{name: "wrong_type_userIdentity_array", unfilt: `{"userIdentity":[],"tlsDetails":{"keyExchange":"X25519MLKEM768"}}`},

		// ---- deeply nested nulls / odd-but-valid shapes ----
		{name: "deeply_nested_nulls", unfilt: `{"eventSource":null,"userIdentity":{"invokedBy":null},"tlsDetails":{"tlsVersion":null,"cipherSuite":null,"clientProvidedHostHeader":null,"keyExchange":"X25519MLKEM768"}}`},
		{name: "json_null_literal", filtered: map[string]string{"Sign": `null`}, unfilt: `null`},
		{name: "json_array_top", filtered: map[string]string{"Sign": `[1,2,3]`}, unfilt: `[1,2,3]`},
		{name: "json_number_top", filtered: map[string]string{"Sign": `42`}, unfilt: `42`},

		// ---- combined hostile both-pass payload ----
		{name: "combined_hostile", filtered: map[string]string{"Sign": `{"requestParameters":{"signingAlgorithm":"FALCON_1024"}}`}, unfilt: `{"eventSource":"secretsmanager.amazonaws.com","tlsDetails":{"tlsVersion":"TLSv9.9","cipherSuite":"TLS_FUTURE_PQC","keyExchange":"MLKEM9999"}}`},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			desc := fmt.Sprintf("filtered=%v unfiltered=%q", tc.filtered, truncate(tc.unfilt, 120))

			client := &fakeCloudTrailClient{
				filteredEvents:  tc.filtered,
				unfilteredEvent: tc.unfilt,
			}

			var assets []models.CryptoAsset
			var err error

			func() {
				// (i) NEVER panics: capture, do not crash the run.
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("PANIC in scan() [ROBUSTNESS BUG]\n  input: %s\n  panic: %v\n  stack:\n%s",
							desc, r, debug.Stack())
					}
				}()
				assets, err = CloudTrailEvidenceScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
			}()

			// A returned error on garbage is acceptable; the scanner is documented to
			// degrade to zero assets on undecodable input. We do not assert on err.
			_ = err

			// (ii) Any non-empty asset slice MUST be schema-valid.
			if len(assets) > 0 {
				if verr := output.ValidateAssetsCBOM(assets); verr != nil {
					t.Errorf("CBOM SCHEMA FAILURE on non-empty assets [OUTPUT BUG]\n  input: %s\n  assets: %d\n  error: %v",
						desc, len(assets), verr)
				}
			}
		})
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
