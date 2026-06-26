package runtime

import (
	"testing"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestParseRuntimeAlgo exercises the pure CloudTrail-event parser over realistic
// requestParameters blobs (classical Sign, PQ Sign, GenerateDataKey keySpec) and
// the malformed / empty cases that must yield ok=false.
func TestParseRuntimeAlgo(t *testing.T) {
	tests := []struct {
		name        string
		blob        string
		wantAlgo    string
		wantKeySpec string
		wantSigning string
		wantOK      bool
	}{
		{
			name:        "classical ECDSA sign",
			blob:        `{"eventName":"Sign","requestParameters":{"keyId":"abc","signingAlgorithm":"ECDSA_SHA_256","messageType":"DIGEST"}}`,
			wantSigning: "ECDSA_SHA_256",
			wantOK:      true,
		},
		{
			name:        "post-quantum ML-DSA sign",
			blob:        `{"eventName":"Sign","requestParameters":{"keyId":"abc","signingAlgorithm":"ML_DSA_SHAKE_256"}}`,
			wantSigning: "ML_DSA_SHAKE_256",
			wantOK:      true,
		},
		{
			name:        "GenerateDataKey keySpec AES_256",
			blob:        `{"eventName":"GenerateDataKey","requestParameters":{"keyId":"abc","keySpec":"AES_256"}}`,
			wantKeySpec: "AES_256",
			wantOK:      true,
		},
		{
			name:        "GenerateDataKeyPair keyPairSpec falls back to keySpec",
			blob:        `{"eventName":"GenerateDataKeyPair","requestParameters":{"keyId":"abc","keyPairSpec":"ML_KEM_1024"}}`,
			wantKeySpec: "ML_KEM_1024",
			wantOK:      true,
		},
		{
			name:     "Encrypt encryptionAlgorithm RSAES_OAEP",
			blob:     `{"eventName":"Encrypt","requestParameters":{"keyId":"abc","encryptionAlgorithm":"RSAES_OAEP_SHA_256"}}`,
			wantAlgo: "RSAES_OAEP_SHA_256",
			wantOK:   true,
		},
		{
			name:   "malformed json yields ok=false",
			blob:   `{not valid json`,
			wantOK: false,
		},
		{
			name:   "valid json but no crypto fields yields ok=false",
			blob:   `{"eventName":"ListKeys","requestParameters":{"limit":50}}`,
			wantOK: false,
		},
		{
			name:   "empty blob yields ok=false",
			blob:   ``,
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algo, keySpec, signing, ok := parseRuntimeAlgo(tt.blob)
			if ok != tt.wantOK {
				t.Fatalf("parseRuntimeAlgo ok=%v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if algo != tt.wantAlgo {
				t.Errorf("algo=%v, want %v", algo, tt.wantAlgo)
			}
			if keySpec != tt.wantKeySpec {
				t.Errorf("keySpec=%v, want %v", keySpec, tt.wantKeySpec)
			}
			if signing != tt.wantSigning {
				t.Errorf("signingAlgo=%v, want %v", signing, tt.wantSigning)
			}
		})
	}
}

// TestRuntimePosture asserts the runtime algorithm -> posture mapping. These are
// STANDALONE KMS data-plane primitives (a Sign signingAlgorithm or a
// GenerateDataKeyPair keySpec), so a pure ML-DSA / ML-KEM primitive is PQCReady
// (pure PQC) — NOT PQCHybrid, which is reserved for the combined TLS KEX group
// (classified separately by tlsObservedPosture).
func TestRuntimePosture(t *testing.T) {
	tests := []struct {
		algo string
		want models.CryptoPosture
	}{
		{"ML_DSA_SHAKE_256", models.PosturePQCReady},
		{"ML_KEM_1024", models.PosturePQCReady},
		{"mlkem768x25519", models.PosturePQCReady},
		{"ECDSA_SHA_256", models.PostureNonPQCClassical},
		{"RSAES_OAEP_SHA_256", models.PostureNonPQCClassical},
		{"SM2PKE", models.PostureNonPQCClassical},
		// EdDSA / Ed25519 is classical (quantum-vulnerable) — must NOT be symmetric-only.
		{"ED25519_SHA_512", models.PostureNonPQCClassical},
		{"ECC_NIST_EDWARDS25519", models.PostureNonPQCClassical},
		{"AES_256", models.PostureSymmetricOnly},
		{"SYMMETRIC_DEFAULT", models.PostureSymmetricOnly},
		// An unrecognized algorithm is Unknown (honest), never assumed quantum-resistant.
		{"unknown-thing", models.PostureUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			if got := runtimePosture(tt.algo); got != tt.want {
				t.Errorf("runtimePosture(%q)=%v, want %v", tt.algo, got, tt.want)
			}
		})
	}
}

// TestChooseAlgo asserts the priority order signingAlgo > algo > keySpec.
func TestChooseAlgo(t *testing.T) {
	tests := []struct {
		name string
		evd  runtimeEvidence
		want string
	}{
		{"signing wins", runtimeEvidence{signingAlgo: "ML_DSA_SHAKE_256", algo: "x", keySpec: "y"}, "ML_DSA_SHAKE_256"},
		{"algo when no signing", runtimeEvidence{algo: "RSAES_OAEP_SHA_256", keySpec: "y"}, "RSAES_OAEP_SHA_256"},
		{"keySpec last", runtimeEvidence{keySpec: "AES_256"}, "AES_256"},
		{"empty", runtimeEvidence{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.evd.chooseAlgo(); got != tt.want {
				t.Errorf("chooseAlgo()=%q, want %q", got, tt.want)
			}
		})
	}
}

// TestRuntimeAlgoProps asserts the fix for the fabricated-algorithm bug: an
// observed asymmetric / signing op (ML_DSA, RSA, ECDSA) must NOT be labeled
// AES-256, must carry the OBSERVED algorithm name with the right primitive, and
// must NOT assert a NIST quantum security level for a classical asymmetric algo.
// Only a genuinely symmetric op (GenerateDataKey / AES_* keyspec) keeps AES-256.
func TestRuntimeAlgoProps(t *testing.T) {
	tests := []struct {
		name          string
		eventName     string
		chosen        string
		wantName      string
		wantPrimitive models.AlgorithmPrimitive
		wantNistLevel int
	}{
		{
			name:          "ML-DSA sign is a PQC signature, not AES-256",
			eventName:     "Sign",
			chosen:        "ML_DSA_SHAKE_256",
			wantName:      "ML_DSA_SHAKE_256",
			wantPrimitive: models.PrimitiveSignature,
			wantNistLevel: 0,
		},
		{
			name:          "ECDSA sign is a classical signature, not AES-256",
			eventName:     "Sign",
			chosen:        "ECDSA_SHA_256",
			wantName:      "ECDSA_SHA_256",
			wantPrimitive: models.PrimitiveSignature,
			wantNistLevel: 0,
		},
		{
			name:          "RSA encrypt is a public-key (kem) op, not AES-256",
			eventName:     "Encrypt",
			chosen:        "RSAES_OAEP_SHA_256",
			wantName:      "RSAES_OAEP_SHA_256",
			wantPrimitive: models.PrimitiveKEM,
			wantNistLevel: 0,
		},
		{
			name:          "ML-KEM data-key-pair is a kem op, not AES-256",
			eventName:     "GenerateDataKeyPair",
			chosen:        "ML_KEM_1024",
			wantName:      "ML_KEM_1024",
			wantPrimitive: models.PrimitiveKEM,
			wantNistLevel: 0,
		},
		{
			name:          "GenerateDataKey AES_256 stays symmetric AES-256",
			eventName:     "GenerateDataKey",
			chosen:        "AES_256",
			wantName:      "AES-256",
			wantPrimitive: models.PrimitiveAE,
			wantNistLevel: 5, // AES-256 anchors NIST Category 5
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			props := runtimeAlgoProps(tt.eventName, tt.chosen)
			ap := props.AlgorithmProperties
			if ap == nil {
				t.Fatalf("AlgorithmProperties is nil")
			}
			if ap.AlgorithmName == "AES-256" && tt.wantName != "AES-256" {
				t.Errorf("%s observed op was fabricated as AES-256", tt.chosen)
			}
			if ap.AlgorithmName != tt.wantName {
				t.Errorf("AlgorithmName=%q, want %q", ap.AlgorithmName, tt.wantName)
			}
			if ap.Primitive != tt.wantPrimitive {
				t.Errorf("Primitive=%q, want %q", ap.Primitive, tt.wantPrimitive)
			}
			if ap.NistQuantumSecurityLevel != tt.wantNistLevel {
				t.Errorf("NistQuantumSecurityLevel=%d, want %d", ap.NistQuantumSecurityLevel, tt.wantNistLevel)
			}
		})
	}
}

// TestParseTLSDetails + classification exercise the A3 PQ-TLS observation pass
// over the exact CloudTrail tlsDetails shapes from the AWS doc: a hybrid ML-KEM
// handshake (X25519MLKEM768 -> observed PQ-hybrid), classical x25519/secp256r1,
// an AWS-service-on-your-behalf call (invokedBy set -> must be skippable), and
// the older shape with no keyExchange (fallback, never asserts PQ).
func TestParseTLSDetails(t *testing.T) {
	pq := `{"eventSource":"secretsmanager.amazonaws.com","userIdentity":{"type":"IAMUser"},"tlsDetails":{"tlsVersion":"TLSv1.3","cipherSuite":"TLS_AES_128_GCM_SHA256","clientProvidedHostHeader":"secretsmanager.us-east-1.amazonaws.com","keyExchange":"X25519MLKEM768"}}`
	classical := `{"eventSource":"kms.amazonaws.com","tlsDetails":{"tlsVersion":"TLSv1.3","cipherSuite":"TLS_AES_256_GCM_SHA384","keyExchange":"x25519"}}`
	svc := `{"eventSource":"ec2.amazonaws.com","userIdentity":{"invokedBy":"autoscaling.amazonaws.com"},"tlsDetails":{"tlsVersion":"TLSv1.2","cipherSuite":"ECDHE-RSA-AES128-GCM-SHA256","keyExchange":"secp256r1"}}`
	noKEX := `{"eventSource":"iam.amazonaws.com","tlsDetails":{"tlsVersion":"TLSv1.2","cipherSuite":"ECDHE-RSA-AES128-GCM-SHA256","clientProvidedHostHeader":"iam.amazonaws.com"}}`
	noTLS := `{"eventSource":"s3.amazonaws.com","requestParameters":{"bucketName":"b"}}`

	// PQ hybrid handshake -> observed pqc-hybrid, high confidence.
	te, ok := parseTLSDetails(pq)
	if !ok || te.keyExchange != "X25519MLKEM768" || te.invokedBy != "" {
		t.Fatalf("pq parse: ok=%v kex=%q invokedBy=%q", ok, te.keyExchange, te.invokedBy)
	}
	if !isMLKEMKeyExchange(te.keyExchange) {
		t.Errorf("X25519MLKEM768 must be detected as ML-KEM")
	}
	if p, c, have := tlsObservedPosture(te); p != models.PosturePQCHybrid || c != "high" || !have {
		t.Errorf("pq posture = %q/%q/%v, want pqc-hybrid/high/true", p, c, have)
	}

	// Classical x25519 -> non-pqc-classical, high.
	te2, _ := parseTLSDetails(classical)
	if isMLKEMKeyExchange(te2.keyExchange) {
		t.Errorf("x25519 must NOT be ML-KEM")
	}
	if p, _, _ := tlsObservedPosture(te2); p != models.PostureNonPQCClassical {
		t.Errorf("x25519 posture = %q, want non-pqc-classical", p)
	}

	// AWS-service-invoked call: parses, but invokedBy is set so the scanner skips it.
	te3, ok3 := parseTLSDetails(svc)
	if !ok3 || te3.invokedBy == "" {
		t.Errorf("service-invoked parse: ok=%v invokedBy=%q (want set so caller skips)", ok3, te3.invokedBy)
	}

	// Older event with no keyExchange: parses (tlsDetails present) but fallback
	// posture is classical/low and never PQ.
	te4, ok4 := parseTLSDetails(noKEX)
	if !ok4 || te4.keyExchange != "" {
		t.Errorf("noKEX parse: ok=%v kex=%q", ok4, te4.keyExchange)
	}
	if p, c, have := tlsObservedPosture(te4); p == models.PosturePQCHybrid || c != "low" || have {
		t.Errorf("noKEX posture = %q/%q/%v, want classical/low/false (never PQ on fallback)", p, c, have)
	}

	// No tlsDetails block at all -> ok=false.
	if _, ok5 := parseTLSDetails(noTLS); ok5 {
		t.Errorf("event without tlsDetails must yield ok=false")
	}
}
