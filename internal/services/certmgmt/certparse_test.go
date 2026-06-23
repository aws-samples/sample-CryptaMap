package certmgmt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// NOTE on idiom: certparse.go is a pure helper (parseCertPEM) shared by the
// iot_certs / iam_certs scanners — it defines no Scan(), makes no AWS SDK call,
// and does no pagination. So there is no client interface to extract and nothing
// to refactor: the testable core IS parseCertPEM. These tests therefore exercise
// the cert-domain HONESTY posture directly: a recognized classical key
// (RSA/ECDSA/Ed25519) must classify as NonPQCClassical and NEVER as a
// no-encryption posture; an unrecognized OID or an unparseable / empty body must
// fall back to Unknown rather than fabricate a confident classical default.
//
// All helpers are prefixed "certparse" to avoid colliding with other test files
// in package certmgmt (parallel agents share this package).

// certparseMakeCertPEM signs a minimal self-signed leaf with the given key pair
// and returns its PEM body, mirroring how a real ACM/IoT/IAM cert body reaches
// parseCertPEM. pub/priv must be a matching key pair accepted by
// x509.CreateCertificate.
func certparseMakeCertPEM(t *testing.T, pub, priv interface{}) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "certparse.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("certparseMakeCertPEM: CreateCertificate failed: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func certparseRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("certparseRSAKey: %v", err)
	}
	return k
}

func certparseECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("certparseECDSAKey: %v", err)
	}
	return k
}

func certparseEd25519Keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("certparseEd25519Keys: %v", err)
	}
	return pub, priv
}

// TestParseCertPEMClassicalKeysAreNonPQCClassical asserts the core honesty rule
// for this scanner's domain: a real, parseable classical certificate is
// quantum-vulnerable and must be posture NonPQCClassical — never PostureUnknown
// (we DID read it) and never a no-encryption / clean posture (a cert is crypto).
// It also confirms the algorithm facts are extracted from the actual key, not
// guessed.
func TestParseCertPEMClassicalKeysAreNonPQCClassical(t *testing.T) {
	rsaKey := certparseRSAKey(t)
	ecKey := certparseECDSAKey(t)
	edPub, edPriv := certparseEd25519Keys(t)

	cases := []struct {
		certparseName      string
		certparsePEM       string
		certparseWantAlgo  string // expected PublicKeyAlgorithm.String()
		certparseWantBits  int    // expected KeySizeBits
		certparseWantCurve string
	}{
		{
			certparseName:     "rsa-2048",
			certparsePEM:      certparseMakeCertPEM(t, &rsaKey.PublicKey, rsaKey),
			certparseWantAlgo: "RSA",
			certparseWantBits: 2048,
		},
		{
			certparseName:      "ecdsa-p384",
			certparsePEM:       certparseMakeCertPEM(t, &ecKey.PublicKey, ecKey),
			certparseWantAlgo:  "ECDSA",
			certparseWantBits:  384,
			certparseWantCurve: "P-384",
		},
		{
			certparseName:     "ed25519",
			certparsePEM:      certparseMakeCertPEM(t, edPub, edPriv),
			certparseWantAlgo: "Ed25519",
			certparseWantBits: 256,
		},
	}

	for _, tc := range cases {
		t.Run(tc.certparseName, func(t *testing.T) {
			got := parseCertPEM(tc.certparsePEM)

			if got.Posture != models.PostureNonPQCClassical {
				t.Errorf("posture = %q, want %q (a parsed classical cert is quantum-vulnerable, not Unknown and not no-encryption)",
					got.Posture, models.PostureNonPQCClassical)
			}
			if got.PubKeyAlgo != tc.certparseWantAlgo {
				t.Errorf("PubKeyAlgo = %q, want %q", got.PubKeyAlgo, tc.certparseWantAlgo)
			}
			if got.SigAlgo == "" {
				t.Errorf("SigAlgo empty for a parseable classical cert; want a real SignatureAlgorithm string")
			}
			if got.AlgoProps == nil {
				t.Fatalf("AlgoProps nil for a recognized classical key; want populated key facts")
			}
			if got.AlgoProps.Primitive != models.PrimitiveSignature {
				t.Errorf("AlgoProps.Primitive = %q, want %q", got.AlgoProps.Primitive, models.PrimitiveSignature)
			}
			if got.AlgoProps.KeySizeBits != tc.certparseWantBits {
				t.Errorf("AlgoProps.KeySizeBits = %d, want %d", got.AlgoProps.KeySizeBits, tc.certparseWantBits)
			}
			if tc.certparseWantCurve != "" && got.AlgoProps.Curve != tc.certparseWantCurve {
				t.Errorf("AlgoProps.Curve = %q, want %q", got.AlgoProps.Curve, tc.certparseWantCurve)
			}
		})
	}
}

// TestParseCertPEMUnreadableIsUnknownNotClassical asserts the no-silent-drop /
// no-fabrication posture: empty, non-PEM, and structurally-broken-PEM inputs must
// yield PostureUnknown with EMPTY algorithm fields — the scanner must not invent a
// confident classical classification for a body it could not actually read (a
// customer could register a true ML-DSA leaf whose OID x509 cannot parse).
func TestParseCertPEMUnreadableIsUnknownNotClassical(t *testing.T) {
	cases := []struct {
		certparseName string
		certparseBody string
	}{
		{"empty", ""},
		{"not-pem-garbage", "this is not a certificate at all"},
		{
			"pem-block-with-bad-der",
			string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-valid-der")})),
		},
	}

	for _, tc := range cases {
		t.Run(tc.certparseName, func(t *testing.T) {
			got := parseCertPEM(tc.certparseBody)

			if got.Posture != models.PostureUnknown {
				t.Errorf("posture = %q, want %q (an unreadable body must NOT be disguised as a confident classical classification)",
					got.Posture, models.PostureUnknown)
			}
			if got.SigAlgo != "" {
				t.Errorf("SigAlgo = %q, want empty (no fabricated signature algo for an unreadable body)", got.SigAlgo)
			}
			if got.PubKeyAlgo != "" {
				t.Errorf("PubKeyAlgo = %q, want empty (no fabricated key algo for an unreadable body)", got.PubKeyAlgo)
			}
			if got.AlgoProps != nil {
				t.Errorf("AlgoProps = %+v, want nil (no fabricated key facts for an unreadable body)", got.AlgoProps)
			}
		})
	}
}
