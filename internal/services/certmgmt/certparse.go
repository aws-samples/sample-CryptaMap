package certmgmt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// parsedCert holds the cryptographic facts extracted from a real X.509
// certificate's PEM body. It is the single source of truth shared by the
// iot_certs and iam_certs scanners, which both fetch a PEM via a per-resource
// API call (IoT DescribeCertificate / IAM GetServerCertificate) and parse it
// with crypto/x509 (same pattern as internal/probing/tls_prober.go:84-85).
type parsedCert struct {
	// SigAlgo is cert.SignatureAlgorithm.String() (e.g. "SHA256-RSA",
	// "ECDSA-SHA384"). Empty when the OID is unrecognized (e.g. a real ML-DSA
	// cert) or the cert could not be parsed — never a fabricated guess.
	SigAlgo string
	// PubKeyAlgo is cert.PublicKeyAlgorithm.String() (e.g. "RSA", "ECDSA",
	// "Ed25519"). Empty on parse failure / unknown.
	PubKeyAlgo string
	// AlgoProps carries the public-key size / curve when the key type is
	// recognized; nil otherwise.
	AlgoProps *models.AlgorithmProperties
	// Posture is derived from the parsed key/signature algorithm: RSA / ECDSA /
	// Ed25519 -> NonPQCClassical; an unrecognized OID or a parse error ->
	// Unknown (we do NOT re-assert a classical default for what we could not
	// read — a customer could register a true ML-DSA leaf).
	Posture models.CryptoPosture
}

// parseCertPEM decodes a PEM-encoded certificate body and extracts its real
// signature/public-key algorithm, key size/curve, and posture. On any
// nil/empty input, PEM-decode failure, or x509 parse error it returns a
// parsedCert with empty algorithm fields and PostureUnknown — so a skipped or
// failed parse is never disguised as a confident classical classification.
func parseCertPEM(pemBody string) parsedCert {
	res := parsedCert{Posture: models.PostureUnknown}
	if pemBody == "" {
		return res
	}
	block, _ := pem.Decode([]byte(pemBody))
	if block == nil {
		return res
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || cert == nil {
		// Includes the case of an unrecognized OID such as a real ML-DSA cert:
		// leave the algorithm fields empty and the posture Unknown.
		return res
	}

	if cert.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		res.SigAlgo = cert.SignatureAlgorithm.String()
	}
	if cert.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		res.PubKeyAlgo = cert.PublicKeyAlgorithm.String()
	}

	// Key size / curve from the concrete public-key type. A recognized classical
	// key (RSA/ECDSA/Ed25519) is quantum-vulnerable -> NonPQCClassical. An
	// unrecognized public-key algorithm leaves the posture Unknown.
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		res.AlgoProps = &models.AlgorithmProperties{
			Primitive:     models.PrimitiveSignature,
			AlgorithmName: res.PubKeyAlgo,
			KeySizeBits:   pub.N.BitLen(),
		}
		res.Posture = models.PostureNonPQCClassical
	case *ecdsa.PublicKey:
		res.AlgoProps = &models.AlgorithmProperties{
			Primitive:     models.PrimitiveSignature,
			AlgorithmName: res.PubKeyAlgo,
			Curve:         pub.Curve.Params().Name,
			KeySizeBits:   pub.Curve.Params().BitSize,
		}
		res.Posture = models.PostureNonPQCClassical
	case ed25519.PublicKey:
		res.AlgoProps = &models.AlgorithmProperties{
			Primitive:     models.PrimitiveSignature,
			AlgorithmName: res.PubKeyAlgo,
			KeySizeBits:   256,
		}
		res.Posture = models.PostureNonPQCClassical
	}
	return res
}
