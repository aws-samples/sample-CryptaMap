package probing

import (
	"strings"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// PostureFromProbe maps a TLS probe result to a CryptoPosture.
func PostureFromProbe(r ProbeResult) models.CryptoPosture {
	if !r.Reachable {
		return models.PostureUnknown
	}
	if r.PQHybridDetected {
		return models.PosturePQCHybrid
	}
	if r.IsLegacyTLS {
		return models.PostureLegacyTLS
	}
	return models.PostureNonPQCClassical
}

// CipherSuiteFromProbe converts a probe to a CycloneDX cipher-suite struct.
func CipherSuiteFromProbe(r ProbeResult) models.CipherSuite {
	algorithms := []string{}
	if r.NegotiatedCipher != "" {
		algorithms = append(algorithms, r.NegotiatedCipher)
	}
	if r.KeyExchange != "" {
		algorithms = append(algorithms, r.KeyExchange)
	}
	if r.CertSignatureAlgo != "" {
		algorithms = append(algorithms, r.CertSignatureAlgo)
	}
	return models.CipherSuite{
		Name:        r.NegotiatedCipher,
		Algorithms:  algorithms,
		Identifiers: []string{r.NegotiatedCipher},
	}
}

// IsAWSPQHybridSuite reports whether a suite name belongs to the AWS PQ-hybrid family.
func IsAWSPQHybridSuite(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "ml_kem") ||
		strings.Contains(n, "ml-kem") ||
		strings.Contains(n, "kyber") ||
		strings.Contains(n, "x25519_ml_kem_768")
}
