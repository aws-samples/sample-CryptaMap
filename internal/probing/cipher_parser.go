package probing

import (
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

// NOTE: the former IsAWSPQHybridSuite / AWSPQHybridSuites / IsKnownPQCEndpoint
// helpers were DELETED. They were dead code that contradicted the live
// detection path: ML-KEM is a negotiated GROUP (ConnectionState.CurveID), never
// part of a TLS cipher-suite name, so suite-name matching can never fire; the
// "kyber" match violated the pqc package rule that bare kyber is never credited
// as standardized PQ; and the hostname-suffix "known PQC endpoint" list would
// fabricate a per-suffix all-clear (PQ negotiation still requires TLS 1.3 and a
// capable client). PQ-hybrid detection MUST key off isPQHybridGroup (CurveID).
