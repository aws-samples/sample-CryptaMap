// Package probing performs passive TLS handshake analysis against discoverable
// AWS endpoints. It records protocol version, cipher suite, key exchange,
// certificate chain, and PQ-hybrid (X25519 + ML-KEM) negotiation.
package probing

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// ProbeResult is the outcome of one TLS probe.
type ProbeResult struct {
	Endpoint          string
	Reachable         bool
	NegotiatedVersion string
	NegotiatedCipher  string
	KeyExchange       string
	CertSignatureAlgo string
	CertSubject       string
	CertIssuer        string
	CertNotAfter      time.Time
	PQHybridDetected  bool
	IsLegacyTLS       bool
	Error             string
}

// Prober performs TLS probes with a configurable timeout.
type Prober struct {
	Timeout time.Duration
}

// NewProber returns a Prober with the given timeout.
func NewProber(timeout time.Duration) *Prober {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Prober{Timeout: timeout}
}

// Probe performs a TLS handshake against host:port. Host can be a DNS name or
// an ALB/CloudFront URL — leading scheme is stripped if present.
func (p *Prober) Probe(ctx context.Context, host string, port int) ProbeResult {
	endpoint := normalize(host, port)
	res := ProbeResult{Endpoint: endpoint}

	dialer := &net.Dialer{Timeout: p.Timeout}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		ServerName:         stripPort(endpoint),
		InsecureSkipVerify: true, // we capture the cert; we are not validating it
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", endpoint, cfg)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer conn.Close()
	res.Reachable = true

	state := conn.ConnectionState()
	res.NegotiatedVersion = versionString(state.Version)
	res.NegotiatedCipher = tls.CipherSuiteName(state.CipherSuite)
	res.IsLegacyTLS = state.Version < tls.VersionTLS12

	// PQ-hybrid detection reads the negotiated KEY-EXCHANGE GROUP, NOT the cipher-
	// suite name. Go folds ML-KEM into the named group (ConnectionState.CurveID),
	// never the TLS 1.3 cipher suite — so cipher-name string matching never fires
	// and would report a real PQ endpoint as classical. tls.X25519MLKEM768 (and the
	// SecP256r1/SecP384r1 variants) are exported CurveID constants as of Go 1.24+.
	res.KeyExchange = kexGroupName(state.CurveID)
	res.PQHybridDetected = isPQHybridGroup(state.CurveID)

	if len(state.PeerCertificates) > 0 {
		c := state.PeerCertificates[0]
		res.CertSubject = c.Subject.String()
		res.CertIssuer = c.Issuer.String()
		res.CertNotAfter = c.NotAfter
		res.CertSignatureAlgo = c.SignatureAlgorithm.String()
		// NOTE: the cert public-key algorithm (c.PublicKeyAlgorithm) is the CERT's
		// signing-key type, NOT the negotiated key exchange — do not conflate them.
	}
	return res
}

// isPQHybridGroup reports whether a negotiated TLS key-exchange group is a hybrid
// post-quantum (ML-KEM) group. These are the only quantum-resistant transport KEX
// groups AWS endpoints negotiate today.
func isPQHybridGroup(id tls.CurveID) bool {
	switch id {
	case tls.X25519MLKEM768:
		return true
	}
	// SecP256r1MLKEM768 / SecP384r1MLKEM1024 are also hybrid PQ groups; match by
	// name to stay correct even if a constant is unavailable in the build's Go.
	return strings.Contains(strings.ToLower(kexGroupName(id)), "mlkem")
}

// kexGroupName renders a negotiated CurveID as a stable group name (e.g.
// "X25519MLKEM768", "X25519", "CurveP256"), falling back to the numeric id.
func kexGroupName(id tls.CurveID) string {
	switch id {
	case tls.X25519MLKEM768:
		return "X25519MLKEM768"
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "CurveP256"
	case tls.CurveP384:
		return "CurveP384"
	case tls.CurveP521:
		return "CurveP521"
	case 0:
		return ""
	}
	return fmt.Sprintf("0x%x", uint16(id))
}

func versionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	}
	return fmt.Sprintf("0x%x", v)
}

func normalize(host string, port int) string {
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	if i := strings.Index(host, "/"); i >= 0 {
		host = host[:i]
	}
	if strings.Contains(host, ":") {
		return host
	}
	if port == 0 {
		port = 443
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func stripPort(endpoint string) string {
	if i := strings.LastIndex(endpoint, ":"); i >= 0 {
		return endpoint[:i]
	}
	return endpoint
}
