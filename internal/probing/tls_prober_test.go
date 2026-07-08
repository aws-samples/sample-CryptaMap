package probing

import (
	"context"
	"crypto/tls"
	"testing"
	"time"
)

// TestIsPQHybridGroup locks the corrected PQ-hybrid detection: it must key off
// the negotiated KEY-EXCHANGE GROUP (CurveID), NOT the cipher-suite name. The old
// code string-matched the TLS 1.3 cipher-suite name, which never carries the
// ML-KEM group, so it would report a genuinely PQ-hybrid endpoint as classical —
// a false "negotiated classical", worse than a false "supported".
func TestIsPQHybridGroup(t *testing.T) {
	if !isPQHybridGroup(tls.X25519MLKEM768) {
		t.Errorf("X25519MLKEM768 must be detected as PQ-hybrid")
	}
	for _, classical := range []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521} {
		if isPQHybridGroup(classical) {
			t.Errorf("%v is classical, must NOT be flagged PQ-hybrid", kexGroupName(classical))
		}
	}
	// A zero/absent CurveID is not PQ-hybrid (no negotiation observed).
	if isPQHybridGroup(0) {
		t.Errorf("absent CurveID(0) must not be flagged PQ-hybrid")
	}
}

// TestKexGroupName proves the negotiated group renders to a stable, readable name
// (the value a future probe path would surface), with the ML-KEM hybrid group
// named explicitly and an absent group rendering empty (never a fabricated label).
func TestKexGroupName(t *testing.T) {
	cases := []struct {
		id   tls.CurveID
		want string
	}{
		{tls.X25519MLKEM768, "X25519MLKEM768"},
		{tls.X25519, "X25519"},
		{tls.CurveP256, "CurveP256"},
		{0, ""},
	}
	for _, c := range cases {
		if got := kexGroupName(c.id); got != c.want {
			t.Errorf("kexGroupName(%v) = %q, want %q", uint16(c.id), got, c.want)
		}
	}
}

// TestStripPortIPv6Safe pins the fix: stripPort must use
// net.SplitHostPort semantics so a bracketed IPv6 literal is not mangled into a
// broken ServerName (LastIndex(":") would cut inside the address).
func TestStripPortIPv6Safe(t *testing.T) {
	cases := map[string]string{
		"example.com:443":  "example.com",
		"[::1]:443":        "::1",
		"[2001:db8::2]:8443": "2001:db8::2",
		"example.com":      "example.com",
	}
	for in, want := range cases {
		if got := stripPort(in); got != want {
			t.Errorf("stripPort(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestProbeHonorsContextCancellation pins the fix: Probe must propagate
// ctx to the dial (tls.Dialer.DialContext), so a cancelled context returns
// promptly instead of parking for the full Timeout.
func TestProbeHonorsContextCancellation(t *testing.T) {
	p := NewProber(30 * time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	// TEST-NET-1 (RFC 5737) is non-routable: without ctx propagation this dial
	// would block toward the 30s Timeout.
	res := p.Probe(ctx, "192.0.2.1", 443)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Probe ignored cancelled context: took %v", elapsed)
	}
	if res.Reachable {
		t.Errorf("cancelled probe must not report Reachable")
	}
	if res.Error == "" {
		t.Errorf("cancelled probe must surface an error")
	}
}
