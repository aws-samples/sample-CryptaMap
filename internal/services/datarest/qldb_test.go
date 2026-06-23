package datarest

import (
	"errors"
	"fmt"
	"net"
	"testing"
)

// TestIsEndpointUnavailable verifies that QLDB endpoint-resolution / DNS
// failures (no such host) are detected as a graceful-skip signal, while
// genuine errors (throttling, AccessDenied, generic) are NOT — so they still
// surface as hard scanner errors.
func TestIsEndpointUnavailable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		// Endpoint/DNS failures -> skip.
		{"nil", nil, false},
		{"dns-not-found", &net.DNSError{Err: "no such host", Name: "qldb.us-east-1.amazonaws.com", IsNotFound: true}, true},
		{"wrapped-dns", fmt.Errorf("qldb ListLedgers: %w", &net.DNSError{Err: "no such host", IsNotFound: true}), true},
		{"no-such-host-string", errors.New(`Get "https://qldb.us-east-1.amazonaws.com/ledgers": dial tcp: lookup qldb.us-east-1.amazonaws.com: no such host`), true},

		// Genuine errors -> do NOT skip (must still hard-fail).
		{"access-denied", errors.New("AccessDeniedException: not authorized to perform qldb:ListLedgers"), false},
		{"throttling", errors.New("ThrottlingException: Rate exceeded"), false},
		{"generic", errors.New("some other failure"), false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isEndpointUnavailable(c.err); got != c.want {
				t.Errorf("isEndpointUnavailable(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}
