package scanner

import (
	"errors"
	"fmt"
	"net"
	"testing"

	smithy "github.com/aws/smithy-go"
)

// TestShouldRetryTypedAndWrapped proves the engine's retry classifier inspects
// the SDK's TYPED error interfaces (via errors.As), not just the top-level
// message — so a throttle/transient error that a scanner has wrapped with
// fmt.Errorf("…: %w", err) is still classified correctly. The substring path is
// retained only as a fallback for errors with no typed cause.
func TestShouldRetryTypedAndWrapped(t *testing.T) {
	// A typed throttle error whose top-level message reveals NOTHING about the
	// throttle (a bare substring check would miss it). Policy: the SDK retryer
	// owns throttles, so the engine must NOT re-run on it.
	typedThrottle := &smithy.GenericAPIError{Code: "ThrottlingException", Message: "rate exceeded"}
	wrappedThrottle := fmt.Errorf("scanner kms: page 3 failed: %w", typedThrottle)

	// A typed transient connection error, wrapped, with an opaque outer message.
	// net.OpError implements Timeout()/Temporary() so RetryableConnectionError
	// classifies it as retryable. Policy: re-run on coarse transient failures.
	typedTransient := &net.OpError{
		Op:  "read",
		Net: "tcp",
		Err: timeoutNetErr{},
	}
	wrappedTransient := fmt.Errorf("scanner s3: list interrupted: %w", typedTransient)

	cases := []struct {
		name string
		err  error
		want bool
	}{
		// Typed path: wrapped throttle is the SDK's job → no engine retry.
		{"wrapped typed throttle", wrappedThrottle, false},
		{"bare typed throttle", error(typedThrottle), false},
		// Typed path: wrapped transient connection error → engine retries.
		{"wrapped typed transient", wrappedTransient, true},
		// Substring fallback still works for opaque (untyped) errors.
		{"substring throttle fallback", errors.New("Throttling: slow down"), false},
		{"substring transient fallback", errors.New("read tcp: i/o timeout"), true},
		// A non-retryable, non-throttle error (e.g. access denied) is not retried.
		{"non-retryable typed api error",
			&smithy.GenericAPIError{Code: "AccessDeniedException", Message: "no"}, false},
		{"nil error", nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldRetry(tc.err); got != tc.want {
				t.Errorf("shouldRetry(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// timeoutNetErr is a minimal net.Error reporting a timeout, used as the inner
// cause of a net.OpError so RetryableConnectionError treats it as transient.
type timeoutNetErr struct{}

func (timeoutNetErr) Error() string   { return "i/o timeout" }
func (timeoutNetErr) Timeout() bool   { return true }
func (timeoutNetErr) Temporary() bool { return true }

var _ net.Error = timeoutNetErr{}
