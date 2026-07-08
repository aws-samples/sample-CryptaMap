package scanner

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// truncThenSucceedScanner reproduces the stale-truncation-mark retry hazard:
// attempt 1 hits the cap (marks the scanner truncated via TruncationCapReached)
// and THEN fails with a retryable error; attempt 2 succeeds cleanly, under cap,
// without marking. Because the engine consumes the process-global truncation
// mark once (services.TakeTruncated) AFTER runWithRetries returns, the stale
// mark from the failed attempt 1 would contaminate the successful attempt 2 —
// falsely labelling a complete scan "truncated" — unless the engine clears the
// mark before each attempt (services.UnmarkTruncated in runWithRetries).
type truncThenSucceedScanner struct {
	name    string
	attempt int
}

func (s *truncThenSucceedScanner) Name() string              { return s.name }
func (s *truncThenSucceedScanner) Category() models.Category { return models.CategoryDataAtRest }

func (s *truncThenSucceedScanner) Scan(context.Context, aws.Config) ([]models.CryptoAsset, error) {
	s.attempt++
	if s.attempt == 1 {
		// Hit the cap (marks this scanner truncated), then fail retryably so the
		// engine re-runs. "i/o timeout" is on shouldRetry's transient-substring
		// allowlist (throttle-free), so attempt 2 follows.
		services.TruncationCapReached(services.MaxAssetsPerScanner+1, s.name, "us-east-1")
		return nil, errors.New("read tcp 10.0.0.1:443: i/o timeout")
	}
	// Attempt 2: a clean, under-cap success — must NOT be reported truncated.
	return []models.CryptoAsset{{ResourceID: s.name + "-ok"}}, nil
}

// TestTruncationMarkClearedOnRetry pins that a truncation mark set by a failed
// retry attempt does not survive onto a subsequent successful attempt. Regression
// for a review follow-up: UnmarkTruncated was defined but never wired, so a
// retry-then-succeed scan was falsely stamped incomplete.
func TestTruncationMarkClearedOnRetry(t *testing.T) {
	// Defensive: ensure no leftover mark from another test in this process.
	services.TakeTruncated("trunc-retry")

	reg := NewRegistry()
	reg.Register(&truncThenSucceedScanner{name: "trunc-retry"})

	// MaxRetries >= 1 so the retryable attempt-1 failure is followed by attempt 2.
	e := NewEngine(reg, nil, EngineOptions{MaxRetries: 2, MaxGoroutines: 2, ToolVersion: "test", BaseDelayMs: 1, MaxDelayMs: 2})
	res := e.Run(context.Background(), aws.Config{Region: "us-east-1"}, "111122223333")

	var found *models.ServiceScanReport
	for i := range res.ServiceStats {
		if res.ServiceStats[i].Service == "trunc-retry" {
			found = &res.ServiceStats[i]
		}
	}
	if found == nil {
		t.Fatalf("no ServiceScanReport for trunc-retry; got %d reports", len(res.ServiceStats))
	}
	// The scan ultimately SUCCEEDED under cap on attempt 2, so its report must
	// carry NO truncation sentinel. If UnmarkTruncated is not wired, attempt-1's
	// stale mark is consumed here and this fails.
	for _, e := range found.Errors {
		if strings.HasPrefix(e, services.TruncationSentinel) {
			t.Errorf("successful retry falsely reported truncated: %q", e)
		}
	}
	if got := found.AssetCount; got != 1 {
		t.Errorf("AssetCount = %d, want 1 (attempt 2's single asset)", got)
	}
}
