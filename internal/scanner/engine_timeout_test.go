package scanner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/aws-samples/cryptamap/internal/compliance"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// hangingScanner blocks forever and deliberately IGNORES its context, modeling
// a scanner stuck inside an SDK call that the SDK's own per-request timeout does
// not cover. Without a per-scanner deadline this would pin its worker goroutine
// until the 15-min Lambda kill, starving every other scanner.
type hangingScanner struct{ name string }

func (h hangingScanner) Name() string              { return h.name }
func (h hangingScanner) Category() models.Category { return models.CategoryDataAtRest }
func (h hangingScanner) Scan(ctx context.Context, _ aws.Config) ([]models.CryptoAsset, error) {
	<-make(chan struct{}) // block forever, never observing ctx
	return nil, nil
}

// fastScanner returns one asset immediately; used to prove the engine still
// collects results from healthy scanners queued alongside a hung one.
type fastScanner struct{ name string }

func (f fastScanner) Name() string              { return f.name }
func (f fastScanner) Category() models.Category { return models.CategoryDataAtRest }
func (f fastScanner) Scan(_ context.Context, _ aws.Config) ([]models.CryptoAsset, error) {
	return []models.CryptoAsset{{
		BomRef:      "fast-asset",
		Name:        "fast-asset",
		Service:     f.name,
		Region:      "ap-south-1",
		Category:    models.CategoryDataAtRest,
		Description: "test asset",
	}}, nil
}

// TestEngineScanTimeout proves PerScanTimeout reclaims a worker from a
// context-deaf hung scanner instead of letting it block the whole shard, while
// a healthy scanner queued alongside it still contributes its assets.
func TestEngineScanTimeout(t *testing.T) {
	reg := NewRegistry()
	reg.Register(hangingScanner{name: "hung"})
	reg.Register(fastScanner{name: "fast"})

	eng := NewEngine(reg, compliance.NewRegistry(nil), EngineOptions{
		MaxGoroutines:  4,
		MaxRetries:     0, // a timeout is not retryable; keep the test deterministic
		PerScanTimeout: 100 * time.Millisecond,
	})

	done := make(chan models.ScanResult, 1)
	go func() { done <- eng.Run(context.Background(), aws.Config{Region: "ap-south-1"}, "111122223333") }()

	// The hung scanner's 100ms budget plus generous slack. If the worker were
	// not released the run would block until ctx (here Background) never fires,
	// and this test would hit the go-test -timeout, failing loudly.
	var res models.ScanResult
	select {
	case res = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("engine did not complete: hung scanner was not reclaimed by PerScanTimeout")
	}

	// Healthy scanner's asset must still be present.
	var sawFast bool
	for _, a := range res.Assets {
		if a.Service == "fast" {
			sawFast = true
		}
	}
	if !sawFast {
		t.Errorf("expected the fast scanner's asset to survive alongside the hung one; assets=%d", len(res.Assets))
	}

	// Hung scanner must be reported as an error (a deadline-exceeded), not a
	// silent empty result.
	var hungErr string
	for _, s := range res.ServiceStats {
		if s.Service == "hung" {
			if len(s.Errors) > 0 {
				hungErr = s.Errors[0]
			}
		}
	}
	if hungErr == "" {
		t.Fatal("hung scanner produced no error; timeout was not surfaced as a scanner error")
	}
	if !strings.Contains(hungErr, context.DeadlineExceeded.Error()) {
		t.Errorf("expected deadline-exceeded error for hung scanner, got %q", hungErr)
	}
}

// TestNewEngineDefaultsPerScanTimeout confirms the unset budget falls back to a
// sane non-zero default (so production callers that omit the field are still
// protected) and an explicit value is preserved.
func TestNewEngineDefaultsPerScanTimeout(t *testing.T) {
	def := NewEngine(NewRegistry(), compliance.NewRegistry(nil), EngineOptions{})
	if def.Opts.PerScanTimeout <= 0 {
		t.Errorf("expected a positive default PerScanTimeout, got %v", def.Opts.PerScanTimeout)
	}

	explicit := NewEngine(NewRegistry(), compliance.NewRegistry(nil), EngineOptions{PerScanTimeout: 42 * time.Second})
	if explicit.Opts.PerScanTimeout != 42*time.Second {
		t.Errorf("explicit PerScanTimeout overridden: got %v", explicit.Opts.PerScanTimeout)
	}
}
