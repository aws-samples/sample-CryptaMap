package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// panicScanner is a fake ServiceScanner whose Scan deliberately panics. It
// exercises the engine's per-job panic recovery: a single panicking scanner must
// not crash the whole account/region scan.
type panicScanner struct{ name string }

func (p panicScanner) Name() string              { return p.name }
func (p panicScanner) Category() models.Category { return models.CategoryDataAtRest }
func (p panicScanner) Scan(context.Context, aws.Config) ([]models.CryptoAsset, error) {
	panic("boom")
}

// okScanner is a fake ServiceScanner that returns one asset without error, used
// to prove the engine still collects results from healthy scanners alongside a
// panicking one.
type okScanner struct{ name string }

func (o okScanner) Name() string              { return o.name }
func (o okScanner) Category() models.Category { return models.CategoryDataAtRest }
func (o okScanner) Scan(context.Context, aws.Config) ([]models.CryptoAsset, error) {
	return []models.CryptoAsset{{ResourceID: o.name + "-asset"}}, nil
}

// TestEnginePanicRecovery asserts that a panicking scanner is converted into a
// normal scanner error (surfaced in its ServiceScanReport.Errors) while the rest
// of the scan completes and returns the healthy scanners' assets.
func TestEnginePanicRecovery(t *testing.T) {
	reg := NewRegistry()
	reg.Register(panicScanner{name: "panicker"})
	reg.Register(okScanner{name: "healthy-a"})
	reg.Register(okScanner{name: "healthy-b"})

	e := NewEngine(reg, nil, EngineOptions{MaxRetries: 0, MaxGoroutines: 4, ToolVersion: "test"})

	res := e.Run(context.Background(), aws.Config{Region: "us-east-1"}, "000000000000")

	// All three scanners must be reported.
	if got, want := len(res.ServiceStats), 3; got != want {
		t.Fatalf("ServiceStats len=%d, want %d (one per scanner)", got, want)
	}

	// The healthy scanners' assets must survive the neighbor's panic.
	if got, want := len(res.Assets), 2; got != want {
		t.Errorf("collected %d assets, want %d from the two healthy scanners", got, want)
	}

	// The panic must be surfaced as a normal error on the panicking scanner's
	// report, not propagated as a crash.
	var panicErr string
	for _, s := range res.ServiceStats {
		if s.Service == "panicker" {
			if len(s.Errors) == 0 {
				t.Fatalf("panicker scanner reported no error; panic was not converted to an error")
			}
			panicErr = s.Errors[0]
		} else if len(s.Errors) != 0 {
			t.Errorf("healthy scanner %q unexpectedly reported errors: %v", s.Service, s.Errors)
		}
	}
	if !strings.Contains(panicErr, "panicked") || !strings.Contains(panicErr, "boom") {
		t.Errorf("panic error = %q, want it to mention the scanner name, \"panicked\", and the panic value \"boom\"", panicErr)
	}
}
