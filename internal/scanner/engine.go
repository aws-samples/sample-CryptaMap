package scanner

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	smithy "github.com/aws/smithy-go"
	"github.com/google/uuid"

	"github.com/aws-samples/cryptamap/internal/compliance"
	"github.com/aws-samples/cryptamap/internal/pqc"
	"github.com/aws-samples/cryptamap/internal/risk"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// EngineOptions configure the orchestrator.
type EngineOptions struct {
	MaxGoroutines  int
	PerServiceCap  map[string]int
	BaseDelayMs    int
	MaxDelayMs     int
	MaxRetries     int
	Verbose        bool
	ToolVersion    string
	MoscaOverrides map[string]risk.MoscaParams
	// PerScanTimeout bounds a single scanner's total work (across all retry
	// attempts). A hung scanner (one that never returns from an SDK call and is
	// not covered by the SDK's own per-request timeout) would otherwise pin a
	// worker goroutine until the whole shard dies at the 15-min Lambda kill,
	// starving every other scanner queued behind it. With this budget the stuck
	// scanner is cancelled, surfaced as a normal scanner error, and the worker
	// moves on. Defaults to a sane value in NewEngine when unset.
	PerScanTimeout time.Duration
}

// Engine orchestrates parallel scanning across registered ServiceScanners.
type Engine struct {
	Registry   *Registry
	Compliance *compliance.Registry
	Opts       EngineOptions
}

// NewEngine builds an Engine with the given registry and options.
func NewEngine(reg *Registry, comp *compliance.Registry, opts EngineOptions) *Engine {
	if opts.MaxGoroutines <= 0 {
		opts.MaxGoroutines = 50
	}
	if opts.MaxRetries <= 0 {
		opts.MaxRetries = 5
	}
	if opts.BaseDelayMs <= 0 {
		opts.BaseDelayMs = 100
	}
	if opts.MaxDelayMs <= 0 {
		opts.MaxDelayMs = 30000
	}
	if opts.ToolVersion == "" {
		opts.ToolVersion = "1.0.0"
	}
	if opts.PerScanTimeout <= 0 {
		// Comfortably below the 15-min Lambda ceiling so a single hung scanner
		// is reclaimed long before the whole shard is killed, yet generous
		// enough for a slow paginated scan over a large account.
		opts.PerScanTimeout = 5 * time.Minute
	}
	return &Engine{Registry: reg, Compliance: comp, Opts: opts}
}

type scanJob struct {
	scanner ServiceScanner
}

type scanOutput struct {
	scanner  string
	assets   []models.CryptoAsset
	err      error
	duration time.Duration
}

// Run executes the full scan against the AWS account/region described by cfg.
// accountID is supplied by the caller and recorded on the result; the engine
// does not resolve it via STS. Individual ServiceScanners resolve account
// identity themselves where they need it.
func (e *Engine) Run(ctx context.Context, cfg aws.Config, accountID string) models.ScanResult {
	startedAt := time.Now().UTC()
	scanners := e.Registry.All()
	jobs := make(chan scanJob, len(scanners))
	results := make(chan scanOutput, len(scanners))

	concurrency := e.Opts.MaxGoroutines
	if concurrency > len(scanners) && len(scanners) > 0 {
		concurrency = len(scanners)
	}

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := range jobs {
				start := time.Now()
				name := j.scanner.Name()
				assets, err := func() (a []models.CryptoAsset, scanErr error) {
					// Recover from a panicking scanner so one bad scanner does not
					// crash the whole account/region scan. The panic is converted
					// into a normal scanner error, surfaced to stderr like any other
					// scanner error below, and the remaining scanners keep running.
					defer func() {
						if r := recover(); r != nil {
							a = nil
							scanErr = fmt.Errorf("scanner %s panicked: %v\n%s", name, r, debug.Stack())
						}
					}()
					return e.runWithRetries(ctx, cfg, j.scanner)
				}()
				// Apply an optional per-service cap (EngineOptions.PerServiceCap).
				// This lets an operator bound a single pathological service in one
				// shard (e.g. an account with millions of one resource type) without
				// changing the global services.MaxAssetsPerScanner. Previously this
				// field was declared but never enforced (dead config).
				if cap, ok := e.Opts.PerServiceCap[j.scanner.Name()]; ok && cap > 0 && len(assets) > cap {
					fmt.Fprintf(os.Stderr, "[scanner:%s] per-service cap %d applied in region %s (had %d assets); results truncated\n",
						j.scanner.Name(), cap, cfg.Region, len(assets))
					assets = assets[:cap]
				}
				results <- scanOutput{
					scanner:  j.scanner.Name(),
					assets:   assets,
					err:      err,
					duration: time.Since(start),
				}
			}
		}(i)
	}

	for _, s := range scanners {
		jobs <- scanJob{scanner: s}
	}
	close(jobs)
	wg.Wait()
	close(results)

	scanID := uuid.NewString()

	allAssets := make([]models.CryptoAsset, 0, 256)
	stats := make([]models.ServiceScanReport, 0, len(scanners))
	scanErrors := 0
	for r := range results {
		stat := models.ServiceScanReport{
			Service:    r.scanner,
			AssetCount: len(r.assets),
			DurationMS: r.duration.Milliseconds(),
		}
		if r.err != nil {
			stat.Errors = []string{r.err.Error()}
			// Always surface per-scanner errors to stderr (not gated on Verbose):
			// in Lambda/org fan-out the engine runs with Verbose=false, and silent
			// scanner failures previously made an auth/permission problem look like
			// a legitimately empty account ("0 assets" with no signal).
			fmt.Fprintf(os.Stderr, "[scanner:%s] error: %v\n", r.scanner, r.err)
			scanErrors++
		}
		stats = append(stats, stat)
		allAssets = append(allAssets, r.assets...)
	}
	completedAt := time.Now().UTC()
	if scanErrors > 0 {
		fmt.Fprintf(os.Stderr, "[engine] account=%s region=%s: %d/%d scanners errored, %d assets discovered\n",
			accountID, cfg.Region, scanErrors, len(scanners), len(allAssets))
	}

	findings := e.buildFindings(allAssets)
	summary := e.buildSummary(allAssets, findings, len(scanners))

	return models.ScanResult{
		ScanID:       scanID,
		AccountID:    accountID,
		Region:       cfg.Region,
		StartedAt:    startedAt,
		CompletedAt:  completedAt,
		Mode:         "live",
		Summary:      summary,
		Assets:       allAssets,
		Findings:     findings,
		ServiceStats: stats,
		ToolVersion:  e.Opts.ToolVersion,
	}
}

// runWithRetries wraps a Scan call with exp-backoff + jitter on retryable errors.
//
// The whole retry loop runs under a per-scanner deadline (EngineOptions
// .PerScanTimeout) so a scanner that hangs inside an SDK call cannot pin its
// worker goroutine for the entire shard. When the budget is exhausted the
// derived context is cancelled; the in-flight Scan unwinds with a
// context.DeadlineExceeded error, which is returned to the worker as an
// ordinary scanner error (surfaced to stderr) rather than crashing the scan.
func (e *Engine) runWithRetries(ctx context.Context, cfg aws.Config, s ServiceScanner) ([]models.CryptoAsset, error) {
	if e.Opts.PerScanTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.Opts.PerScanTimeout)
		defer cancel()
	}
	var lastErr error
	for attempt := 0; attempt <= e.Opts.MaxRetries; attempt++ {
		assets, err := scanWithDeadline(ctx, cfg, s)
		if err == nil {
			return assets, nil
		}
		lastErr = err
		// Classify retryability against the SDK's typed error interfaces first,
		// then fall back to a substring heuristic (see shouldRetry). Otherwise
		// return immediately.
		if attempt == e.Opts.MaxRetries || !shouldRetry(err) {
			return assets, err
		}
		delay := backoff(attempt, e.Opts.BaseDelayMs, e.Opts.MaxDelayMs)
		select {
		case <-ctx.Done():
			return assets, ctx.Err()
		case <-time.After(delay):
		}
	}
	return nil, lastErr
}

// scanWithDeadline runs a single Scan and guarantees the caller is released the
// moment ctx is cancelled (e.g. the PerScanTimeout fires), EVEN IF the scanner
// ignores its context and blocks forever. A well-behaved scanner observes the
// cancellation and unwinds on its own; for a context-deaf hang we abandon the
// in-flight goroutine (it leaks until the process exits, but the worker is
// freed to drain the rest of the shard) and return ctx.Err(). This is the
// difference between losing one scanner and losing every scanner queued behind
// the hung one until the 15-min Lambda kill.
func scanWithDeadline(ctx context.Context, cfg aws.Config, s ServiceScanner) ([]models.CryptoAsset, error) {
	type scanRet struct {
		assets []models.CryptoAsset
		err    error
	}
	done := make(chan scanRet, 1) // buffered so an abandoned goroutine can still send and exit
	go func() {
		// Recover from a panicking scanner HERE, inside the goroutine that runs
		// Scan, so one bad scanner cannot crash the whole shard. The recover MUST
		// live in this goroutine — a panic in a child goroutine cannot be caught
		// by a deferred recover in the parent (it would crash the process). The
		// panic is converted into a normal scanner error and flows back through
		// the same channel as any other error.
		defer func() {
			if r := recover(); r != nil {
				done <- scanRet{assets: nil, err: fmt.Errorf("scanner %s panicked: %v\n%s", s.Name(), r, debug.Stack())}
			}
		}()
		assets, err := s.Scan(ctx, cfg)
		done <- scanRet{assets: assets, err: err}
	}()
	select {
	case r := <-done:
		return r.assets, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// engineThrottleCheck classifies throttle errors by the SDK's canonical set of
// throttle error codes (Throttling/ThrottlingException/RequestLimitExceeded/…),
// matched via errors.As against any wrapped error exposing ErrorCode(). It is
// reused for both the typed and (indirectly) the policy decision below.
var engineThrottleCheck = retry.ThrottleErrorCode{Codes: retry.DefaultThrottleErrorCodes}

// shouldRetry decides whether the ENGINE layer should re-run a whole Scan. The
// AWS SDK client is configured with adaptive retry mode (cmd/cryptamap), which
// already owns throttle + transient-network retries with a client-side rate
// limiter. To avoid the ~3-6x attempt amplification of double-retrying the same
// throttle, the engine layer deliberately does NOT retry throttle errors
// (Throttling/TooManyRequests/RequestLimitExceeded/503) — those are the SDK's
// job. It only re-runs a Scan for coarse transient failures that can occur
// BETWEEN SDK calls within a multi-call scanner (e.g. a connection reset partway
// through pagination), where a fresh Scan is the cleaner recovery.
//
// Classification is done against the SDK's TYPED error interfaces first, so a
// throttle/transient error that a scanner has wrapped (fmt.Errorf("…: %w", err))
// is still classified correctly — a bare string match on the top-level message
// would miss the wrapped cause. A substring heuristic is retained as a fallback
// for errors that carry no typed cause (e.g. ad-hoc fmt.Errorf strings).
func shouldRetry(err error) bool {
	if err == nil {
		return false
	}

	// Typed path. A throttle (even wrapped) is the SDK retryer's job; never
	// double-retry it here, regardless of what the transient check would say.
	if engineThrottleCheck.IsErrorThrottle(err) == aws.TrueTernary {
		return false
	}
	// A typed, wrapped transient connection error (connection reset, dial,
	// timeout, temporary, closed connection, retryable 5xx, RequestTimeout) is
	// exactly the "between-SDK-calls" failure a fresh Scan recovers from.
	if (retry.RetryableConnectionError{}).IsErrorRetryable(err) == aws.TrueTernary {
		return true
	}

	// Substring fallback for errors with no typed cause.
	msg := err.Error()
	// Throttle classes are owned by the SDK retryer; do not double-retry them.
	if contains(msg, "Throttling") || contains(msg, "TooManyRequests") ||
		contains(msg, "RequestLimitExceeded") || contains(msg, "503") {
		return false
	}
	for _, hint := range []string{"i/o timeout", "connection reset"} {
		if contains(msg, hint) {
			return true
		}
	}
	return false
}

// ensure the smithy.APIError type stays a build dependency: the typed throttle
// check above resolves an error's ErrorCode() through smithy's APIError
// contract (GenericAPIError implements it), and tests construct one directly.
var _ smithy.APIError = (*smithy.GenericAPIError)(nil)

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func backoff(attempt, baseMs, maxMs int) time.Duration {
	exp := 1 << attempt
	d := baseMs * exp
	if d > maxMs {
		d = maxMs
	}
	jitter := rand.Intn(baseMs + 1)
	return time.Duration(d+jitter) * time.Millisecond
}

// buildFindings converts assets into Findings with Mosca + compliance attached.
// It delegates to the exported, pure scanner.BuildFindings so the live scan
// path and the offline org-merge-files adapter share ONE finding-generation
// code path (byte-identical behavior).
func (e *Engine) buildFindings(assets []models.CryptoAsset) []models.Finding {
	return BuildFindings(assets, e.Compliance, e.Opts.MoscaOverrides)
}

// buildSummary aggregates counts.
func (e *Engine) buildSummary(assets []models.CryptoAsset, findings []models.Finding, services int) models.ScanSummary {
	s := models.ScanSummary{
		TotalAssets:   len(assets),
		TotalFindings: len(findings),
		ServiceCount:  services,
	}
	for _, f := range findings {
		switch f.Severity {
		case models.SeverityCritical:
			s.Critical++
		case models.SeverityHigh:
			s.High++
		case models.SeverityMedium:
			s.Medium++
		case models.SeverityInformational:
			s.Informational++
		}
	}
	return s
}

func recommendation(p models.CryptoPosture, service string) string {
	base := postureRecommendation(p)
	// Append the verified per-service action where the PQC matrix has one, so the
	// generic posture guidance (the WHY) is followed by the concrete, service-
	// specific HOW (e.g. the exact ACM/KMS/ELB knob). PQCSupportFor resolves the
	// asset.Service via serviceAlias; on a miss it returns ok=false and we keep
	// just the posture guidance. The action is omitted for the no-action quantum-
	// safe postures, where the posture line is already terminal and a migration
	// how-to would be misleading.
	if isQuantumSafeRecommendationPosture(p) {
		return base
	}
	if sup, ok := pqc.PQCSupportFor(service); ok && sup.HowToEnable != "" {
		return base + " " + sup.HowToEnable
	}
	return base
}

// isQuantumSafeRecommendationPosture reports the no-action quantum-safe postures
// for which a per-service migration how-to must NOT be appended.
func isQuantumSafeRecommendationPosture(p models.CryptoPosture) bool {
	switch p {
	case models.PostureSymmetricOnly, models.PosturePQCHybrid, models.PosturePQCReady:
		return true
	default:
		return false
	}
}

// postureRecommendation is the posture-level guidance (service-independent).
func postureRecommendation(p models.CryptoPosture) string {
	switch p {
	case models.PostureNoEncryption:
		return "Enable AES-256 server-side encryption with a customer-managed KMS key."
	case models.PostureLegacyTLS:
		return "Migrate to a TLS 1.2+ security policy; prefer the AWS PQ-hybrid policy when available (e.g. ELBSecurityPolicy-TLS13-1-3-PQ-2024-04 once published)."
	case models.PostureNonPQCClassical:
		return "Plan migration to PQ-hybrid TLS (X25519 + ML-KEM-768) and ML-DSA certificates per CNSA 2.0 deadlines."
	case models.PostureSymmetricOnly:
		return "AES-256 / already-PQC at rest is quantum-safe; no PQC migration required — listed for inventory completeness."
	case models.PosturePQCHybrid, models.PosturePQCReady:
		return "PQC-ready posture detected; verify periodically as ciphersuites evolve."
	}
	return "Review cryptographic posture against organizational policy."
}

// docsURL returns the verified AWS doc citation for the service from the PQC
// matrix (per-service SourceURL), falling back to the generic AWS cryptography
// guide for any service the matrix does not cover. PQCSupportFor resolves the
// asset.Service via serviceAlias and never panics on an unmapped key.
func docsURL(service string) string {
	if sup, ok := pqc.PQCSupportFor(service); ok && sup.SourceURL != "" {
		return sup.SourceURL
	}
	return "https://docs.aws.amazon.com/security/latest/userguide/cryptography.html"
}
