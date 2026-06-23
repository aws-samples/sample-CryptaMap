package services

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestTruncationCapReached verifies the per-scanner safety cap fires exactly at
// the bound (not before) so scanners loop fully up to MaxAssetsPerScanner and
// only truncate — loudly — beyond it.
func TestTruncationCapReached(t *testing.T) {
	cases := []struct {
		name  string
		count int
		want  bool
	}{
		{"zero", 0, false},
		{"one-below", MaxAssetsPerScanner - 1, false},
		{"at-cap", MaxAssetsPerScanner, true},
		{"above-cap", MaxAssetsPerScanner + 1000, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := TruncationCapReached(c.count, "test-scanner", "us-east-1"); got != c.want {
				t.Errorf("TruncationCapReached(%d) = %v, want %v", c.count, got, c.want)
			}
		})
	}
}

// TestStampDocFactKeyed proves the keyed doc-fact helper reproduces the OLD
// inline StampDocFact provenance for a real migrated key: source=aws-doc plus the
// knowledge's confidence/sourceUrl/asOf, and additionally records the fact key.
func TestStampDocFactKeyed(t *testing.T) {
	a := NewAssetWithARN("arn:aws:dynamodb:ap-south-1:111111111111:table/t", "dynamodb", models.CategoryDataAtRest, "111111111111", "ap-south-1", "t", "AWS::DynamoDB::Table", AESAtRest())
	StampDocFactKeyed(&a, "datarest/dynamodb/at-rest-aes256")

	if got := a.Properties[PropSource]; got != SourceAWSDoc {
		t.Errorf("source = %q, want %q", got, SourceAWSDoc)
	}
	if got := a.Properties[PropDocFact]; got != "datarest/dynamodb/at-rest-aes256" {
		t.Errorf("docFact = %q, want the migrated key", got)
	}
	// confidence/url/asOf must be sourced from the knowledge (non-empty, sane).
	if got := a.Properties[PropConfidence]; got != "high" {
		t.Errorf("confidence = %q, want high (from knowledge)", got)
	}
	if got := a.Properties[PropSourceURL]; got == "" {
		t.Error("sourceUrl empty — should be sourced from the knowledge fact")
	}
	if got := a.Properties[PropAsOf]; got == "" {
		t.Error("asOf empty — should be sourced from the knowledge fact")
	}
}

// TestStampDocFactKeyedUnknownKeyFailsSafe proves an unknown key degrades to a
// missing provenance DETAIL (source + key only, no fabricated confidence/date),
// never a panic or a wrong classification.
func TestStampDocFactKeyedUnknownKeyFailsSafe(t *testing.T) {
	a := NewAssetWithARN("arn:aws:x:::y", "x", models.CategoryDataAtRest, "1", "r", "y", "T", NoEncryption())
	StampDocFactKeyed(&a, "no/such/fact")
	if a.Properties[PropSource] != SourceAWSDoc {
		t.Errorf("source = %q, want aws-doc even for unknown key", a.Properties[PropSource])
	}
	if a.Properties[PropDocFact] != "no/such/fact" {
		t.Errorf("docFact key not recorded for unknown key")
	}
	if _, ok := a.Properties[PropConfidence]; ok {
		t.Error("confidence must NOT be fabricated for an unknown key")
	}
	if _, ok := a.Properties[PropAsOf]; ok {
		t.Error("asOf must NOT be fabricated for an unknown key")
	}
}

// TestStampDocFactSubclaimKeyed proves the sub-claim variant records only the
// url + asOf (and the key) WITHOUT touching source/confidence — so it can cite a
// documented sub-claim without clobbering an already-observed posture basis
// (the kms_rotation rotation-inapplicability case).
func TestStampDocFactSubclaimKeyed(t *testing.T) {
	a := NewAssetWithARN("arn:aws:kms:ap-south-1:1:key/abc", "kms", models.CategoryKeyManagement, "1", "ap-south-1", "abc", "AWS::KMS::Key", AESAtRest())
	StampObserved(&a, "high") // primary basis: a live DescribeKey observation
	StampDocFactSubclaimKeyed(&a, "keymgmt/kms_rotation/rotation-inapplicable")

	if got := a.Properties[PropSource]; got != SourceObserved {
		t.Errorf("source = %q, want %q (sub-claim must NOT clobber the observed basis)", got, SourceObserved)
	}
	if got := a.Properties[PropConfidence]; got != "high" {
		t.Errorf("confidence = %q, want high (from StampObserved, untouched by sub-claim)", got)
	}
	if got := a.Properties[PropSourceURL]; got == "" {
		t.Error("sub-claim sourceUrl empty — should be set from the knowledge fact")
	}
	if got := a.Properties[PropAsOf]; got == "" {
		t.Error("sub-claim asOf empty — should be set from the knowledge fact")
	}
	if got := a.Properties[PropDocFact]; got != "keymgmt/kms_rotation/rotation-inapplicable" {
		t.Errorf("docFact key = %q, want the rotation-inapplicable key", got)
	}
}

// TestNewAssetWithARNPreservesARN proves the region-less constructor keeps the
// caller's exact ARN (so the dedup bom-ref is region-independent) while still
// recording the region for display.
func TestNewAssetWithARNPreservesARN(t *testing.T) {
	a := NewAssetWithARN("arn:aws:s3:::my-bucket", "s3", models.CategoryDataAtRest, "111111111111", "ap-south-1", "my-bucket", "AWS::S3::Bucket", NoEncryption())
	if a.ResourceARN != "arn:aws:s3:::my-bucket" {
		t.Errorf("ResourceARN = %q, want region-less arn:aws:s3:::my-bucket", a.ResourceARN)
	}
	if a.Region != "ap-south-1" {
		t.Errorf("Region = %q, want ap-south-1 (recorded for display)", a.Region)
	}
	if a.ResourceType != "AWS::S3::Bucket" {
		t.Errorf("ResourceType = %q, want AWS::S3::Bucket", a.ResourceType)
	}
	// Two assets with the same ARN but different scan regions must share a bom-ref
	// (region-independent dedup key) — the core of the cross-region phantom fix.
	b := NewAssetWithARN("arn:aws:s3:::my-bucket", "s3", models.CategoryDataAtRest, "111111111111", "us-east-1", "my-bucket", "AWS::S3::Bucket", AESAtRest())
	if a.BomRef != b.BomRef {
		t.Errorf("same ARN must yield same BomRef regardless of region: %q vs %q", a.BomRef, b.BomRef)
	}
}

// TestMapConcurrentOrderPreserved proves the result slice mirrors INPUT order
// regardless of which goroutine finishes first — the scanners depend on this so
// the emitted asset order is deterministic across runs (stable CBOM diffs). The
// fn here returns out-of-order completion timing by transforming the value, not
// by sleeping (Date/clock APIs are unavailable in this environment).
func TestMapConcurrentOrderPreserved(t *testing.T) {
	in := make([]int, 100)
	for i := range in {
		in[i] = i
	}
	got := MapConcurrent(context.Background(), 8, in, func(_ context.Context, n int) (string, bool) {
		return fmt.Sprintf("v%d", n), true
	})
	if len(got) != len(in) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(in))
	}
	for i := range got {
		if want := fmt.Sprintf("v%d", i); got[i] != want {
			t.Errorf("got[%d] = %q, want %q (order not preserved)", i, got[i], want)
		}
	}
}

// TestMapConcurrentDropSemantics proves keep=false drops an item (mirrors a
// per-item `continue`) while preserving the relative order of the kept items —
// here, only even values survive.
func TestMapConcurrentDropSemantics(t *testing.T) {
	in := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	got := MapConcurrent(context.Background(), 4, in, func(_ context.Context, n int) (int, bool) {
		return n, n%2 == 0 // keep evens only
	})
	want := []int{0, 2, 4, 6, 8}
	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

// TestMapConcurrentConcurrencyBound proves no more than `workers` invocations of
// fn run at once (the whole point of the bounded primitive — a dense region must
// not launch thousands of simultaneous SDK calls). A live counter incremented on
// entry / decremented on exit must never exceed the worker cap. Run with -race to
// also catch any shared-slice data race in the order-addressed write.
func TestMapConcurrentConcurrencyBound(t *testing.T) {
	const workers = 5
	in := make([]int, 200)
	var inFlight, maxSeen int64
	var mu sync.Mutex
	got := MapConcurrent(context.Background(), workers, in, func(_ context.Context, _ int) (int, bool) {
		cur := atomic.AddInt64(&inFlight, 1)
		mu.Lock()
		if cur > maxSeen {
			maxSeen = cur
		}
		mu.Unlock()
		// Spin briefly so concurrent calls actually overlap, without any clock API.
		sum := 0
		for j := 0; j < 50000; j++ {
			sum += j
		}
		atomic.AddInt64(&inFlight, -1)
		return sum, true
	})
	if len(got) != len(in) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(in))
	}
	if maxSeen > workers {
		t.Errorf("max concurrent fn = %d, want <= %d (concurrency bound violated)", maxSeen, workers)
	}
	if maxSeen < 2 {
		t.Errorf("max concurrent fn = %d, want >= 2 (fn never actually ran concurrently)", maxSeen)
	}
}

// TestMapConcurrentEmptyAndDefaults proves the empty-input fast path returns nil
// (not a zero-length non-nil slice the callers would append) and that a non-
// positive worker count falls back to DefaultInnerConcurrency rather than
// dead-locking on a zero-capacity semaphore.
func TestMapConcurrentEmptyAndDefaults(t *testing.T) {
	if got := MapConcurrent(context.Background(), 8, []int(nil), func(_ context.Context, n int) (int, bool) {
		return n, true
	}); got != nil {
		t.Errorf("empty input: got %v, want nil", got)
	}
	// workers <= 0 must not hang; it falls back to DefaultInnerConcurrency.
	got := MapConcurrent(context.Background(), 0, []int{1, 2, 3}, func(_ context.Context, n int) (int, bool) {
		return n * 2, true
	})
	if len(got) != 3 || got[0] != 2 || got[2] != 6 {
		t.Errorf("workers=0 fallback: got %v, want [2 4 6]", got)
	}
}
