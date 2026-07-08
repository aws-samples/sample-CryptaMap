package output

import (
	"testing"
	"time"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestScanSortKeyDistinctForSameSecond proves two scans of the same
// (account, region) completing within the same second get DISTINCT sort keys —
// with the timestamp-only SK they collided and the unconditional PutItem
// silently overwrote the losing scan record (retry / concurrent invocation /
// replayed event).
func TestScanSortKeyDistinctForSameSecond(t *testing.T) {
	completed := time.Date(2026, 6, 12, 10, 30, 0, 0, time.UTC)
	a := models.ScanResult{AccountID: "111122223333", Region: "ap-south-1", ScanID: "scan-aaa", CompletedAt: completed}
	b := models.ScanResult{AccountID: "111122223333", Region: "ap-south-1", ScanID: "scan-bbb", CompletedAt: completed}

	skA, skB := scanSortKey(a), scanSortKey(b)
	if skA == skB {
		t.Fatalf("same-second scans collided on SK %q — the second PutItem would silently overwrite the first", skA)
	}
	// SK must stay chronologically ordered: timestamp segment first.
	wantPrefix := "SCAN#2026-06-12T10:30:00Z#"
	if skA != wantPrefix+"scan-aaa" {
		t.Errorf("scanSortKey = %q, want %q", skA, wantPrefix+"scan-aaa")
	}
}
