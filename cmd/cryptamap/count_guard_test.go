package main

import (
	"fmt"
	"strings"
	"testing"
)

// TestBannerScannerCount guards the --help banner (cmd/cryptamap/main.go) against
// scanner-count drift: the count printed in the root command's Long text MUST be
// derived from the live registry (registeredScannerCount), never a hardcoded
// literal. The banner previously claimed "63 AWS services" while the registry
// wired far more, so a regulator-facing --help line contradicted reality.
//
// This test fails if the banner ever re-hardcodes a stale count or stops tracking
// the registry.
func TestBannerScannerCount(t *testing.T) {
	count := registeredScannerCount()

	long := newRootCmd().Long
	if long == "" {
		t.Fatalf("root command Long banner is empty")
	}

	// The banner must report the live registry count.
	if want := fmt.Sprintf("%d AWS service scanners", count); !strings.Contains(long, want) {
		t.Errorf("banner does not report the live registry count.\n  want substring: %q\n  banner: %q", want, long)
	}

	// Guard against the specific stale literals this fix removed leaking back in.
	for _, stale := range []string{"63 AWS services", "64 AWS services", "66 AWS services"} {
		if strings.Contains(long, stale) {
			t.Errorf("banner contains stale scanner-count string %q (use registeredScannerCount instead)", stale)
		}
	}
}

// TestRegisteredScannerCount pins the expected total wired by registerAllScanners
// so an accidental drop of a register block (or a name collision that silently
// dedups two scanners) is caught. The breakdown mirrors the registration helpers:
// certmgmt 10 + keymgmt 9 + sdkpqc 3 + runtime 1 + datarest 49 + transit 27 = 99.
// (2026-06-15 coverage-expansion: +11 datarest + 2 certmgmt promoted scanners.)
func TestRegisteredScannerCount(t *testing.T) {
	if got, want := registeredScannerCount(), 99; got != want {
		t.Errorf("registeredScannerCount = %d, want %d (count r.Register calls across register*.go); "+
			"update this test AND the doc count strings (DEPLOYMENT.md / ARCHITECTURE.md) together", got, want)
	}
}
