// Command gen-knowledge regenerates the embedded PQC knowledge file
// (internal/pqc/data/pqc-knowledge.json) from the in-package Go literals — the
// maintainer-edited source of truth. It is the sibling of cmd/gen-ts.
//
// Phase 1: it marshals pqc.KnowledgeFromLiterals() to pretty JSON. The embedded
// file is therefore always a faithful projection of the literals (zero
// transcription risk), and the golden test asserts embedded == literals so a
// stale embed fails CI. Run after editing matrix.go / primitives.go /
// policy_ciphers.go (or the Type-C facts):
//
//	go run ./cmd/gen-knowledge            # rewrite the embedded default
//	go run ./cmd/gen-knowledge -check     # fail if the embed is stale (CI guard)
//
// Phase 3 extends this with a maintainer-only doc-sourced regeneration path; for
// now it is a pure literals→JSON projection (no network, no internal tooling).
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/aws-samples/cryptamap/internal/pqc"
)

const outPath = "internal/pqc/data/pqc-knowledge.json"

func main() {
	check := flag.Bool("check", false, "fail if the on-disk embed differs from the literals projection (CI staleness guard)")
	flag.Parse()

	k := pqc.KnowledgeFromLiterals()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(k); err != nil {
		fmt.Fprintf(os.Stderr, "gen-knowledge: marshal: %v\n", err)
		os.Exit(1)
	}
	want := buf.Bytes()

	if *check {
		got, err := os.ReadFile(outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gen-knowledge -check: read %s: %v\n", outPath, err)
			os.Exit(1)
		}
		if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(want)) {
			fmt.Fprintf(os.Stderr, "ERROR: %s is stale. Run 'go run ./cmd/gen-knowledge' and commit.\n", outPath)
			os.Exit(1)
		}
		fmt.Printf("gen-knowledge: %s is up to date (%d service rows, %d primitives)\n",
			outPath, len(k.ServiceMatrix), len(k.Primitives))
		return
	}

	if err := os.WriteFile(outPath, want, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "gen-knowledge: write %s: %v\n", outPath, err)
		os.Exit(1)
	}
	fmt.Printf("gen-knowledge: wrote %s (%d service rows, %d primitives, %d cipher-profile tables, %d doc-facts)\n",
		outPath, len(k.ServiceMatrix), len(k.Primitives), len(k.CipherProfiles), len(k.ScannerDocFacts))
}
