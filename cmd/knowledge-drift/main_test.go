package main

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/aws-samples/cryptamap/internal/pqc"
)

// baselineSnapshot is the enum/identifier projection of the active (embedded)
// knowledge — the left-hand side of every diff in these tests.
func baselineSnapshot() enumSnapshot {
	return snapshotFromKnowledge(pqc.LoadedKnowledge())
}

// TestIdenticalEnumsNoDrift proves the safety floor: when the observed enums are
// exactly the current knowledge's enum/identifier layer, the diff finds NO drift
// and the report is clean (the would-be exit code is 0). The observed snapshot is
// round-tripped through JSON to also exercise the parse path the CLI uses.
func TestIdenticalEnumsNoDrift(t *testing.T) {
	current := baselineSnapshot()

	// Round-trip the baseline through JSON to mimic loading an observed file that
	// happens to match the knowledge exactly.
	raw, err := json.Marshal(current)
	if err != nil {
		t.Fatalf("marshal baseline snapshot: %v", err)
	}
	var observed enumSnapshot
	if err := json.Unmarshal(raw, &observed); err != nil {
		t.Fatalf("unmarshal observed snapshot: %v", err)
	}

	rep := diffSnapshots(current, observed)

	if rep.DriftCount != 0 {
		t.Errorf("identical enums must yield 0 drift, got %d: %+v", rep.DriftCount, rep.Drifts)
	}
	if len(rep.OnlyInObserved) != 0 || len(rep.OnlyInBaseline) != 0 {
		t.Errorf("identical enums must have no one-sided facts, got onlyInObserved=%d onlyInBaseline=%d",
			len(rep.OnlyInObserved), len(rep.OnlyInBaseline))
	}
	if rep.FactsCompared == 0 {
		t.Fatal("expected a non-empty set of facts to be compared")
	}
	// A clean report implies exit 0 (the CLI only exits non-zero on DriftCount>0).
	if exitCode := wantExit(rep, true); exitCode != 0 {
		t.Errorf("clean report with --fail-on-drift must imply exit 0, got %d", exitCode)
	}
}

// TestChangedAddedRemovedEnumsReportDrift proves each drift kind is detected from
// a real fixture file: a changed sourceUrl, an added enum, a removed enum, and a
// fact present only in the observed docs — and that this implies exit non-zero
// under --fail-on-drift. It also confirms a JUDGMENT change is NOT what drives
// this (the fixture only ever touches enum/identifier fields).
func TestChangedAddedRemovedEnumsReportDrift(t *testing.T) {
	current := baselineSnapshot()
	observed := loadObserved(t, "testdata/observed-drift.json")

	rep := diffSnapshots(current, observed)

	if rep.DriftCount == 0 {
		t.Fatal("expected drift from the fixture, got none")
	}

	byKey := make(map[string]factDrift, len(rep.Drifts))
	for _, d := range rep.Drifts {
		byKey[string(d.Section)+"/"+d.Key] = d
	}

	// (1) sourceUrl change on a cipher profile.
	if d, ok := byKey["cipherProfiles/kmsKeySpec/RSA_2048"]; !ok {
		t.Error("expected sourceUrl drift on cipherProfiles/kmsKeySpec/RSA_2048")
	} else if d.SourceURLChanged == nil {
		t.Errorf("kmsKeySpec/RSA_2048: expected a sourceUrl change, got %+v", d)
	}

	// (2) added enum on ML_DSA_87 (the fixture adds a bogus bits: token the
	// baseline does not carry, since ML-DSA specs have no KeySizeBits).
	if d, ok := byKey["cipherProfiles/kmsKeySpec/ML_DSA_87"]; !ok {
		t.Error("expected added-enum drift on cipherProfiles/kmsKeySpec/ML_DSA_87")
	} else if !contains(d.AddedEnums, "bits:4896") {
		t.Errorf("kmsKeySpec/ML_DSA_87: expected added enum bits:4896, got addedEnums=%v", d.AddedEnums)
	}

	// (3) the fixture omits the algorithmName/curve tokens it would have carried
	// for RSA_2048? No — it keeps RSA_2048's enums identical, so its ONLY drift is
	// the sourceUrl. Confirm we did not spuriously report removed enums there.
	if d := byKey["cipherProfiles/kmsKeySpec/RSA_2048"]; len(d.RemovedEnums) != 0 || len(d.AddedEnums) != 0 {
		t.Errorf("kmsKeySpec/RSA_2048: expected only a sourceUrl change, got added=%v removed=%v",
			d.AddedEnums, d.RemovedEnums)
	}

	// (4) a fact present only in the observed docs (a new key spec our knowledge
	// has not captured).
	if !hasFact(rep.OnlyInObserved, secCipherProfiles, "kmsKeySpec/ML_DSA_99") {
		t.Errorf("expected kmsKeySpec/ML_DSA_99 to be reported only-in-observed, got %+v", rep.OnlyInObserved)
	}

	// (5) the dynamodb doc-fact sourceUrl in the fixture matches the baseline, so
	// it must NOT appear as drift (negative control).
	if _, ok := byKey["scannerDocFacts/datarest/dynamodb/at-rest-aes256"]; ok {
		t.Error("dynamodb doc-fact has an unchanged sourceUrl and must not be reported as drift")
	}

	// Drift present => --fail-on-drift implies exit non-zero.
	if exitCode := wantExit(rep, true); exitCode == 0 {
		t.Error("drift present with --fail-on-drift must imply a non-zero exit code")
	}
	// Without --fail-on-drift the tool still reports but exits 0.
	if exitCode := wantExit(rep, false); exitCode != 0 {
		t.Errorf("without --fail-on-drift the tool must exit 0 even on drift, got %d", exitCode)
	}
}

// TestJudgmentFieldsNotProjected guards the locked design decision: the
// enum/identifier projection must NOT carry any judgment field. We assert the
// projection of a profile keeps the identifier tokens but never emits a security
// level, and that the service-matrix projection reduces to the sourceUrl only
// (pqcStatus and the prose fields are dropped).
func TestJudgmentFieldsNotProjected(t *testing.T) {
	snap := baselineSnapshot()

	for key, fe := range snap.CipherProfiles {
		for _, tok := range fe.Enums {
			// Judgment numbers would surface as bare integers or "level:" tokens;
			// the projection only emits identifier/algorithmName/curve/bits tokens.
			if tok == "0" || tok == "112" || tok == "256" {
				t.Errorf("%s: enum token %q looks like a security level — judgment must not be projected", key, tok)
			}
		}
	}

	// Spot-check a known service row reduces to sourceUrl with no enum tokens.
	row, ok := snap.ServiceMatrix["acm"]
	if !ok {
		t.Fatal("expected an 'acm' service-matrix row in the projection")
	}
	if row.SourceURL == "" {
		t.Error("service-matrix projection must keep the sourceUrl")
	}
	if len(row.Enums) != 0 {
		t.Errorf("service-matrix projection must not enumerate free-text prose tokens, got %v", row.Enums)
	}
}

// TestReportTextMentionsReportOnly ensures the human report makes the
// report-only, no-mutation contract explicit (the tool never writes the
// knowledge file).
func TestReportTextMentionsReportOnly(t *testing.T) {
	current := baselineSnapshot()
	observed := loadObserved(t, "testdata/observed-drift.json")
	rep := diffSnapshots(current, observed)

	tmp, err := os.CreateTemp(t.TempDir(), "drift-*.txt")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	defer tmp.Close()
	rep.writeText(tmp)
	if _, err := tmp.Seek(0, 0); err != nil {
		t.Fatalf("seek: %v", err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(tmp); err != nil {
		t.Fatalf("read back: %v", err)
	}
	out := buf.String()
	if !bytes.Contains([]byte(out), []byte("REPORT-ONLY")) {
		t.Error("report text must state it is REPORT-ONLY")
	}
}

// wantExit mirrors the exit policy in main: exit 1 only when drift is found AND
// --fail-on-drift is set; otherwise 0. (Parse/IO errors exit 2 but are exercised
// at the CLI boundary, not here.)
func wantExit(rep driftReport, failOnDrift bool) int {
	if rep.DriftCount > 0 && failOnDrift {
		return 1
	}
	return 0
}

func loadObserved(t *testing.T, path string) enumSnapshot {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var s enumSnapshot
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		t.Fatalf("parse fixture %s: %v", path, err)
	}
	return s
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func hasFact(refs []factRef, sec section, key string) bool {
	for _, r := range refs {
		if r.Section == sec && r.Key == key {
			return true
		}
	}
	return false
}
