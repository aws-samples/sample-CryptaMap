// Command knowledge-drift is a MAINTAINER-ONLY, REPORT-ONLY drift detector for
// CryptaMap's PQC knowledge (internal/pqc/data/pqc-knowledge.json). It is the
// sibling of cmd/gen-knowledge, and like it is NOT imported by the customer scan
// binary (cmd/cryptamap) — it never enters the air-gapped scan path.
//
// WHAT IT CHECKS (and, deliberately, what it does NOT)
//
// The knowledge file mixes two layers of fact:
//
//	(1) a DETERMINISTICALLY-EXTRACTABLE enum/identifier layer — the raw AWS API
//	    enum strings, security-policy names, key-spec identifiers, SSE mode names,
//	    and the AWS doc sourceUrl that names them; and
//	(2) a JUDGMENT layer — CryptaMap's reasoning plus NIST standards: pqcStatus,
//	    nistQuantumSecurityLevel, classicalSecurityLevel, quantumVulnerable.
//
// Layer (2) is NOT on any AWS page (it is our classification + NIST FIPS/SP), so
// this tool MUST NOT drift-check or regenerate it (locked design decision, task
// #4 P4). knowledge-drift compares ONLY layer (1) between the current embedded
// knowledge and a second "observed enums" JSON file — what a future online doc
// fetch WOULD produce — and emits a structured drift report. It NEVER mutates the
// knowledge file; remediation is a human edit + `go run ./cmd/gen-knowledge`.
//
// FOR THIS PHASE it is OFFLINE: the --observed file is supplied by the maintainer
// (a fixture today, an online-fetch artifact later). The online-fetch wiring
// (public awslabs MCP / doc scrape -> observed.json) is a documented later step;
// this command is the deterministic diff engine + report only. It makes NO
// network, MCP, or AWS calls.
//
//	go run ./cmd/knowledge-drift --observed observed.json                # report
//	go run ./cmd/knowledge-drift --observed observed.json --fail-on-drift # CI gate
//	go run ./cmd/knowledge-drift --observed observed.json --json         # machine-readable
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/aws-samples/cryptamap/internal/pqc"
)

func main() {
	observedPath := flag.String("observed", "", "path to the observed-enums JSON file (what an online doc fetch WOULD produce); required")
	failOnDrift := flag.Bool("fail-on-drift", false, "exit non-zero when any enum/identifier drift is found (CI gate)")
	asJSON := flag.Bool("json", false, "emit the drift report as JSON instead of text")
	flag.Parse()

	if *observedPath == "" {
		fmt.Fprintln(os.Stderr, "knowledge-drift: --observed <file> is required")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*observedPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "knowledge-drift: read %s: %v\n", *observedPath, err)
		os.Exit(2)
	}
	var observed enumSnapshot
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&observed); err != nil {
		fmt.Fprintf(os.Stderr, "knowledge-drift: parse %s: %v\n", *observedPath, err)
		os.Exit(2)
	}

	// The current enum/identifier layer is projected from the ACTIVE knowledge
	// (embedded baseline, or an opt-in override — same precedence as the scanner).
	current := snapshotFromKnowledge(pqc.LoadedKnowledge())

	report := diffSnapshots(current, observed)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "knowledge-drift: encode report: %v\n", err)
			os.Exit(2)
		}
	} else {
		report.writeText(os.Stdout)
	}

	if report.DriftCount > 0 && *failOnDrift {
		os.Exit(1)
	}
}

// enumSnapshot is the DETERMINISTIC enum/identifier projection of the knowledge —
// the only layer this tool compares. It is what both the embedded knowledge and
// the observed-enums file are reduced to before diffing, so the comparison is
// strictly like-for-like and never touches a judgment field.
//
// Each fact is keyed by a stable identifier (serviceKey / cipher-profile id /
// doc-fact slug). Per fact we keep ONLY:
//   - the AWS doc URL that names the enum (sourceUrl), and
//   - the set of raw enum/identifier strings the page deterministically yields
//     (key specs, security-policy names, SSE modes, key algorithms, ...).
//
// The observed-enums file authored by a maintainer (or a future online fetcher)
// MUST be in exactly this shape.
type enumSnapshot struct {
	// ServiceMatrix is keyed by serviceKey; Enums holds the enum/policy
	// identifiers the maintainer extracted from that service's sourceUrl.
	ServiceMatrix map[string]factEnums `json:"serviceMatrix"`
	// CipherProfiles is keyed "{table}/{identifier}" (e.g. "kmsKeySpec/RSA_2048");
	// Enums holds the deterministic identifier-layer tokens (the identifier
	// itself, algorithmName, curve, keySizeBits) the AWS page states.
	CipherProfiles map[string]factEnums `json:"cipherProfiles"`
	// ScannerDocFacts is keyed by doc-fact slug; only the sourceUrl is a
	// deterministic identifier (the Value prose is judgment and is NOT compared).
	ScannerDocFacts map[string]factEnums `json:"scannerDocFacts"`
}

// factEnums is the enum/identifier layer for a single fact: the AWS doc URL plus
// the deterministically-extractable identifier strings. Enums is treated as a
// SET (order-insensitive); duplicates are collapsed.
type factEnums struct {
	SourceURL string   `json:"sourceUrl"`
	Enums     []string `json:"enums"`
}

// snapshotFromKnowledge projects a Knowledge envelope down to its enum/identifier
// layer. It reads ONLY the deterministic fields and deliberately ignores every
// judgment field (pqcStatus, nistQuantumSecurityLevel, classicalSecurityLevel,
// quantumVulnerable, and all free-text rationale/notes prose).
func snapshotFromKnowledge(k pqc.Knowledge) enumSnapshot {
	s := enumSnapshot{
		ServiceMatrix:   make(map[string]factEnums, len(k.ServiceMatrix)),
		CipherProfiles:  make(map[string]factEnums),
		ScannerDocFacts: make(map[string]factEnums, len(k.ScannerDocFacts)),
	}

	// Service matrix: the deterministic layer is the sourceUrl. The PQC
	// mechanism / how-to prose carries enum tokens but is free text, so we do NOT
	// parse it here — the observed-enums file supplies the explicit token set, and
	// the baseline contributes none, surfacing any maintainer-asserted enum as an
	// honest "removed" (i.e. present in docs, absent from our enumerated baseline)
	// rather than a false match. The sourceUrl is the load-bearing identifier.
	for _, e := range k.ServiceMatrix {
		s.ServiceMatrix[e.ServiceKey] = factEnums{SourceURL: e.SourceURL}
	}

	// Cipher profiles: the identifier, algorithmName, curve, and key size are all
	// deterministically named on the AWS key-spec / cipher pages. The classical /
	// NIST security levels are NIST-derived JUDGMENT and are excluded.
	for table, profs := range k.CipherProfiles {
		for _, p := range profs {
			key := table + "/" + p.Identifier
			s.CipherProfiles[key] = factEnums{
				SourceURL: p.SourceURL,
				Enums:     cipherEnumTokens(p),
			}
		}
	}

	// Scanner doc-facts: only the sourceUrl is a deterministic identifier; the
	// Value is a prose guarantee (judgment) and Confidence is our weighting.
	for slug, f := range k.ScannerDocFacts {
		s.ScannerDocFacts[slug] = factEnums{SourceURL: f.SourceURL}
	}

	return s
}

// cipherEnumTokens extracts the deterministic identifier-layer tokens of a cipher
// profile: the raw enum identifier, the algorithm name, the curve, and the key
// size (as a token). It NEVER emits classicalSecurityLevel / nistQuantumSecurityLevel.
func cipherEnumTokens(p pqc.CipherProfile) []string {
	toks := []string{p.Identifier}
	if p.AlgorithmName != "" {
		toks = append(toks, p.AlgorithmName)
	}
	if p.Curve != "" {
		toks = append(toks, "curve:"+p.Curve)
	}
	if p.KeySizeBits != 0 {
		toks = append(toks, fmt.Sprintf("bits:%d", p.KeySizeBits))
	}
	return toks
}

// section is one of the three drift-checked knowledge sections.
type section string

const (
	secServiceMatrix   section = "serviceMatrix"
	secCipherProfiles  section = "cipherProfiles"
	secScannerDocFacts section = "scannerDocFacts"
)

// factDrift is the per-fact drift verdict for the enum/identifier layer of one
// fact. AddedEnums/RemovedEnums/sourceUrl changes are all reported with the
// fact's sourceUrl so a maintainer can go straight to the AWS page to confirm.
type factDrift struct {
	Section section `json:"section"`
	Key     string  `json:"key"`
	// SourceURL is the baseline (current-knowledge) AWS doc URL for this fact, so
	// the reader can open the page the enums were sourced from.
	SourceURL string `json:"sourceUrl,omitempty"`
	// SourceURLChanged reports a drift in the doc URL itself (a moved/renamed page).
	SourceURLChanged *stringChange `json:"sourceUrlChanged,omitempty"`
	// AddedEnums: identifiers present in observed (docs) but absent from baseline.
	AddedEnums []string `json:"addedEnums,omitempty"`
	// RemovedEnums: identifiers present in baseline but absent from observed (docs).
	RemovedEnums []string `json:"removedEnums,omitempty"`
}

// stringChange is a before/after pair for a single drifted scalar identifier.
type stringChange struct {
	Was string `json:"was"`
	Now string `json:"now"`
}

// driftReport is the structured, report-only output. It NEVER carries a mutated
// knowledge file — only the diff verdict and the totals.
type driftReport struct {
	// FactsCompared is how many facts existed on at least one side and were diffed.
	FactsCompared int `json:"factsCompared"`
	// DriftCount is the number of facts with any enum/identifier drift.
	DriftCount int `json:"driftCount"`
	// OnlyInObserved/OnlyInBaseline are facts present on exactly one side (a fact
	// added to / removed from the knowledge surface, distinct from per-enum drift).
	OnlyInObserved []factRef `json:"onlyInObserved,omitempty"`
	OnlyInBaseline []factRef `json:"onlyInBaseline,omitempty"`
	// Drifts are the per-fact enum/identifier verdicts, sorted for stable output.
	Drifts []factDrift `json:"drifts,omitempty"`
}

// factRef names a fact present on only one side of the diff.
type factRef struct {
	Section section `json:"section"`
	Key     string  `json:"key"`
}

// diffSnapshots is the deterministic diff engine: it compares the enum/identifier
// layer of two snapshots, section by section, and produces a structured report.
// It performs NO mutation and NO judgment-field comparison.
func diffSnapshots(current, observed enumSnapshot) driftReport {
	var rep driftReport

	diffSection(secServiceMatrix, current.ServiceMatrix, observed.ServiceMatrix, &rep)
	diffSection(secCipherProfiles, current.CipherProfiles, observed.CipherProfiles, &rep)
	diffSection(secScannerDocFacts, current.ScannerDocFacts, observed.ScannerDocFacts, &rep)

	// Stable ordering: section then key, so the report (and CI logs) are diff-able.
	sort.Slice(rep.Drifts, func(i, j int) bool {
		if rep.Drifts[i].Section != rep.Drifts[j].Section {
			return rep.Drifts[i].Section < rep.Drifts[j].Section
		}
		return rep.Drifts[i].Key < rep.Drifts[j].Key
	})
	sort.Slice(rep.OnlyInObserved, func(i, j int) bool {
		if rep.OnlyInObserved[i].Section != rep.OnlyInObserved[j].Section {
			return rep.OnlyInObserved[i].Section < rep.OnlyInObserved[j].Section
		}
		return rep.OnlyInObserved[i].Key < rep.OnlyInObserved[j].Key
	})
	sort.Slice(rep.OnlyInBaseline, func(i, j int) bool {
		if rep.OnlyInBaseline[i].Section != rep.OnlyInBaseline[j].Section {
			return rep.OnlyInBaseline[i].Section < rep.OnlyInBaseline[j].Section
		}
		return rep.OnlyInBaseline[i].Key < rep.OnlyInBaseline[j].Key
	})
	return rep
}

// diffSection diffs one section's fact maps, appending verdicts to rep.
func diffSection(sec section, current, observed map[string]factEnums, rep *driftReport) {
	// Facts present on both sides: compare their enum/identifier layer.
	for key, cur := range current {
		obs, ok := observed[key]
		if !ok {
			rep.OnlyInBaseline = append(rep.OnlyInBaseline, factRef{Section: sec, Key: key})
			continue
		}
		rep.FactsCompared++
		if d, drifted := diffFact(sec, key, cur, obs); drifted {
			rep.DriftCount++
			rep.Drifts = append(rep.Drifts, d)
		}
	}
	// Facts only in observed (a new AWS enum surface our knowledge has not caught up to).
	for key := range observed {
		if _, ok := current[key]; !ok {
			rep.OnlyInObserved = append(rep.OnlyInObserved, factRef{Section: sec, Key: key})
		}
	}
}

// diffFact compares the enum/identifier layer of a single fact present on both
// sides. drifted is false iff the sourceUrl and the enum SET are identical.
func diffFact(sec section, key string, cur, obs factEnums) (factDrift, bool) {
	d := factDrift{Section: sec, Key: key, SourceURL: cur.SourceURL}
	drifted := false

	if cur.SourceURL != obs.SourceURL {
		d.SourceURLChanged = &stringChange{Was: cur.SourceURL, Now: obs.SourceURL}
		drifted = true
	}

	added, removed := diffSets(cur.Enums, obs.Enums)
	if len(added) > 0 {
		d.AddedEnums = added
		drifted = true
	}
	if len(removed) > 0 {
		d.RemovedEnums = removed
		drifted = true
	}
	return d, drifted
}

// diffSets returns the elements added (in observed, not baseline) and removed (in
// baseline, not observed), each sorted, treating the inputs as sets.
func diffSets(baseline, observed []string) (added, removed []string) {
	base := make(map[string]bool, len(baseline))
	for _, e := range baseline {
		base[e] = true
	}
	obs := make(map[string]bool, len(observed))
	for _, e := range observed {
		obs[e] = true
	}
	for e := range obs {
		if !base[e] {
			added = append(added, e)
		}
	}
	for e := range base {
		if !obs[e] {
			removed = append(removed, e)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// writeText renders the report in a human-readable, maintainer-facing form. The
// header states plainly that this is a report and that no file was changed.
func (r driftReport) writeText(w *os.File) {
	fmt.Fprintln(w, "PQC knowledge drift report (enum/identifier layer only — REPORT-ONLY, nothing was modified)")
	fmt.Fprintln(w, "============================================================================================")
	fmt.Fprintf(w, "  Facts compared:  %d\n", r.FactsCompared)
	fmt.Fprintf(w, "  Facts drifted:   %d\n", r.DriftCount)
	fmt.Fprintf(w, "  Only in docs:    %d (enum surface our knowledge has not yet captured)\n", len(r.OnlyInObserved))
	fmt.Fprintf(w, "  Only in baseline: %d (enums we carry that the observed docs did not list)\n", len(r.OnlyInBaseline))

	if r.DriftCount == 0 && len(r.OnlyInObserved) == 0 && len(r.OnlyInBaseline) == 0 {
		fmt.Fprintln(w, "\nNo enum/identifier drift. (Judgment fields are intentionally not checked.)")
		return
	}

	for _, ref := range r.OnlyInObserved {
		fmt.Fprintf(w, "\n[only-in-docs]  %s / %s\n", ref.Section, ref.Key)
	}
	for _, ref := range r.OnlyInBaseline {
		fmt.Fprintf(w, "\n[only-in-baseline]  %s / %s\n", ref.Section, ref.Key)
	}
	for _, d := range r.Drifts {
		fmt.Fprintf(w, "\n[drift]  %s / %s\n", d.Section, d.Key)
		if d.SourceURL != "" {
			fmt.Fprintf(w, "    sourceUrl: %s\n", d.SourceURL)
		}
		if d.SourceURLChanged != nil {
			fmt.Fprintf(w, "    sourceUrl CHANGED: %q -> %q\n", d.SourceURLChanged.Was, d.SourceURLChanged.Now)
		}
		for _, e := range d.AddedEnums {
			fmt.Fprintf(w, "    + %s  (in docs, not in knowledge)\n", e)
		}
		for _, e := range d.RemovedEnums {
			fmt.Fprintf(w, "    - %s  (in knowledge, not in docs)\n", e)
		}
	}
	fmt.Fprintln(w, "\nTo reconcile: review the AWS sourceUrl above, edit the in-package literals")
	fmt.Fprintln(w, "(matrix.go / policy_ciphers.go / embed.go), then run: go run ./cmd/gen-knowledge")
}
