package pqc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"sync"
)

// Knowledge-as-data layer (task #35, Phase 1).
//
// CryptaMap's PQC knowledge — the service support matrix, the primitive
// vulnerability table, the cipher-profile tables, and (Phase 1b) the scanner
// Type-C doc-facts — is authored as Go literals in matrix.go / primitives.go /
// policy_ciphers.go. Those literals remain the MAINTAINER-EDITED SOURCE OF TRUTH
// and the golden-test oracle. This file marshals them into a single versioned,
// embedded `data/pqc-knowledge.json` and provides a loader so the RUNTIME reads
// the knowledge as DATA:
//
//   embedded default (always present, air-gap floor)
//     → optionally overlaid by a validated, NEWER on-disk override
//       ($CRYPTAMAP_KNOWLEDGE_FILE) written by the future refresh path (Phase 4+).
//
// The embedded JSON is generated FROM the literals (cmd/gen-knowledge, Phase 3)
// — never hand-typed — so there is zero transcription risk, and the golden test
// (knowledge_golden_test.go) proves embedded == literals across the full
// classification surface before the literals could ever be removed. For Phase 1
// the accessors still read the literals; the loaded knowledge is verified to
// match and exposed via KnowledgeProvenance() for the Phase-2 freshness surface.
//
// This file adds NO new import edges beyond stdlib: it is pure data + I/O on an
// optional override file, keeping internal/pqc dependency-light (the scan path
// never opens a socket or spawns a process).

// knowledgeSchemaVersion is the major schema version the loader understands. A
// knowledge file declaring a higher schemaVersion is REJECTED (forward-compat
// guard) and the embedded default stands.
const knowledgeSchemaVersion = 1

// Knowledge is the versioned envelope embedded as data/pqc-knowledge.json and
// (optionally) written by the refresh path. Field shapes mirror the existing
// json tags on SupportEntry / PrimitiveEntry / CipherProfile so marshalling
// round-trips with no renames.
type Knowledge struct {
	SchemaVersion    int    `json:"schemaVersion"`
	KnowledgeVersion string `json:"knowledgeVersion"` // monotonic YYYY-MM-DD; override precedence compares this
	AsOf             string `json:"asOf"`             // baseline verification date (mirrors const AsOf)
	GeneratedBy      string `json:"generatedBy,omitempty"`
	GeneratedAt      string `json:"generatedAt,omitempty"`
	Digest           string `json:"digest,omitempty"` // sha256 over the canonicalized fact sections (excludes this field)

	ServiceMatrix  []SupportEntry             `json:"serviceMatrix"`
	ServiceAlias   map[string]string          `json:"serviceAlias"`
	Primitives     []PrimitiveEntry           `json:"primitives"`
	PrimitiveAlias map[string]string          `json:"primitiveAlias"`
	CipherProfiles map[string][]CipherProfile `json:"cipherProfiles"` // keyed: kmsKeySpec / acmKeyAlgorithm / s3SSEAlgorithm
	// ScannerDocFacts holds the Type-C documented per-scanner facts (Phase 1b).
	// Keyed {package}/{scanner}/{fact-slug}. Empty until Phase 1b migrates them.
	ScannerDocFacts map[string]ScannerDocFact `json:"scannerDocFacts,omitempty"`
}

// ScannerDocFact is one Type-C documented crypto fact a scanner stamps onto an
// asset (e.g. "DynamoDB at-rest is always AES-256"). Populated in Phase 1b.
type ScannerDocFact struct {
	Value      string `json:"value"`
	SourceURL  string `json:"sourceUrl"`
	Confidence string `json:"confidence"`
	AsOf       string `json:"asOf"`
}

// knowledgeFromLiterals builds a Knowledge envelope from the in-package literal
// tables. This is the authoritative, deterministic projection of the literals;
// the embedded JSON is generated from it and the golden test compares against it.
// Slices are sorted by stable keys so the projection (and therefore the digest)
// is deterministic.
func KnowledgeFromLiterals() Knowledge {
	matrixRows := make([]SupportEntry, 0, len(matrix))
	for _, e := range matrix {
		matrixRows = append(matrixRows, e)
	}
	sort.Slice(matrixRows, func(i, j int) bool { return matrixRows[i].ServiceKey < matrixRows[j].ServiceKey })

	primRows := make([]PrimitiveEntry, 0, len(primitives))
	for _, e := range primitives {
		primRows = append(primRows, e)
	}
	sort.Slice(primRows, func(i, j int) bool { return primRows[i].Primitive < primRows[j].Primitive })

	profiles := map[string][]CipherProfile{
		"kmsKeySpec":      sortedProfiles(kmsKeySpecProfiles),
		"acmKeyAlgorithm": sortedProfiles(acmKeyAlgorithmProfiles),
		"s3SSEAlgorithm":  sortedProfiles(s3SSEAlgorithmProfiles),
	}

	k := Knowledge{
		SchemaVersion:    knowledgeSchemaVersion,
		KnowledgeVersion: AsOf, // baseline knowledge version == the literals' verification date
		AsOf:             AsOf,
		GeneratedBy:      "literals",
		ServiceMatrix:    matrixRows,
		ServiceAlias:     copyStrMap(serviceAlias),
		Primitives:       primRows,
		PrimitiveAlias:   copyStrMap(primitiveAlias),
		CipherProfiles:   profiles,
		ScannerDocFacts:  copyDocFacts(scannerDocFacts),
	}
	k.Digest = k.computeDigest()
	return k
}

func sortedProfiles(m map[string]CipherProfile) []CipherProfile {
	out := make([]CipherProfile, 0, len(m))
	for _, p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identifier < out[j].Identifier })
	return out
}

func copyStrMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copyDocFacts(m map[string]ScannerDocFact) map[string]ScannerDocFact {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]ScannerDocFact, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// computeDigest returns a sha256 over the canonicalized fact sections (every
// field EXCEPT Digest/GeneratedAt/GeneratedBy), so two envelopes carrying the
// same facts produce the same digest regardless of generation metadata —
// tamper-evidence + change-detection for the refresh/diff path.
func (k Knowledge) computeDigest() string {
	canon := struct {
		SchemaVersion   int                        `json:"schemaVersion"`
		AsOf            string                     `json:"asOf"`
		ServiceMatrix   []SupportEntry             `json:"serviceMatrix"`
		ServiceAlias    map[string]string          `json:"serviceAlias"`
		Primitives      []PrimitiveEntry           `json:"primitives"`
		PrimitiveAlias  map[string]string          `json:"primitiveAlias"`
		CipherProfiles  map[string][]CipherProfile `json:"cipherProfiles"`
		ScannerDocFacts map[string]ScannerDocFact  `json:"scannerDocFacts"`
	}{
		SchemaVersion:   k.SchemaVersion,
		AsOf:            k.AsOf,
		ServiceMatrix:   k.ServiceMatrix,
		ServiceAlias:    k.ServiceAlias,
		Primitives:      k.Primitives,
		PrimitiveAlias:  k.PrimitiveAlias,
		CipherProfiles:  k.CipherProfiles,
		ScannerDocFacts: k.ScannerDocFacts,
	}
	// json.Marshal sorts map keys deterministically; slices are pre-sorted.
	b, _ := json.Marshal(canon)
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// validate checks that a parsed Knowledge envelope is structurally sound enough
// to load: understood schema, non-empty version, non-empty matrix/primitives,
// and every serviceAlias target resolving to a real matrix row. A file failing
// validation is rejected wholesale → the embedded/last-good knowledge stands
// (never a corrupted classification — Phase-1 safety invariant). It does NOT
// re-verify classification equivalence; that is the golden test's job for the
// embedded default and the review-gate's job for a refreshed override.
func (k Knowledge) validate() error {
	if k.SchemaVersion == 0 {
		return fmt.Errorf("missing schemaVersion")
	}
	if k.SchemaVersion > knowledgeSchemaVersion {
		return fmt.Errorf("schemaVersion %d newer than supported %d", k.SchemaVersion, knowledgeSchemaVersion)
	}
	if k.KnowledgeVersion == "" {
		return fmt.Errorf("missing knowledgeVersion")
	}
	if len(k.ServiceMatrix) == 0 {
		return fmt.Errorf("empty serviceMatrix")
	}
	if len(k.Primitives) == 0 {
		return fmt.Errorf("empty primitives")
	}
	keys := make(map[string]bool, len(k.ServiceMatrix))
	for _, e := range k.ServiceMatrix {
		if e.ServiceKey == "" {
			return fmt.Errorf("serviceMatrix row with empty serviceKey")
		}
		keys[e.ServiceKey] = true
	}
	for alias, target := range k.ServiceAlias {
		if !keys[target] {
			return fmt.Errorf("serviceAlias[%q]=%q does not resolve to a matrix row", alias, target)
		}
	}
	return nil
}

// KnowledgeSource describes where the loaded knowledge came from, for the
// Phase-2 freshness/provenance surface.
type KnowledgeSource string

const (
	// SourceEmbedded: the baked-in default (air-gap floor) is active.
	SourceEmbedded KnowledgeSource = "embedded"
	// SourceOverride: a validated, newer on-disk override is active.
	SourceOverride KnowledgeSource = "override"
)

// KnowledgeProvenance is the freshness/provenance snapshot of the active
// knowledge, surfaced by the Phase-2 `knowledge-status` command + CBOM metadata.
type KnowledgeProvenance struct {
	Source           KnowledgeSource `json:"source"`
	KnowledgeVersion string          `json:"knowledgeVersion"`
	AsOf             string          `json:"asOf"`
	MinAsOf          string          `json:"minAsOf"` // oldest fact date — the conservative "weakest-link" freshness headline
	MaxAsOf          string          `json:"maxAsOf"` // newest fact date
	Digest           string          `json:"digest"`
	GeneratedBy      string          `json:"generatedBy,omitempty"`
	GeneratedAt      string          `json:"generatedAt,omitempty"`
	FactCount        int             `json:"factCount"`
	OverridePath     string          `json:"overridePath,omitempty"`
	OverrideError    string          `json:"overrideError,omitempty"` // why an override was rejected, if any
}

var (
	loadOnce   sync.Once
	loadedKnow Knowledge
	loadedProv KnowledgeProvenance
)

// loadKnowledge lazily resolves the active knowledge: parse the embedded default
// (which the golden test guarantees parses + matches the literals), then attempt
// a validated, newer override. sync.Once (not init) keeps the package import
// cheap and panic-free.
func loadKnowledge() {
	loadOnce.Do(func() {
		emb, err := parseKnowledge(embeddedKnowledge)
		if err != nil {
			// The embedded default is generated from the literals and golden-tested;
			// a parse failure here is a build-time bug, not a runtime condition. Fall
			// back to the literal projection so the scanner never loses its knowledge.
			emb = KnowledgeFromLiterals()
		}
		loadedKnow = emb
		loadedProv = provenanceFor(emb, SourceEmbedded, "", "")

		// Optional override (Phase 4+ refresh writes this). Absent/invalid/older →
		// embedded stands. Whole-file replace, never field-merge.
		path := overridePath()
		if path == "" {
			return
		}
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return // no override present: embedded stands (the common air-gap path)
		}
		ov, perr := parseKnowledge(raw)
		if perr != nil {
			loadedProv.OverrideError = "parse: " + perr.Error()
			return
		}
		if verr := ov.validate(); verr != nil {
			loadedProv.OverrideError = "validate: " + verr.Error()
			return
		}
		// Verify the override's self-declared digest against a recomputation over
		// its own fact sections (same canonicalization the baseline digest uses).
		// A mismatch means the content was altered after the digest was stamped
		// (or the digest was forged) — fail closed: log + ignore, embedded stands.
		// A tampered override must never silently replace crypto facts.
		if got := ov.computeDigest(); got != ov.Digest {
			loadedProv.OverrideError = fmt.Sprintf("digest mismatch: declared %q, recomputed %q", ov.Digest, got)
			return
		}
		if ov.KnowledgeVersion <= emb.KnowledgeVersion {
			loadedProv.OverrideError = fmt.Sprintf("override version %q not newer than embedded %q", ov.KnowledgeVersion, emb.KnowledgeVersion)
			return
		}
		loadedKnow = ov
		loadedProv = provenanceFor(ov, SourceOverride, path, "")
	})
}

// overridePath returns the override file location, or "" when unset. Explicit
// env var wins; otherwise a directory env var; otherwise empty (no implicit
// scan of the filesystem — the override is opt-in).
func overridePath() string {
	if p := os.Getenv("CRYPTAMAP_KNOWLEDGE_FILE"); p != "" {
		return p
	}
	if d := os.Getenv("CRYPTAMAP_KNOWLEDGE_DIR"); d != "" {
		return d + "/pqc-knowledge.json"
	}
	return ""
}

func parseKnowledge(raw []byte) (Knowledge, error) {
	var k Knowledge
	if err := json.Unmarshal(raw, &k); err != nil {
		return Knowledge{}, err
	}
	return k, nil
}

// provenanceFor builds the freshness snapshot, computing minAsOf/maxAsOf across
// EVERY dated fact (matrix rows, cipher profiles, scanner doc-facts) so the
// headline "oldest fact" number is honest over the whole knowledge set.
func provenanceFor(k Knowledge, src KnowledgeSource, path, overrideErr string) KnowledgeProvenance {
	minAsOf, maxAsOf, n := "", "", 0
	consider := func(d string) {
		if d == "" {
			return
		}
		n++
		if minAsOf == "" || d < minAsOf {
			minAsOf = d
		}
		if d > maxAsOf {
			maxAsOf = d
		}
	}
	// Matrix rows do not yet carry a per-row asOf (added in a later phase); use
	// the envelope AsOf as their floor so the count + range stay honest.
	consider(k.AsOf)
	for _, profs := range k.CipherProfiles {
		for _, p := range profs {
			consider(p.AsOf)
		}
	}
	for _, f := range k.ScannerDocFacts {
		consider(f.AsOf)
	}
	if minAsOf == "" {
		minAsOf = k.AsOf
	}
	if maxAsOf == "" {
		maxAsOf = k.AsOf
	}
	return KnowledgeProvenance{
		Source:           src,
		KnowledgeVersion: k.KnowledgeVersion,
		AsOf:             k.AsOf,
		MinAsOf:          minAsOf,
		MaxAsOf:          maxAsOf,
		Digest:           k.Digest,
		GeneratedBy:      k.GeneratedBy,
		GeneratedAt:      k.GeneratedAt,
		FactCount:        n,
		OverridePath:     path,
		OverrideError:    overrideErr,
	}
}

// LoadedKnowledge returns the active (embedded-or-override) knowledge envelope.
func LoadedKnowledge() Knowledge {
	loadKnowledge()
	return loadedKnow
}

// KnowledgeProvenanceInfo returns the freshness/provenance snapshot of the
// active knowledge — the data behind the Phase-2 `knowledge-status` command and
// the CBOM knowledge:* metadata. It never panics.
func KnowledgeProvenanceInfo() KnowledgeProvenance {
	loadKnowledge()
	return loadedProv
}
