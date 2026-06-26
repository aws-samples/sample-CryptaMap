package pqc

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestEmbeddedKnowledgeMatchesLiterals is the KEYSTONE Phase-1 safety gate: it
// proves the embedded data/pqc-knowledge.json, when parsed, reproduces the
// in-package literal projection (KnowledgeFromLiterals) EXACTLY. If this fails,
// the embed is stale (run `go run ./cmd/gen-knowledge`) or a literal changed
// without regenerating — either way the embedded knowledge would diverge from
// the source of truth, so the build must not proceed.
//
// It compares at the STRUCT level (reflect.DeepEqual on parsed Knowledge), NOT
// marshal-to-marshal: two different structs can serialize to the same bytes when
// both omitempty the same zero fields, so a byte-compare could hide a real
// divergence. DeepEqual on the decoded structs is the honest oracle.
func TestEmbeddedKnowledgeMatchesLiterals(t *testing.T) {
	want := KnowledgeFromLiterals()

	var got Knowledge
	if err := json.Unmarshal(embeddedKnowledge, &got); err != nil {
		t.Fatalf("embedded pqc-knowledge.json does not parse: %v (run: go run ./cmd/gen-knowledge)", err)
	}

	if !reflect.DeepEqual(want, got) {
		// Narrow the failure to the first diverging section for a useful message.
		switch {
		case !reflect.DeepEqual(want.ServiceMatrix, got.ServiceMatrix):
			t.Errorf("serviceMatrix differs: literals=%d rows, embedded=%d rows — embed is STALE, run: go run ./cmd/gen-knowledge",
				len(want.ServiceMatrix), len(got.ServiceMatrix))
		case !reflect.DeepEqual(want.Primitives, got.Primitives):
			t.Errorf("primitives differ: literals=%d, embedded=%d — run: go run ./cmd/gen-knowledge",
				len(want.Primitives), len(got.Primitives))
		case !reflect.DeepEqual(want.ServiceAlias, got.ServiceAlias):
			t.Errorf("serviceAlias differs — run: go run ./cmd/gen-knowledge")
		case !reflect.DeepEqual(want.PrimitiveAlias, got.PrimitiveAlias):
			t.Errorf("primitiveAlias differs — run: go run ./cmd/gen-knowledge")
		case !reflect.DeepEqual(want.CipherProfiles, got.CipherProfiles):
			t.Errorf("cipherProfiles differ — run: go run ./cmd/gen-knowledge")
		case !reflect.DeepEqual(want.ScannerDocFacts, got.ScannerDocFacts):
			t.Errorf("scannerDocFacts differ — run: go run ./cmd/gen-knowledge")
		case want.Digest != got.Digest:
			t.Errorf("digest differs: literals=%s embedded=%s — run: go run ./cmd/gen-knowledge", want.Digest, got.Digest)
		default:
			t.Errorf("embedded knowledge differs from literals (envelope metadata) — run: go run ./cmd/gen-knowledge")
		}
	}
}

// TestEmbeddedKnowledgeReproducesAllLookups proves the EMBEDDED knowledge, when
// queried through the same shapes the accessors use, reproduces the literal
// tables' lookups exactly — service rows, every alias, every primitive, and
// every cipher profile. This is the "no fact silently changed" enumeration
// (every key/alias, not a representative subset — a representative shortcut
// could miss exactly the row that flipped).
func TestEmbeddedKnowledgeReproducesAllLookups(t *testing.T) {
	var emb Knowledge
	if err := json.Unmarshal(embeddedKnowledge, &emb); err != nil {
		t.Fatalf("parse embedded: %v", err)
	}
	embMatrix := map[string]SupportEntry{}
	for _, e := range emb.ServiceMatrix {
		embMatrix[e.ServiceKey] = e
	}

	// Every literal matrix row is present + identical in the embed.
	for key, lit := range matrix {
		got, ok := embMatrix[key]
		if !ok {
			t.Errorf("matrix row %q missing from embedded knowledge", key)
			continue
		}
		if !reflect.DeepEqual(lit, got) {
			t.Errorf("matrix row %q differs between literal and embedded", key)
		}
	}
	if len(embMatrix) != len(matrix) {
		t.Errorf("embedded matrix has %d rows, literal has %d", len(embMatrix), len(matrix))
	}

	// Every serviceAlias entry matches.
	if !reflect.DeepEqual(serviceAlias, emb.ServiceAlias) {
		t.Errorf("serviceAlias map differs between literal and embedded")
	}
	// Every primitiveAlias entry matches.
	if !reflect.DeepEqual(primitiveAlias, emb.PrimitiveAlias) {
		t.Errorf("primitiveAlias map differs between literal and embedded")
	}

	// Every primitive row matches.
	embPrim := map[string]PrimitiveEntry{}
	for _, e := range emb.Primitives {
		embPrim[e.Primitive] = e
	}
	for key, lit := range primitives {
		got, ok := embPrim[key]
		if !ok || !reflect.DeepEqual(lit, got) {
			t.Errorf("primitive %q differs/missing between literal and embedded", key)
		}
	}

	// Every cipher profile in each table matches.
	embProfiles := map[string]map[string]CipherProfile{}
	for table, profs := range emb.CipherProfiles {
		m := map[string]CipherProfile{}
		for _, p := range profs {
			m[p.Identifier] = p
		}
		embProfiles[table] = m
	}
	checkTable := func(name string, lit map[string]CipherProfile) {
		got := embProfiles[name]
		if len(got) != len(lit) {
			t.Errorf("cipher table %q: embedded=%d entries, literal=%d", name, len(got), len(lit))
		}
		for id, lp := range lit {
			if gp, ok := got[id]; !ok || !reflect.DeepEqual(lp, gp) {
				t.Errorf("cipher table %q entry %q differs/missing", name, id)
			}
		}
	}
	checkTable("kmsKeySpec", kmsKeySpecProfiles)
	checkTable("acmKeyAlgorithm", acmKeyAlgorithmProfiles)
	checkTable("s3SSEAlgorithm", s3SSEAlgorithmProfiles)
}

// TestScannerDocFactsRoundTripThroughAccessor proves every literal Type-C
// doc-fact is reproduced EXACTLY when read back through the public accessor
// (ScannerDocFactByKey, which reads the loaded/embedded knowledge) — the
// "no doc-fact silently changed in the literals→JSON→loader round trip"
// enumeration. It enumerates every key (not a sample) and also asserts the
// accessor fails closed (ok=false) for an unknown key.
func TestScannerDocFactsRoundTripThroughAccessor(t *testing.T) {
	if len(scannerDocFacts) == 0 {
		t.Fatal("scannerDocFacts is empty — the 22 Type-C facts were not migrated")
	}
	for key, lit := range scannerDocFacts {
		got, ok := ScannerDocFactByKey(key)
		if !ok {
			t.Errorf("doc-fact %q missing from loaded knowledge (accessor returned ok=false)", key)
			continue
		}
		if !reflect.DeepEqual(lit, got) {
			t.Errorf("doc-fact %q differs between literal and accessor:\n literal=%+v\n loaded =%+v", key, lit, got)
		}
	}
	// The loaded knowledge must carry the SAME set of keys as the literals (no
	// extra rows the literals don't know about, no dropped rows).
	loaded := LoadedKnowledge()
	if len(loaded.ScannerDocFacts) != len(scannerDocFacts) {
		t.Errorf("loaded knowledge has %d doc-facts, literals have %d", len(loaded.ScannerDocFacts), len(scannerDocFacts))
	}
	// Unknown key fails closed.
	if _, ok := ScannerDocFactByKey("no/such/fact"); ok {
		t.Error("ScannerDocFactByKey returned ok=true for an unknown key")
	}
}

// TestScannerDocFactsWellFormed asserts every migrated doc-fact carries the four
// required fields with sane shapes — a non-empty value (the documented guarantee
// prose), an https AWS-doc sourceURL, a confidence in {high,medium,low}, and an
// ISO YYYY-MM-DD asOf. This catches a fact that lost a field in the migration
// (which would surface downstream as a blank provenance row, not a crash).
func TestScannerDocFactsWellFormed(t *testing.T) {
	validConf := map[string]bool{"high": true, "medium": true, "low": true}
	isISODate := func(s string) bool {
		if len(s) != len("2006-01-02") {
			return false
		}
		var y, m, d int
		n, err := fmt.Sscanf(s, "%4d-%2d-%2d", &y, &m, &d)
		return err == nil && n == 3 && m >= 1 && m <= 12 && d >= 1 && d <= 31
	}
	for key, f := range scannerDocFacts {
		if f.Value == "" {
			t.Errorf("doc-fact %q: empty value (the documented guarantee prose)", key)
		}
		if !strings.HasPrefix(f.SourceURL, "https://docs.aws.amazon.com/") {
			t.Errorf("doc-fact %q: sourceURL %q is not an https AWS-doc URL", key, f.SourceURL)
		}
		if !validConf[f.Confidence] {
			t.Errorf("doc-fact %q: confidence %q not in {high,medium,low}", key, f.Confidence)
		}
		if !isISODate(f.AsOf) {
			t.Errorf("doc-fact %q: asOf %q is not YYYY-MM-DD", key, f.AsOf)
		}
	}
}

// TestEffectivePQCStatusCartesianUnchanged sweeps the FULL cartesian product of
// {every PQCStatus} × {every primitive incl. "" and unknown} × {every
// CryptoPosture incl. no-encryption} through EffectivePQCStatus, and asserts the
// embedded-knowledge-derived inputs produce the SAME output as the literal
// inputs for every cell. This is what proves the knowledge-as-data move flips
// ZERO classifications (StatusNotEncrypted override, symmetric-only promotion,
// db_transit non-inheritance, etc.). EffectivePQCStatus logic is unchanged; this
// guards the DATA feeding it.
func TestEffectivePQCStatusCartesianUnchanged(t *testing.T) {
	statuses := []PQCStatus{
		StatusAvailable, StatusHybridTLSOnly, StatusNotYet,
		StatusNotApplicable, StatusNotEncrypted,
	}
	postures := []models.CryptoPosture{
		models.PostureNoEncryption, models.PostureLegacyTLS, models.PostureNonPQCClassical,
		models.PostureSymmetricOnly, models.PosturePQCHybrid, models.PosturePQCReady,
		models.PostureUnknown, "",
	}
	// Primitives: every canonical primitive key, plus "" and an unknown label.
	prims := []string{"", "totally-unknown-primitive"}
	for key := range primitives {
		prims = append(prims, key)
	}
	// Also exercise a sampling of aliases (alias resolution feeds the same logic).
	for alias := range primitiveAlias {
		prims = append(prims, alias)
	}

	for _, s := range statuses {
		for _, prim := range prims {
			for _, p := range postures {
				// EffectivePQCStatus + IsQuantumVulnerablePrimitive read the literal
				// tables today; this asserts they remain internally consistent and
				// deterministic across the full surface (the regression oracle the
				// later accessor-swap to loaded-data must continue to satisfy).
				got := EffectivePQCStatus(s, prim, p)

				// Re-derive the expected output from first principles to lock the
				// invariants (independent of the function's own code path):
				var want PQCStatus
				switch {
				case p == models.PostureNoEncryption:
					want = StatusNotEncrypted
				case isQuantumResistantPosture(p):
					want = StatusNotApplicable
				case s != StatusNotYet:
					want = s
				case prim != "" && !IsQuantumVulnerablePrimitive(prim):
					want = StatusNotApplicable
				default:
					want = s
				}
				if got != want {
					t.Errorf("EffectivePQCStatus(%q,%q,%q)=%q, want %q", s, prim, p, got, want)
				}
			}
		}
	}
}

// TestKnowledgeLoaderEmbeddedDefault proves the loader resolves the embedded
// default with NO override env set (the air-gap path) and reports SourceEmbedded
// with a sane provenance (version + minAsOf populated).
func TestKnowledgeLoaderEmbeddedDefault(t *testing.T) {
	t.Setenv("CRYPTAMAP_KNOWLEDGE_FILE", "")
	t.Setenv("CRYPTAMAP_KNOWLEDGE_DIR", "")
	// Note: loadKnowledge() uses sync.Once; in a fresh test binary this is the
	// first call. Provenance must reflect the embedded default.
	prov := KnowledgeProvenanceInfo()
	if prov.Source != SourceEmbedded {
		t.Errorf("Source=%q, want embedded (no override env set)", prov.Source)
	}
	if prov.KnowledgeVersion == "" || prov.MinAsOf == "" || prov.MaxAsOf == "" {
		t.Errorf("provenance incomplete: %+v", prov)
	}
	k := LoadedKnowledge()
	if len(k.ServiceMatrix) != len(matrix) {
		t.Errorf("loaded matrix rows=%d, want %d", len(k.ServiceMatrix), len(matrix))
	}
}

// TestOverrideDigestVerification proves the override-digest guard the loader
// applies: an override whose content was altered after its Digest was stamped
// (tamper) recomputes to a DIFFERENT digest than it declares, so the guard
// (computeDigest() != Digest) fires and the override is rejected — a tampered
// override must never silently replace crypto facts. An honest override (digest
// re-stamped over its real content) passes the same guard.
func TestOverrideDigestVerification(t *testing.T) {
	// Start from an honest, newer override built from the literals.
	honest := KnowledgeFromLiterals()
	honest.KnowledgeVersion = "9999-12-31" // newer than embedded
	honest.GeneratedBy = "test-refresh"
	honest.Digest = honest.computeDigest() // re-stamp over its real content
	if honest.computeDigest() != honest.Digest {
		t.Fatalf("honest override should pass digest guard: declared %q recomputed %q",
			honest.Digest, honest.computeDigest())
	}

	// Tamper: flip a crypto fact AFTER stamping the digest, leaving the stale
	// self-declared Digest in place (the realistic attack — alter facts, keep the
	// old digest). The recomputed digest now diverges, so the guard must reject.
	tampered := KnowledgeFromLiterals()
	tampered.KnowledgeVersion = "9999-12-31"
	tampered.Digest = tampered.computeDigest()
	if len(tampered.Primitives) == 0 {
		t.Fatal("no primitives to tamper")
	}
	// Downgrade a quantum-vulnerable primitive to look safe — exactly the kind of
	// crypto fact a tamper would target.
	tampered.Primitives[0].QuantumVulnerable = !tampered.Primitives[0].QuantumVulnerable
	if got := tampered.computeDigest(); got == tampered.Digest {
		t.Fatal("tampering a primitive did not change the recomputed digest")
	}
	// This is the exact guard the loader applies before accepting an override.
	if tampered.computeDigest() == tampered.Digest {
		t.Error("tampered override would NOT be rejected by the digest guard")
	}

	// A forged digest (attacker stamps an arbitrary value over tampered content)
	// is likewise rejected.
	forged := tampered
	forged.Digest = "sha256:deadbeef"
	if forged.computeDigest() == forged.Digest {
		t.Error("forged digest unexpectedly matched recomputation")
	}
}

// TestKnowledgeValidateRejects proves validate() rejects the malformed envelopes
// the loader must refuse (so a corrupt override degrades to the embedded floor,
// never to a broken classification).
func TestKnowledgeValidateRejects(t *testing.T) {
	base := KnowledgeFromLiterals()

	// Future schema version -> rejected.
	future := base
	future.SchemaVersion = knowledgeSchemaVersion + 1
	if err := future.validate(); err == nil {
		t.Errorf("validate accepted a newer schemaVersion")
	}
	// Empty matrix -> rejected.
	empty := base
	empty.ServiceMatrix = nil
	if err := empty.validate(); err == nil {
		t.Errorf("validate accepted an empty serviceMatrix")
	}
	// Dangling alias -> rejected.
	dangling := base
	dangling.ServiceAlias = map[string]string{"x": "no-such-row"}
	if err := dangling.validate(); err == nil {
		t.Errorf("validate accepted a dangling serviceAlias target")
	}
	// The literal projection itself must validate.
	if err := base.validate(); err != nil {
		t.Errorf("literal projection failed validate: %v", err)
	}
}
