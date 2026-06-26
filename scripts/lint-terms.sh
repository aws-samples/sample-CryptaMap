#!/usr/bin/env bash
# lint-terms.sh — PQC-messaging banned-term gate. Fail (non-zero) if a misleading
# user-visible wording reappears anywhere a customer can read it: dashboard source,
# Go output strings, README, CHANGELOG, and docs.
#
# It enforces accurate post-quantum-cryptography terminology across THREE
# banned-pattern families:
#
#   A) "quantum-safe" (any written form) — over-credits AES-256-at-rest (resistant
#      to Grover, NOT post-quantum migrated). Use "quantum-resistant".
#   B) Absolute crypto-state claims — "stays safe", "already safe", "is safe"
#      (crypto context), "comprehensive coverage", "fully protected". Crypto posture
#      is never absolute; use resistance / "no action" / "broad" framing.
#   C) "classical" used for ASYMMETRIC crypto — the specific phrases "classical RSA",
#      "classical ECC/ECDSA/ECDH", "classical public key", "classical asymmetric",
#      "classical RSA-ECC", "classical (non-PQC)". Use "traditional" for pre-PQC
#      asymmetric crypto. BARE "classical" is NOT banned: it has a legitimate
#      computing sense ("classically broken", "classical computer", "classical
#      brute force") that is correct and explicitly permitted.
#
# WHY: CryptaMap's PQC-messaging remediation replaced misleading user-visible
# wording. This gate stops it from silently regressing back in.
#
# SCOPE (the surfaces a user reads): dashboard/src, cmd, internal, README.md,
# CHANGELOG.md, docs.
#
# EXCLUDED (generated / re-synced artifacts — never hand-edited; the build regen
# step reproduces them from the now-clean source, so gating them is noise):
#   dashboard/dist/**            (vite build output)
#   cmd/cryptamap/webdist/**     (the embedded copy of dashboard/dist + re-synced
#                                 mock/compliance JSON; `make build-serve` rebuilds it)
#
# ALLOWLIST — deliberate, load-bearing exemptions. Each is a WIRE-VALUE, an
# internal SIGNAL string, an official PROPER NOUN, a third-party VOCAB citation,
# or a computing-sense (non-asymmetric) use of "classical": rewording any of them
# would break a contract or falsify a cited source. Each allowlisted hit is matched
# by an exact `file:exactlinetext` rule below, so a NEW stray banned term on any
# OTHER line still fails the gate.
set -uo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Paths to scan (the user-visible surfaces).
SCAN_PATHS=(dashboard/src cmd internal README.md CHANGELOG.md docs)

# (A) Case-insensitive, word-boundary "quantum-safe" pattern (ERE).
PATTERN='quantum[-_ ]?safe'

# (B) Absolute crypto-state claims (ERE, word-boundary, case-insensitive).
#     "is safe" is included but its only legitimate (non-crypto) use — the
#     thread-safety idiom "is safe for concurrent use" — is allowlisted below.
ABSOLUTE_PATTERN='stays safe|already safe|is safe|comprehensive coverage|fully protected'

# (C) NARROW "classical"-for-asymmetric phrases (ERE, case-insensitive). Bare
#     "classical" is deliberately NOT matched. The computing-sense phrases
#     ("classically broken", "classical computer", "classical brute") and the
#     wire-value / field tokens ('non-pqc-classical', 'classicalSecurityLevel')
#     are allowlisted below.
CLASSICAL_PATTERN='classical (rsa|ecc|ecdsa|ecdh|public key|asymmetric|rsa-ecc|\(non-pqc\))'

# ---------------------------------------------------------------------------
# ALLOWLIST: each entry is "RELPATH:LINENO\tEXACT_LINE_TEXT" produced by grep -n.
# We match on path + line CONTENT (not line number) so edits that shift line
# numbers do not silently re-allow a banned term, and so the exemption is tied to
# the specific load-bearing string rather than a position. A line is exempt only
# if its (path, trimmed-content) pair appears here.
#
#  -- (A) quantum-safe wire-values / signals / proper nouns / citations --
#  1) WIRE-VALUE enum string  StrengthSafe = "quantum-safe"  — serialized into the
#     CBOM/asset JSON and parsed back; mirrored to TS via gen-ts and into the
#     embedded knowledge JSON. Changing it breaks CBOM round-trip. KEEP.
#  2) generated.ts enum value — the gen-ts projection of (1). KEEP (mirror).
#  3) pqc-knowledge.json "strength" value — the gen-knowledge projection of (1). KEEP.
#  4) roadmap_test asserts the (1) wire value (`want quantum-safe`). KEEP.
#  5) compliance evidence-signal string "quantum-safe" (mapper.go producer ->
#     securityhub.go consumer case-match) + its explaining comments + tests.
#     Changing it silently flips SecurityHub PASSED/FAILED. KEEP.
#  6) Europol "Quantum-Safe Financial Forum" (QSFF) — official body proper noun. KEEP.
#  7) rbi.go — quotes the ABSENCE of an official "quantum-safe protocols" mandate;
#     the quoted phrase is the point of the sentence. KEEP.
#  8) PQC-READINESS-CROSSWALK.md — external CycloneDX / IBM CBOMkit enum vocab
#     `quantum-safe | quantum-vulnerable | not-applicable | unknown`. KEEP (citation).
#
#  -- (B) absolute-claim exemptions --
#  9) registry.go — "It is safe for concurrent use." is the Go thread-safety
#     idiom, NOT a crypto-posture claim. KEEP (computing sense).
#
#  -- (C) classical (computing-sense / wire-value / field) exemptions --
# 10) primitives.go — enum value `PostureNonPQCClassical ... "non-pqc-classical"`
#     is the serialized wire-value; its display label is reworded, the token is
#     kept for CBOM round-trip compatibility. The CLASSICAL_PATTERN does not match
#     the hyphenated token, but the phrase "classical asymmetric" in nearby prose
#     could; any such line is exempted by exact match here.
#     (No current source line trips CLASSICAL_PATTERN outside output strings, so
#      this family currently needs no per-line entry; entries are added here ONLY
#      for deliberate computing-sense uses if/when they appear in scanned source.)
# ---------------------------------------------------------------------------
is_allowlisted() {
  # $1 = relative path, $2 = trimmed line content
  local path="$1" line="$2"
  case "$path" in
    internal/pqc/primitives.go)
      [ "$line" = 'StrengthSafe SymmetricStrength = "quantum-safe"' ] && return 0 ;;
    dashboard/src/types/generated.ts)
      [ "$line" = "export type SymmetricStrength = 'quantum-safe' | 'adequate-review' | 'weak-replace' | 'likely-safe-unconfirmed';" ] && return 0 ;;
    dashboard/src/lib/posture.ts)
      # posture map KEY 'quantum-safe' is the EXEMPT wire-value enum (mirrors (1));
      # only the displayed VALUE label was reworded to "quantum-resistant". KEEP key.
      case "$line" in "'quantum-safe': { label: 'AES-256 — quantum-resistant', indicator: 'success' },") return 0 ;; esac ;;
    internal/pqc/data/pqc-knowledge.json)
      [ "$line" = '"strength": "quantum-safe",' ] && return 0 ;;
    internal/roadmap/roadmap_test.go)
      case "$line" in 't.Errorf("s3 AES-256 SymmetricStrength = %q, want quantum-safe"'*) return 0 ;; esac ;;
    internal/compliance/mapper.go)
      case "$line" in
        'return "quantum-safe"') return 0 ;;
        '// evidence signal: "quantum-safe"'*) return 0 ;;
        *'not the fully-resistant "quantum-safe" signal.') return 0 ;;
        '// "quantum-safe" here is the EXEMPT internal evidence-signal value'*) return 0 ;;
      esac ;;
    internal/compliance/mapper_test.go)
      case "$line" in
        '// "quantum-safe" signal.') return 0 ;;
        'models.PosturePQCReady:      "quantum-safe",') return 0 ;;
        'models.PostureSymmetricOnly: "quantum-safe",') return 0 ;;
      esac ;;
    internal/output/securityhub.go)
      case "$line" in
        '//     quantum-safe | quantum-vulnerable | partial | informational') return 0 ;;
        *'quantum-vulnerable≡non-compliant→FAILED; quantum-safe≡') return 0 ;;
        'case "compliant", "quantum-safe":') return 0 ;;
      esac ;;
    internal/output/securityhub_test.go)
      case "$line" in
        '{"quantum-safe->PASSED", []string{"quantum-safe"}, "PASSED"},') return 0 ;;
        '{"mixed readiness+mandate: vulnerable wins", []string{"quantum-safe", "quantum-vulnerable"}, "FAILED"},') return 0 ;;
      esac ;;
    internal/compliance/europol.go)
      case "$line" in
        '// EuropolMapper — Europol Quantum-Safe Financial Forum (QSFF) recommendations.') return 0 ;;
        'ControlName: "Quantum-Safe Financial Forum recommendation",') return 0 ;;
      esac ;;
    internal/compliance/rbi.go)
      case "$line" in '// IMPORTANT: RBI has NOT issued a "quantum-safe protocols" mandate.'*) return 0 ;; esac ;;
    docs/PQC-READINESS-CROSSWALK.md)
      case "$line" in
        '- **CycloneDX / IBM CBOMkit** emit `quantum-safe | quantum-vulnerable | not-applicable | unknown`.') return 0 ;;
        # Prose that quote-cites the same external CBOMkit/CycloneDX vocab inline.
        *'`quantum-safe | quantum-vulnerable | not-applicable | unknown` vocabulary.') return 0 ;;
      esac ;;
    internal/scanner/registry.go)
      # (B) "is safe for concurrent use" — Go thread-safety idiom, not crypto. KEEP.
      case "$line" in '// Registry holds all enabled ServiceScanners. It is safe for concurrent use.') return 0 ;; esac ;;
  esac
  return 1
}

# is_comment_line returns 0 if the trimmed Go/TS line is a pure // comment. The
# classical-asymmetric check (C) skips these: a code comment is not a customer-
# visible surface, and "classical RSA/ECDSA" appears extensively in source
# comments that faithfully describe the (correct) computing/posture distinction.
is_comment_line() {
  case "$1" in '//'*) return 0 ;; esac
  return 1
}

# WHOLE-FILE exemption hook: a glossary/policy doc that DEFINES this gate would
# need to quote every banned term verbatim, so it is excluded wholesale from all
# three checks. None ships in this repo today; the hook is retained for future use.
EXEMPT_FILE='docs/.terminology-glossary-EXEMPT.md'

# ---------------------------------------------------------------------------
# Family A + B: "quantum-safe" and absolute-claim patterns. Scanned across all
# text source in SCAN_PATHS (incl. comments/tests) — these wordings are banned
# everywhere user-facing and have a small, exact allowlist.
# ---------------------------------------------------------------------------
hits_ab=$(grep -rniwE "$PATTERN|$ABSOLUTE_PATTERN" "${SCAN_PATHS[@]}" \
        --include='*.go' --include='*.ts' --include='*.tsx' \
        --include='*.json' --include='*.md' \
        --exclude-dir=dist --exclude-dir=webdist --exclude-dir=node_modules \
        2>/dev/null \
        | grep -vF "${EXEMPT_FILE}:")

# ---------------------------------------------------------------------------
# Family C: NARROW "classical"-for-asymmetric phrases. This check is deliberately
# scoped to RENDERED user-visible text only, because "classical RSA/ECDSA" is a
# correct, ubiquitous description in:
#   - source comments (not user-visible)            -> skipped by is_comment_line
#   - *_test.go fixtures/assertions (not shipped)    -> --exclude='*_test.go'
#   - the NON-RENDERED knowledge data fields         -> excluded files below:
#       internal/pqc/matrix.go         (Notes/PQCMechanism — only HowToEnable renders)
#       internal/pqc/embed.go          (scannerDocFacts.Value — never copied to assets)
#       internal/pqc/data/pqc-knowledge.json (gen projection of the above)
#     Latent-risk note: if a future change starts RENDERING those fields to
#     user-facing output, drop the exclusion below and re-audit.
# What remains is genuine output: Properties["note"] strings, scanner
# recommendations, dashboard labels, README/docs prose.
# ---------------------------------------------------------------------------
hits_c=$(grep -rniE "$CLASSICAL_PATTERN" "${SCAN_PATHS[@]}" \
        --include='*.go' --include='*.ts' --include='*.tsx' \
        --include='*.json' --include='*.md' \
        --exclude-dir=dist --exclude-dir=webdist --exclude-dir=node_modules \
        --exclude='*_test.go' \
        2>/dev/null \
        | grep -vE '^(internal/pqc/matrix\.go|internal/pqc/embed\.go|internal/pqc/data/pqc-knowledge\.json):' \
        | grep -vF "${EXEMPT_FILE}:")

fail=0
violations=""

process_hits() {
  # $1 = newline-delimited grep -n output; $2 = "skip-comments" to drop // lines.
  local raw path rest content trimmed skip="${2:-}"
  while IFS= read -r raw; do
    [ -z "$raw" ] && continue
    path="${raw%%:*}"
    rest="${raw#*:}"          # "lineno:content"
    content="${rest#*:}"      # "content"
    trimmed="$(printf '%s' "$content" | sed -e 's/^[[:space:]]*//')"
    if [ "$skip" = "skip-comments" ] && is_comment_line "$trimmed"; then
      continue
    fi
    if is_allowlisted "$path" "$trimmed"; then
      continue
    fi
    fail=1
    violations="${violations}${raw}"$'\n'
  done <<EOF
$1
EOF
}

process_hits "$hits_ab" ""
process_hits "$hits_c" "skip-comments"

if [ "$fail" -ne 0 ]; then
  echo "ERROR: banned user-visible PQC-messaging wording found."
  echo "  - use 'quantum-resistant' (not 'quantum-safe')"
  echo "  - drop absolute crypto-state claims ('already/stays/is safe', 'comprehensive coverage', 'fully protected')"
  echo "  - use 'traditional' for pre-PQC asymmetric crypto (not 'classical RSA/ECC/ECDSA/...')"
  echo "If a hit is a deliberate wire-value/signal/proper-noun/citation/computing-sense use,"
  echo "add it to the allowlist in scripts/lint-terms.sh with a comment explaining why."
  echo "Use 'quantum-resistant' not 'quantum-safe', and 'traditional' not 'classical' for pre-PQC asymmetric crypto. Offending lines:"
  echo
  printf '%s' "$violations"
  exit 1
fi

echo "lint-terms: OK — no banned user-visible PQC-messaging wording outside the allowlist."
