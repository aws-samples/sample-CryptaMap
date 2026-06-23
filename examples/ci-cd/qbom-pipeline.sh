#!/usr/bin/env bash
#
# qbom-pipeline.sh — portable "continuous QBOM" pipeline (any CI, or run locally).
#
# This is the REFERENCE implementation of the CERT-In CIWP "continuous QBOM"
# pattern, read literally: on every pipeline run, regenerate the cryptographic
# bill of materials, sign + date it, and FAIL the build if the run introduces a
# NEW critical post-quantum finding versus a committed baseline.
#
# Steps (each step is also a stage in the GitHub Actions / GitLab CI samples):
#   1. assume a READ-ONLY AWS role (OIDC web-identity in CI; profile locally),
#   2. run `cryptamap` against the caller account (read-only Describe/List/Get),
#   3. emit a DATED CBOM + ASFF for the run,
#   4. SIGN the dated CBOM (cosign keyless, or minisign) — see README.md,
#   5. DIFF the run's CRITICAL set vs the committed baseline ASFF and exit
#      non-zero on a NEW critical.
#
# SAFETY: every AWS call here is read-only (sts assume-role / get-caller-identity
# and the scanner's own Describe/List/Get APIs). Nothing is created, modified, or
# deleted. The scanner is invoked WITHOUT --no-security-hub disabled by default;
# pass CRYPTAMAP_NO_SECURITY_HUB=1 to skip BatchImportFindings if the CI role
# lacks securityhub:BatchImportFindings (the local ASFF file is still produced).
#
# This is a CUSTOMER-ADAPTABLE EXAMPLE; it is NOT wired into this repo's own CI.
#
# Usage:
#   examples/ci-cd/qbom-pipeline.sh
#
# Environment (all overridable):
#   CRYPTAMAP_BIN          path to the cryptamap binary        (default: ./dist/cryptamap)
#   CRYPTAMAP_REGIONS      comma-separated regions to scan     (default: ap-south-1)
#   CRYPTAMAP_OUTPUT_DIR   run artefact directory              (default: ./dist/qbom-output)
#   CRYPTAMAP_BASELINE     committed baseline ASFF JSON        (default: examples/ci-cd/baseline.asff.json)
#   AWS_ROLE_ARN           read-only role to assume via OIDC   (CI only; optional)
#   AWS_WEB_IDENTITY_TOKEN_FILE  OIDC token file               (CI only; set by the platform)
#   AWS_PROFILE            named profile for LOCAL runs        (optional)
#   COSIGN_ENABLED=1       sign the dated CBOM with cosign     (default: off — see README.md)
#   MINISIGN_KEY           minisign secret key file to sign with (optional alternative)
#   CRYPTAMAP_NO_SECURITY_HUB=1  pass --no-security-hub to the scanner (optional)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

CRYPTAMAP_BIN="${CRYPTAMAP_BIN:-${REPO_ROOT}/dist/cryptamap}"
CRYPTAMAP_REGIONS="${CRYPTAMAP_REGIONS:-ap-south-1}"
CRYPTAMAP_OUTPUT_DIR="${CRYPTAMAP_OUTPUT_DIR:-${REPO_ROOT}/dist/qbom-output}"
CRYPTAMAP_BASELINE="${CRYPTAMAP_BASELINE:-${REPO_ROOT}/examples/ci-cd/baseline.asff.json}"

log() { printf '[qbom] %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# Step 1 — assume a read-only AWS role (OIDC in CI), or fall back to a profile.
# ---------------------------------------------------------------------------
assume_readonly_role() {
  if [[ -n "${AWS_ROLE_ARN:-}" && -n "${AWS_WEB_IDENTITY_TOKEN_FILE:-}" ]]; then
    log "assuming read-only role via OIDC web identity: ${AWS_ROLE_ARN}"
    local creds
    creds="$(aws sts assume-role-with-web-identity \
      --role-arn "${AWS_ROLE_ARN}" \
      --role-session-name "cryptamap-qbom-$(date -u +%Y%m%dT%H%M%SZ)" \
      --web-identity-token "$(cat "${AWS_WEB_IDENTITY_TOKEN_FILE}")" \
      --duration-seconds 3600 \
      --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
      --output text)"
    AWS_ACCESS_KEY_ID="$(echo "${creds}" | cut -f1)"
    AWS_SECRET_ACCESS_KEY="$(echo "${creds}" | cut -f2)"
    AWS_SESSION_TOKEN="$(echo "${creds}" | cut -f3)"
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  else
    log "no OIDC role configured — using ambient credentials / AWS_PROFILE=${AWS_PROFILE:-<default>}"
  fi
  # Read-only confirmation; never mutates anything.
  aws sts get-caller-identity --output text --query 'Arn' >&2
}

# ---------------------------------------------------------------------------
# Step 2 + 3 — run cryptamap (read-only) → dated CBOM + ASFF for this run.
# ---------------------------------------------------------------------------
run_scan() {
  mkdir -p "${CRYPTAMAP_OUTPUT_DIR}"
  local args=(--regions "${CRYPTAMAP_REGIONS}" --output-dir "${CRYPTAMAP_OUTPUT_DIR}" --verbose)
  if [[ -n "${AWS_PROFILE:-}" ]]; then
    args+=(--profile "${AWS_PROFILE}")
  fi
  if [[ "${CRYPTAMAP_NO_SECURITY_HUB:-0}" == "1" ]]; then
    args+=(--no-security-hub)
  fi
  log "scanning regions=${CRYPTAMAP_REGIONS} (read-only Describe/List/Get only)"
  "${CRYPTAMAP_BIN}" "${args[@]}"
}

# newest_artifact <suffix> — newest file in the output dir matching *<suffix>.
newest_artifact() {
  local suffix="$1"
  # shellcheck disable=SC2012 # ls -t is the portable "newest first" here; names are tool-generated and safe.
  ls -1t "${CRYPTAMAP_OUTPUT_DIR}"/*"${suffix}" 2>/dev/null | head -n1
}

# ---------------------------------------------------------------------------
# Step 4 — sign the DATED CBOM (cosign keyless OR minisign). Reference only;
# both are no-ops unless explicitly enabled. See README.md "Signing the CBOM".
# ---------------------------------------------------------------------------
sign_cbom() {
  local cbom="$1"
  if [[ "${COSIGN_ENABLED:-0}" == "1" ]] && command -v cosign >/dev/null 2>&1; then
    log "signing ${cbom} with cosign (keyless / OIDC)"
    COSIGN_EXPERIMENTAL=1 cosign sign-blob --yes \
      --output-signature "${cbom}.sig" \
      --output-certificate "${cbom}.pem" \
      "${cbom}"
  elif [[ -n "${MINISIGN_KEY:-}" ]] && command -v minisign >/dev/null 2>&1; then
    log "signing ${cbom} with minisign"
    minisign -S -s "${MINISIGN_KEY}" -m "${cbom}" -x "${cbom}.minisig"
  else
    log "signing skipped (set COSIGN_ENABLED=1 or MINISIGN_KEY=… to enable) — see README.md"
  fi
}

# ---------------------------------------------------------------------------
# Step 5 — diff the run's CRITICAL set vs the committed baseline ASFF.
# Prefers the Go helper (examples/ci-cd/baseline-diff.go); falls back to a
# self-contained jq implementation so this script works on any CI without Go.
# ---------------------------------------------------------------------------
diff_against_baseline() {
  local current_asff="$1"
  if [[ ! -f "${CRYPTAMAP_BASELINE}" ]]; then
    log "ERROR: baseline ASFF not found at ${CRYPTAMAP_BASELINE}."
    log "Seed it once from a clean run (see README.md 'Seeding the baseline')."
    exit 2
  fi

  if command -v go >/dev/null 2>&1; then
    log "diffing critical set with the Go helper (baseline-diff.go)"
    go run "${REPO_ROOT}/examples/ci-cd/baseline-diff.go" \
      -baseline "${CRYPTAMAP_BASELINE}" -current "${current_asff}"
    return
  fi

  command -v jq >/dev/null 2>&1 || {
    log "ERROR: need either 'go' or 'jq' to diff the critical set."
    exit 2
  }
  log "diffing critical set with jq (Go not available)"
  # Stable identity key per finding: AwsAccountId | Resources[0].Id | Title.
  # The volatile ASFF .Id (per-run UUID) and timestamps are deliberately ignored.
  local key='.[] | select(.Severity.Label=="CRITICAL")
      | (.AwsAccountId + "|" + (.Resources[0].Id // "") + "|" + .Title)'
  local introduced
  introduced="$(comm -13 \
    <(jq -r "${key}" "${CRYPTAMAP_BASELINE}" | sort -u) \
    <(jq -r "${key}" "${current_asff}" | sort -u))"
  local base_n cur_n
  base_n="$(jq -r '[.[] | select(.Severity.Label=="CRITICAL")] | length' "${CRYPTAMAP_BASELINE}")"
  cur_n="$(jq -r '[.[] | select(.Severity.Label=="CRITICAL")] | length' "${current_asff}")"
  log "gating on CRITICAL — baseline=${base_n} current=${cur_n}"
  if [[ -z "${introduced}" ]]; then
    log "no NEW CRITICAL findings — gate PASSED."
    return 0
  fi
  log "NEW CRITICAL finding(s) not in baseline — gate FAILED:"
  # One line per introduced finding. Read line-by-line so resource names with
  # spaces or glob characters are printed verbatim (no word-splitting/globbing).
  while IFS= read -r finding; do
    printf '  + CRITICAL | %s\n' "${finding}" >&2
  done <<< "${introduced}"
  log "If accepted, re-seed the baseline (see README.md)."
  return 1
}

main() {
  assume_readonly_role
  run_scan

  local cbom asff
  cbom="$(newest_artifact .cbom.json)"
  asff="$(newest_artifact .asff.json)"
  [[ -n "${cbom}" ]] || { log "ERROR: no .cbom.json produced in ${CRYPTAMAP_OUTPUT_DIR}"; exit 2; }
  [[ -n "${asff}" ]] || { log "ERROR: no .asff.json produced in ${CRYPTAMAP_OUTPUT_DIR}"; exit 2; }
  log "dated CBOM:  ${cbom}"
  log "dated ASFF:  ${asff}"

  sign_cbom "${cbom}"
  diff_against_baseline "${asff}"
  log "QBOM pipeline complete."
}

main "$@"
