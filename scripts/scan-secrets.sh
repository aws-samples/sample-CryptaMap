#!/usr/bin/env bash
# scan-secrets.sh — fail (non-zero) if any tracked file contains data that must
# NEVER ship in a public repo:
#   * a real-looking 12-digit AWS account ID (anything NOT in the synthetic allowlist)
#   * a PEM private-key block
#   * a developer-machine absolute path (/Users/... or /home/<user>/...)
#   * a known-real bucket name from this project's history
#
# Run locally before committing, and in CI (the secret-scan job). It scans only
# git-TRACKED files (so node_modules / generated artifacts are out of scope).
# Portable to macOS bash 3.2 (no mapfile / no associative arrays).
#
#   ./scripts/scan-secrets.sh
#
# Allowlisted synthetic IDs: AWS-docs example ranges (123456789012, 111122223333,
# 444455556666, 000000000000), the synthetic demo org's 1111000000NN range, and
# 385979361815 (lives only in the upstream CycloneDX schema bundle under
# testdata/schemas/, which is excluded below anyway).
set -uo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# git pathspecs: all tracked files EXCEPT the upstream schema bundle (third-party
# JSON with an unrelated 12-digit number) and this script itself.
PATHSPEC=(':!testdata/schemas/' ':!scripts/scan-secrets.sh')

fail=0

# 1) Real-looking AWS account IDs, matched ONLY in an ACCOUNT-ID CONTEXT (not any
#    12 digits anywhere — that false-positives on go.sum hashes, dates, and random
#    bom-ref hex). Context = an ARN account segment (arn:partition:svc:region:ACCT:)
#    or an "accountId"/"account":"ACCT" JSON field. Allowlist = AWS-docs example IDs,
#    the obvious all-same/sequential test fakes, and the synthetic demo org range.
echo "[scan] AWS account IDs in ARN/accountId context outside the synthetic allowlist ..."
# Allowlist: AWS-docs example IDs, the synthetic demo-org range (1111000000NN), the
# obvious all-same-digit test fakes (111111111111 / 222222222222 / 000000000000 /
# 999999999999), and sequential test fakes (012345678901 / 210987654321).
allow='123456789012|111122223333|444455556666|555566667777|666677778888|999988887777|000000000000|111111111111|222222222222|333333333333|999999999999|012345678901|210987654321|1111000000[0-9][0-9]'
ids="$(git grep -hoE 'arn:[a-z0-9-]*:[a-z0-9-]*:[a-z0-9-]*:[0-9]{12}:|"account(Id)?"[[:space:]]*:[[:space:]]*"[0-9]{12}"' -- "${PATHSPEC[@]}" 2>/dev/null \
        | grep -oE '[0-9]{12}' | sort -u | grep -Ev "^($allow)$" || true)"
if [[ -n "$ids" ]]; then
  echo "  FAIL: non-allowlisted account ID(s) in ARN/accountId context:"
  while IFS= read -r id; do
    [[ -z "$id" ]] && continue
    echo "    $id  (in: $(git grep -lF "$id" -- "${PATHSPEC[@]}" | head -3 | tr '\n' ' '))"
  done <<< "$ids"
  fail=1
fi

# 2) PEM private-key blocks.
echo "[scan] PEM private-key blocks ..."
pk="$(git grep -lE 'BEGIN ([A-Z0-9 ]+ )?PRIVATE KEY' -- "${PATHSPEC[@]}" 2>/dev/null || true)"
if [[ -n "$pk" ]]; then echo "  FAIL: private key block(s) in:"; echo "$pk" | sed 's/^/    /'; fail=1; fi

# 3) Developer-machine absolute paths.
echo "[scan] developer-machine absolute paths ..."
dp="$(git grep -lE '/Users/[a-zA-Z]|/home/[a-zA-Z]+/' -- "${PATHSPEC[@]}" 2>/dev/null || true)"
if [[ -n "$dp" ]]; then echo "  FAIL: absolute dev path(s) in:"; echo "$dp" | sed 's/^/    /'; fail=1; fi

# 4) Known-real bucket name(s) from project history (defense-in-depth).
echo "[scan] known real bucket names ..."
b="$(git grep -lE 'cryptamap-data-resultsbucket' -- "${PATHSPEC[@]}" 2>/dev/null || true)"
if [[ -n "$b" ]]; then echo "  FAIL: real bucket name in:"; echo "$b" | sed 's/^/    /'; fail=1; fi

if [[ "$fail" -eq 0 ]]; then
  echo "[scan] OK — no real account IDs, private keys, dev paths, or real bucket names in tracked files."
else
  echo "[scan] FAILED — fix the findings above before committing/publishing."
fi
exit "$fail"
