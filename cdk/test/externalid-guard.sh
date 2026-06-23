#!/usr/bin/env bash
# Regression guard for fix H5 (LocalScannerRole trust hardening).
#
# Asserts the two security invariants added to the CDK app:
#
#   1. ORG SCANNING REFUSES THE PUBLIC DEFAULT EXTERNAL ID.
#      `cdk synth -c orgScanningEnabled=true` with NO scannerExternalId override
#      MUST fail (the public literal 'cryptamap-scanner' cannot be used for a real
#      org install). Before H5 this synthesized cleanly — that is the regression.
#
#   2. THE LOCAL (management-account) SCANNER ROLE TRUST MIRRORS THE MEMBER ROLE.
#      With a private ExternalId, synth MUST succeed AND the LocalScannerRole's
#      AssumeRolePolicyDocument MUST carry the SAME confused-deputy guard as the
#      member StackSet template (scanner-role-template.json): a StringEquals
#      Condition on both aws:PrincipalOrgID and sts:ExternalId. Before H5 the
#      LocalScannerRole had no Condition at all.
#
# Run from anywhere; resolves paths relative to this script. Requires the CDK
# toolchain (cdk/node_modules) and a dist/lambda asset to exist (the normal
# build produces it; this guard only inspects the Security stack template).
set -euo pipefail

CDK_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CDK_DIR"

fail() { echo "FAIL: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1) Org scanning WITHOUT a private ExternalId override must FAIL synth.
# ---------------------------------------------------------------------------
echo "[1/2] asserting org synth with public-default ExternalId is REFUSED..."
if npx cdk synth -c orgScanningEnabled=true >/tmp/h5-guard-fail.out 2>&1; then
  fail "synth with public default ExternalId succeeded; expected it to be refused"
fi
if ! grep -q "Refusing to deploy org scanning with the public default ExternalId" /tmp/h5-guard-fail.out; then
  fail "synth failed but not with the expected ExternalId-guard error"
fi
echo "      OK - refused with the expected error."

# ---------------------------------------------------------------------------
# 2) Org scanning WITH a private ExternalId must SUCCEED and the
#    LocalScannerRole trust must mirror the member StackSet template.
# ---------------------------------------------------------------------------
echo "[2/2] asserting org synth with a private ExternalId succeeds + LocalScannerRole trust is gated..."
npx cdk synth -c orgScanningEnabled=true -c organizationId=o-realtest \
  -c scannerExternalId=my-private-id >/dev/null 2>/tmp/h5-guard-ok.err \
  || fail "synth with a private ExternalId failed (see /tmp/h5-guard-ok.err)"

python3 - "$CDK_DIR/cdk.out/CryptaMap-Security.template.json" <<'PY' || fail "LocalScannerRole trust assertion failed"
import json, sys
with open(sys.argv[1]) as f:
    tmpl = json.load(f)
roles = [
    r for r in tmpl["Resources"].values()
    if r["Type"] == "AWS::IAM::Role"
    and r["Properties"].get("RoleName") == "CryptaMapScannerRole"
]
assert len(roles) == 1, f"expected exactly one CryptaMapScannerRole, got {len(roles)}"
stmts = roles[0]["Properties"]["AssumeRolePolicyDocument"]["Statement"]
assert len(stmts) == 1, f"expected one trust statement, got {len(stmts)}"
cond = stmts[0].get("Condition", {}).get("StringEquals", {})
assert cond.get("aws:PrincipalOrgID") == "o-realtest", \
    f"missing/incorrect aws:PrincipalOrgID condition: {cond!r}"
assert cond.get("sts:ExternalId") == "my-private-id", \
    f"missing/incorrect sts:ExternalId condition: {cond!r}"
print("      OK - LocalScannerRole trust has aws:PrincipalOrgID + sts:ExternalId.")
PY

echo "PASS: H5 ExternalId guard + LocalScannerRole trust regression checks."
