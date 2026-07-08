#!/usr/bin/env bash
# Regression guard for fix H5 (LocalScannerRole trust hardening).
#
# Asserts the security invariants added to the CDK app:
#
#   1. ORG SCANNING REFUSES THE PUBLIC DEFAULT EXTERNAL ID.
#      `cdk synth -c orgScanningEnabled=true` with NO scannerExternalId override
#      MUST fail (the public literal 'cryptamap-scanner' cannot be used for a real
#      org install). Before H5 this synthesized cleanly — that is the regression.
#
#   2. ORG SCANNING REFUSES A SILENT ALERT TOPIC.
#      With no -c alertEmail, org synth MUST fail (alarms/budget would publish to
#      a subscriber-less SNS topic); -c allowSilentAlerts=true is the explicit
#      demo/eval escape hatch.
#
#   3. THE LOCAL (management-account) SCANNER ROLE TRUST MIRRORS THE MEMBER ROLE.
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
# 0) `-c orgScanningEnabled=false` must actually DISABLE org scanning.
#    CLI context values arrive as strings; before the asBool coercer in
#    bin/app.ts the string "false" was truthy, so an operator explicitly
#    disabling org scanning deployed the full org fan-out (fail-open).
# ---------------------------------------------------------------------------
echo "[0/3] asserting -c orgScanningEnabled=false disables the org fan-out..."
npx cdk ls -c orgScanningEnabled=false >/tmp/h5-guard-lsfalse.out 2>&1 \
  || fail "cdk ls -c orgScanningEnabled=false errored (string 'false' likely treated as true; see /tmp/h5-guard-lsfalse.out)"
if grep -q 'OrgFanout' /tmp/h5-guard-lsfalse.out; then
  fail "orgScanningEnabled=false still synthesized the OrgFanout stack (string-'false' treated as true)"
fi
echo "      OK - no OrgFanout stack when orgScanningEnabled=false."

# ---------------------------------------------------------------------------
# 1) Org scanning WITHOUT a private ExternalId override must FAIL synth.
# ---------------------------------------------------------------------------
echo "[1/3] asserting org synth with public-default ExternalId is REFUSED..."
if npx cdk synth -c orgScanningEnabled=true >/tmp/h5-guard-fail.out 2>&1; then
  fail "synth with public default ExternalId succeeded; expected it to be refused"
fi
if ! grep -q "Refusing to deploy org scanning with the public default ExternalId" /tmp/h5-guard-fail.out; then
  fail "synth failed but not with the expected ExternalId-guard error"
fi
echo "      OK - refused with the expected error."

# ---------------------------------------------------------------------------
# 2) Org scanning with NO alertEmail must FAIL synth (silent-alerts guard);
# 3) org scanning WITH a private ExternalId (+ the explicit allowSilentAlerts
#    escape hatch) must SUCCEED and the LocalScannerRole trust must mirror the
#    member StackSet template.
# ---------------------------------------------------------------------------
echo "[2/3] asserting org synth with no alertEmail is REFUSED (silent-alerts guard)..."
# Same guard class as the ExternalId check: org alarms/budget with a
# subscriber-less SNS topic would fire into the void, so app.ts refuses unless
# -c alertEmail is set or -c allowSilentAlerts=true is passed explicitly.
if npx cdk synth -c orgScanningEnabled=true -c organizationId=o-realtest \
  -c orgRootId=r-realtest1 \
  -c scannerExternalId=my-private-id >/tmp/h5-guard-silent.out 2>&1; then
  fail "org synth with no alertEmail succeeded; expected the silent-alerts guard to refuse"
fi
if ! grep -q "Refusing to deploy org scanning with no alert subscriber" /tmp/h5-guard-silent.out; then
  fail "synth failed but not with the expected silent-alerts-guard error"
fi
echo "      OK - refused with the expected error."

echo "[3/3] asserting org synth with a private ExternalId succeeds + LocalScannerRole trust is gated..."
# orgRootId is required too: app.ts refuses org synth with the placeholder
# 'r-exam' root id (the same class of guard as the ExternalId check above).
# allowSilentAlerts=true is the documented demo/eval escape hatch for the
# silent-alerts guard asserted above (this is a synth-only test, no real ops).
npx cdk synth -c orgScanningEnabled=true -c organizationId=o-realtest \
  -c orgRootId=r-realtest1 \
  -c scannerExternalId=my-private-id -c allowSilentAlerts=true >/dev/null 2>/tmp/h5-guard-ok.err \
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
