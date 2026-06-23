#!/usr/bin/env bash
#
# release-build.sh — produce air-gap-ready release binaries of the CryptaMap CLI.
#
# It cross-compiles the CLI for the four supported desktop/server targets
# (darwin/amd64, darwin/arm64, linux/amd64, linux/arm64) into
# dist/release/cryptamap-<os>-<arch>, then writes a single dist/release/SHA256SUMS
# manifest covering every binary.
#
# Builds are reproducible-leaning: CGO_ENABLED=0 (static, no host libc) and
# -ldflags="-s -w" (strip symbol + DWARF tables) — the same flags the Lambda
# bootstrap uses in the Makefile.
#
# SIGNING IS NOT DONE HERE. Air-gapped operators sign SHA256SUMS with their OWN
# offline key (minisign or cosign); this script only documents and STAGES the
# exact commands. It generates no keys, signs nothing, and makes no network or
# AWS calls. See examples/airgap/VERIFY.md for the operator-side verify flow.
#
# Usage:
#   ./scripts/release-build.sh                 # build all four targets
#   VERSION=1.2.0 ./scripts/release-build.sh    # override the embedded version label
#   GOOS=linux GOARCH=arm64 ./scripts/release-build.sh   # build ONLY that target
#
# When GOOS and GOARCH are both set in the environment, only that single
# target is built (handy for CI matrices and for the package's own smoke test).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${REPO_ROOT}/dist"
RELEASE_DIR="${DIST}/release"
CMD_PKG="./cmd/cryptamap"

# The release label. Defaults to the toolVersion const in cmd/cryptamap/main.go
# so the release name tracks the in-binary version even when no override is given.
# If the CLI ever exposes a package-level `var version` (instead of the current
# const), we inject VERSION into it via -ldflags -X; otherwise the const wins and
# VERSION is used only to name the artifacts.
default_version() {
  grep -oE 'toolVersion[[:space:]]*=[[:space:]]*"[^"]+"' "${REPO_ROOT}/cmd/cryptamap/main.go" 2>/dev/null \
    | grep -oE '"[^"]+"' | tr -d '"' | head -1
}
VERSION="${VERSION:-$(default_version)}"
VERSION="${VERSION:-dev}"

# Detect whether main has an injectable package-level `var version` (not the
# current const). Only then is an -X ldflag safe — injecting into a const fails
# the build. This keeps the script correct today and future-proof if the const
# is ever promoted to a var.
LDFLAGS="-s -w"
if grep -qE '^var[[:space:]]+version[[:space:]]' "${REPO_ROOT}/cmd/cryptamap/main.go" 2>/dev/null; then
  LDFLAGS="${LDFLAGS} -X main.version=${VERSION}"
fi

# The supported release targets. Override by exporting BOTH GOOS and GOARCH to
# build a single target (the script honours the environment for CI matrices).
TARGETS=(
  "darwin/amd64"
  "darwin/arm64"
  "linux/amd64"
  "linux/arm64"
)
if [[ -n "${GOOS:-}" && -n "${GOARCH:-}" ]]; then
  TARGETS=("${GOOS}/${GOARCH}")
  echo "[release] single-target build requested via environment: ${GOOS}/${GOARCH}"
fi

mkdir -p "${RELEASE_DIR}"
echo "[release] version label : ${VERSION}"
echo "[release] ldflags        : ${LDFLAGS}"
echo "[release] output dir     : ${RELEASE_DIR}"

BUILT=()
for target in "${TARGETS[@]}"; do
  os="${target%/*}"
  arch="${target#*/}"
  out="${RELEASE_DIR}/cryptamap-${os}-${arch}"
  echo "[release] building ${os}/${arch} -> $(basename "${out}")"
  ( cd "${REPO_ROOT}" && \
    GOOS="${os}" GOARCH="${arch}" CGO_ENABLED=0 \
    go build -trimpath -ldflags="${LDFLAGS}" -o "${out}" "${CMD_PKG}" )
  BUILT+=("${out}")
done

# Generate the SHA256SUMS manifest. Paths are relative to dist/release/ so the
# manifest verifies cleanly with `sha256sum -c SHA256SUMS` from inside that dir
# on the air-gapped host (no absolute paths to rewrite).
echo "[release] writing SHA256SUMS manifest"
(
  cd "${RELEASE_DIR}"
  : > SHA256SUMS
  for out in "${BUILT[@]}"; do
    name="$(basename "${out}")"
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "${name}" >> SHA256SUMS
    else
      # macOS / BSD: emit the same `<hash>  <name>` format sha256sum -c expects.
      printf '%s  %s\n' "$(shasum -a 256 "${name}" | awk '{print $1}')" "${name}" >> SHA256SUMS
    fi
  done
)

echo
echo "[release] artifacts in ${RELEASE_DIR}:"
( cd "${RELEASE_DIR}" && ls -la cryptamap-* SHA256SUMS )
echo
echo "[release] SHA256SUMS:"
cat "${RELEASE_DIR}/SHA256SUMS"

# ---------------------------------------------------------------------------
# Operator signing instructions (NOT executed — no keys are touched here).
#
# Sign ONLY the SHA256SUMS manifest: it transitively covers every binary, so one
# detached signature authenticates the whole release. The operator signs offline
# with their own key; CryptaMap ships no signing key.
# ---------------------------------------------------------------------------
cat <<EOF

[release] NEXT — sign the manifest OFFLINE with your own key (this script signs nothing).

  Option A — minisign (https://jedisct1.github.io/minisign/)
    # one-time, on a trusted offline machine:
    minisign -G                                   # generate your key pair
    # sign the manifest (produces SHA256SUMS.minisig):
    minisign -Sm "${RELEASE_DIR}/SHA256SUMS"
    # operators verify with your PUBLIC key:
    minisign -Vm SHA256SUMS -p minisign.pub

  Option B — cosign (https://docs.sigstore.dev/), keyed (air-gap friendly):
    # one-time:
    cosign generate-key-pair                      # -> cosign.key / cosign.pub
    # sign the manifest as a blob (produces SHA256SUMS.sig):
    cosign sign-blob --key cosign.key --output-signature "${RELEASE_DIR}/SHA256SUMS.sig" "${RELEASE_DIR}/SHA256SUMS"
    # operators verify with your PUBLIC key:
    cosign verify-blob --key cosign.pub --signature SHA256SUMS.sig SHA256SUMS

Distribute these files together for side-loading onto the air-gapped host:
  cryptamap-<os>-<arch>   (the binaries)
  SHA256SUMS              (the manifest)
  SHA256SUMS.minisig OR SHA256SUMS.sig   (your detached signature)
  your PUBLIC key         (minisign.pub or cosign.pub)

See examples/airgap/VERIFY.md for the operator-side offline verification steps.
EOF
