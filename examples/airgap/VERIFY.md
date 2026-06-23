# Verifying a CryptaMap release on an air-gapped host

CryptaMap ships as statically linked, stripped, cross-compiled binaries
(`CGO_ENABLED=0`, `-ldflags="-s -w"`) plus a single `SHA256SUMS` manifest. Before
you side-load and trust a binary on a disconnected host, verify **two** things,
entirely offline:

1. **Integrity** — the binary matches the checksum in `SHA256SUMS`.
2. **Authenticity** — `SHA256SUMS` itself was signed by the key you trust.

Both checks are local: no network, no AWS, no Sigstore transparency log.

## What you receive

Bundle these files onto removable media and carry them across the air gap:

| File | What it is |
| --- | --- |
| `cryptamap-<os>-<arch>` | the binary for your platform (e.g. `cryptamap-linux-arm64`) |
| `SHA256SUMS` | one `<sha256>  <filename>` line per binary |
| `SHA256SUMS.minisig` **or** `SHA256SUMS.sig` | the detached signature over `SHA256SUMS` |
| `minisign.pub` **or** `cosign.pub` | the signer's **public** key (verify this fingerprint out of band) |

The release was produced by `scripts/release-build.sh`. That script does **not**
sign — your release engineer signs `SHA256SUMS` offline with their own private
key, which never leaves the trusted machine.

## Step 1 — verify the manifest signature (authenticity)

Do this **first**: if the manifest is forged, its checksums are worthless.

### Option A — minisign

```sh
minisign -Vm SHA256SUMS -p minisign.pub
```

Expect `Signature and comment signature verified`. Any other output: STOP, do
not install. Confirm `minisign.pub` is the key you trust by checking its
fingerprint against a value obtained through a separate, trusted channel.

### Option B — cosign (keyed, air-gap friendly)

```sh
cosign verify-blob --key cosign.pub --signature SHA256SUMS.sig SHA256SUMS
```

Expect `Verified OK`. Use the **keyed** flow shown here — keyless/OIDC
verification needs the Sigstore transparency log and will not work air-gapped.

## Step 2 — verify the binary checksums (integrity)

Only after the signature checks out. From the directory holding the files:

```sh
# Linux (coreutils):
sha256sum --check --ignore-missing SHA256SUMS

# macOS / BSD (no sha256sum):
shasum -a 256 -c SHA256SUMS
```

`--ignore-missing` lets you verify just the one binary you carried across
without failing on the other platforms' entries. Expect `<file>: OK`. A
`FAILED` line means the binary does not match the signed manifest — discard it.

## Step 3 — install

Only once **both** steps pass:

```sh
chmod +x cryptamap-linux-arm64
mv cryptamap-linux-arm64 /usr/local/bin/cryptamap
cryptamap --version    # sanity check the embedded version label
```

## Why sign the manifest and not each binary

`SHA256SUMS` cryptographically commits to every binary's hash, so a single
detached signature over the manifest transitively authenticates the whole
release. Verifying one signature plus the checksum list is simpler — and harder
to get subtly wrong — than tracking a separate signature per binary.
