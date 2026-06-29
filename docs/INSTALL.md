# Install & build prerequisites

CryptaMap is distributed as **source you build yourself** — there is no prebuilt
download (see [No prebuilt binary](#no-prebuilt-binary)). This page lists the exact
toolchain, the two build targets, the IAM an operator needs to run a local scan, and
a couple of repo-specific gotchas.

## Toolchain

| Tool | Version | Where it is pinned |
|---|---|---|
| Go | **1.26.2** | `go.mod` (`go 1.26.2`); CI installs via `go-version-file: go.mod` |
| Node.js | **20** | `.github/workflows/ci.yml` (dashboard + CDK jobs) |
| npm | (ships with Node 20) | not separately pinned |

> These are the only authoritative pins. There is **no `.nvmrc` and no `engines`
> field** — the Node 20 requirement lives only in the CI workflow, so other Node
> majors are untested. Go is required even for the deploy path, because the policy
> generator and the Lambda bootstrap are Go programs.

## The two build targets

```bash
make build-cli      # -> ./dist/cryptamap   (CLI only; placeholder dashboard UI)
make build-serve    # -> ./dist/cryptamap   (CLI WITH the real dashboard embedded)
```

- **`make build-cli`** runs `go build -o ./dist/cryptamap ./cmd/cryptamap`. The
  resulting binary scans and writes all artifacts, but `cryptamap serve` shows only a
  placeholder page — plain `go build` embeds a committed placeholder bundle.
- **`make build-serve`** builds the dashboard (`cd dashboard && npm run build`,
  i.e. `tsc -b && vite build`) and copies `dashboard/dist` into
  `cmd/cryptamap/webdist` before the Go build, so the real Cloudscape UI is embedded.
  Use this if you want the local dashboard.

### How the dashboard is embedded

The binary embeds the UI with Go `//go:embed all:webdist`. Because `go:embed` cannot
reference a directory outside its own package, `make build-serve` copies the Vite
output (`dashboard/dist`) into `cmd/cryptamap/webdist` first. As a safety guard,
`build-serve` deletes any `*.local.json` from the staged bundle and **fails the build
if any survive**, so real-account data can never be baked into the binary.

## No prebuilt binary

No prebuilt or signed release artifact is published. `SECURITY.md`'s reference to
"the latest release" means **build from the latest `main`**. For offline/air-gapped
distribution, `make release` runs `scripts/release-build.sh`, which cross-compiles
locally into `dist/release` for four targets (`darwin/amd64`, `darwin/arm64`,
`linux/amd64`, `linux/arm64`) and writes a `SHA256SUMS` manifest. Binaries are built
static and stripped (`CGO_ENABLED=0`, `-trimpath -ldflags="-s -w"`). Code signing is
operator-side and deferred; for air-gap verification see
[`examples/airgap/VERIFY.md`](../examples/airgap/VERIFY.md).

## IAM for the local operator (Path 2, single-account scan)

The single-account CLI scan uses **your own ambient/default-profile credentials
directly** — it does **not** assume `CryptaMapScannerRole` (that role is only used by
the deployed org fan-out). So the principal you run as must itself hold the read
actions.

**Minimum policy = the canonical least-privilege read list** — the **140 `readActions`**
in [`cdk/policy/scanner-actions.json`](../cdk/policy/scanner-actions.json), generated
from `cmd/gen-policy/main.go` and kept honest by `make check-policy`. (The same file
also defines 3 orchestrator-only *writes* — `s3:PutObject`, `dynamodb:PutItem`,
`securityhub:BatchImportFindings` — which the local operator does **not** need.) The
140-action read list is **narrower than the AWS-managed `ReadOnlyAccess` policy**,
which CryptaMap deliberately avoids.

You may further trim it for a strictly single-account run:

- **`organizations:ListAccounts`** is not needed — it is only used by the org
  fan-out to enumerate member accounts. The CLI scans only the caller account (it
  *warns* and ignores `--org` / `--accounts`).
- **None of the three orchestrator writes** (`s3:PutObject`, `dynamodb:PutItem`,
  `securityhub:BatchImportFindings`) are needed — the CLI writes every artifact to
  **local files**.

Beyond the per-service read actions, the CLI itself calls only
`sts:GetCallerIdentity` (to resolve the account id) and, with `--regions all`,
`ec2:DescribeRegions` — both already in the list.

## Repo gotcha: scope your Go commands

```bash
# Do this:
go build ./internal/... ./pkg/... ./cmd/...
go test  ./internal/... ./pkg/... ./cmd/...

# NOT this — it fails:
go build ./...
```

Bare `./...` fails because `cdk/node_modules` vendors invalid standalone `.go`
init-template files. CI works around this by not running `npm ci` in the Go job; you
should scope to the module packages as shown.
