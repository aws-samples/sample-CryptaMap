# Importing CryptaMap findings into AWS Security Hub

CryptaMap **does not push findings to Security Hub itself.** A scan writes a local
ASFF file (`<prefix>.asff.json`) — a JSON **array** of findings, stamped with
SchemaVersion `2018-10-08` — and you import it. This keeps the tool read-only against
your account and lets you decide when and where findings land.

## Prerequisites

1. **Enable Security Hub** in the target account **and region**. Findings carry a
   per-finding `Region`, and you must import them in that same region.
2. **No custom product onboarding is required.** CryptaMap stamps the built-in
   *default* product ARN —
   `arn:<partition>:securityhub:<region>:<account>:product/<account>/default` — so
   there is nothing to register; the default product is the standard path for
   importing custom findings.
3. **Permission:** the importing principal needs `securityhub:BatchImportFindings`
   scoped to that `product/<account>/default` ARN (this is exactly the statement the
   deployed orchestrator role gets — see `DEPLOYMENT.md` §3 and
   `cmd/gen-policy/main.go`).

## Import command

```bash
aws securityhub batch-import-findings \
  --region <REGION> \
  --findings file://path/to/<scan>.asff.json
```

The emitted file is already a `Findings` array, so it maps directly to `--findings`.

### Batches of 100

`BatchImportFindings` accepts at most **100 findings per call** (an AWS API limit).
For a larger array, split it first — for example with `jq`:

```bash
jq -c '.[]' <scan>.asff.json | split -l 100 - chunk_
for f in chunk_*; do
  jq -s '.' "$f" > "$f.json"
  aws securityhub batch-import-findings --region <REGION> --findings "file://$f.json"
done
```

## Multi-account / multi-region notes

- The `ProductArn` **account segment must equal the finding's `AwsAccountId`**, or
  Security Hub rejects that finding. CryptaMap sets both from the scanned resource, so
  they already match — just import in the matching account/region (or use Security Hub
  cross-region aggregation / a delegated administrator to centralize).
- **Partitions** (GovCloud/China) are handled automatically: the `ProductArn` and the
  ASFF `Partition` follow the finding's region.

## Placeholder guard

If the configured `output.security_hub.product_arn` still contains an unexpanded
`${ACCOUNT}` / `${REGION}` token (e.g. account/region could not be resolved), the
local ASFF validator **fails fast** with an "unexpanded `${...}` placeholder" error
rather than letting `BatchImportFindings` reject it downstream. Set a concrete
`product_arn`, or rely on the default per-finding substitution.

## After import: optional alerting

If you deployed the `CryptaMap-Alerting` stack, an EventBridge rule matches imported
CryptaMap findings with `Severity.Label = CRITICAL` and routes them to a
CMK-encrypted SNS topic (email subscription) — see `cdk/lib/alerting-stack.ts`.
