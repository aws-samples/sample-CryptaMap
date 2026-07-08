# Third-Party Notices

CryptaMap is distributed under the MIT No Attribution (MIT-0) license (see
[`LICENSE`](./LICENSE)). It redistributes and/or depends on third-party open
source software that is licensed under its own terms.

**This file is a hand-authored summary of the MAJOR direct dependencies only.**
It is not exhaustive and is not the authoritative license text. The complete,
authoritative per-module license text ships with each module:

- **Go modules** — the full dependency set (direct and indirect) is recorded in
  [`go.mod`](./go.mod) / [`go.sum`](./go.sum); each module's `LICENSE` file is
  present in the Go module cache and in any vendored copy.
- **npm packages** — see the `LICENSE` file inside each package under
  `dashboard/node_modules/<pkg>` and `cdk/node_modules/<pkg>`.

For a machine-generated, complete report at release time, run
`make third-party-notices` (see the `Makefile`), which uses `go-licenses` and
`license-checker` to enumerate every transitive dependency and its license.
That step is deferred to release-time tooling and is not run in this repository.

License identifiers below use [SPDX](https://spdx.org/licenses/) short names.

---

## Go modules (from `go.mod` require block — direct dependencies)

| Module | License |
|---|---|
| `github.com/aws/aws-cdk-go/awscdk/v2` | Apache-2.0 |
| `github.com/aws/aws-lambda-go` | Apache-2.0 |
| `github.com/aws/aws-sdk-go-v2` (core) | Apache-2.0 |
| `github.com/aws/aws-sdk-go-v2/config` | Apache-2.0 |
| `github.com/aws/aws-sdk-go-v2/credentials` | Apache-2.0 |
| `github.com/aws/aws-sdk-go-v2/service/*` (all AWS service clients — acm, acmpca, apigateway, appmesh, athena, backup, bedrock, cloudfront, cloudtrail, dynamodb, ec2, ecr, ecs, eks, iam, kms, lambda, rds, s3, sagemaker, secretsmanager, sns, sqs, ssm, sts, and the many others listed in `go.mod`) | Apache-2.0 |
| `github.com/aws/constructs-go/constructs/v10` | Apache-2.0 |
| `github.com/aws/jsii-runtime-go` | Apache-2.0 |
| `github.com/aws/smithy-go` | Apache-2.0 |
| `github.com/google/uuid` | BSD-3-Clause |
| `github.com/santhosh-tekuri/jsonschema/v5` | Apache-2.0 |
| `github.com/spf13/cobra` | Apache-2.0 |
| `github.com/xuri/excelize/v2` | BSD-3-Clause |
| `gopkg.in/yaml.v3` | MIT and Apache-2.0 (dual; see module LICENSE) |

Indirect Go dependencies (marked `// indirect` in `go.mod`) are omitted from this
summary; their licenses are predominantly Apache-2.0, BSD-3-Clause, and MIT. See
each module's `LICENSE` for the authoritative text.

## npm packages — dashboard (`dashboard/package.json` dependencies)

| Package | License |
|---|---|
| `@cloudscape-design/collection-hooks` | Apache-2.0 |
| `@cloudscape-design/components` | Apache-2.0 |
| `@cloudscape-design/global-styles` | Apache-2.0 |
| `html2pdf.js` | MIT |
| `react` | MIT |
| `react-dom` | MIT |
| `react-router-dom` | MIT |

## npm packages — CDK (`cdk/package.json` dependencies)

| Package | License |
|---|---|
| `aws-cdk-lib` | Apache-2.0 |
| `constructs` | Apache-2.0 |

---

If you believe a dependency or its license is misattributed here, please open an
issue. The definitive license for any module is the `LICENSE` file distributed
with that module.
