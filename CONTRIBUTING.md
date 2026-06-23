# Contributing Guidelines

Thank you for your interest in contributing to CryptaMap. Whether it's a bug
report, new feature, correction, or additional documentation, we greatly value
feedback and contributions from our community.

Please read through this document before submitting any issues or pull requests
to ensure we have all the necessary information to effectively respond to your
bug report or contribution.

## Reporting Bugs/Feature Requests

We welcome you to use the GitHub issue tracker to report bugs or suggest features.

When filing an issue, please check existing open, or recently closed, issues to
make sure somebody else hasn't already reported the issue. Please try to include
as much information as you can. Details like these are incredibly useful:

- A reproducible test case or series of steps
- The version of our code being used
- Any modifications you've made relevant to the bug
- Anything unusual about your environment or deployment

## Contributing via Pull Requests

Contributions via pull requests are much appreciated. Before sending us a pull
request, please ensure that:

1. You are working against the latest source on the `main` branch.
2. You check existing open, and recently merged, pull requests to make sure
   someone else hasn't addressed the problem already.
3. You open an issue to discuss any significant work — we would hate for your
   time to be wasted.

To send us a pull request, please:

1. Fork the repository.
2. Modify the source; please focus on the specific change you are contributing.
   If you also reformat all the code, it will be hard for us to focus on your
   change.
3. Ensure local tests pass: `go test ./internal/... ./pkg/... ./cmd/...` and `make
   build`. (Scope the build/test to these module paths rather than `./...`: the
   CDK app vendors AWS CDK init-template `.go` files under `cdk/node_modules` that
   are not valid standalone Go, so a bare `go build ./...`/`go test ./...` reports
   errors on those template files — this is expected and CI scopes around it.) New scanners must
   keep mock coverage at 100% (`go run ./cmd/gen-dashboard-mock -check` and the
   `internal/mock` coverage test enforce this), and any IAM action a new scanner
   needs must be added to `cmd/gen-policy` (run `go run ./cmd/gen-policy -check`).
4. Commit to your fork using clear commit messages.
5. Send us a pull request, answering any default questions in the pull request
   interface.
6. Pay attention to any automated CI failures reported in the pull request, and
   stay involved in the conversation.

GitHub provides additional document on [forking a repository](https://help.github.com/articles/fork-a-repo/)
and [creating a pull request](https://help.github.com/articles/creating-a-pull-request/).

## Project conventions

- **No real account data.** Never commit a real AWS account ID, ARN, bucket name,
  private key, or customer identifier. Demo data is generated synthetically by
  `cmd/gen-dashboard-mock`. CI runs a secret/identifier scan that fails the build
  on these.
- **Honesty over coverage.** A scanner must never fabricate a posture or a
  compliance control ID. When state cannot be determined, emit `unknown` with a
  note — never a false all-clear or a false alarm.

## Finding contributions to work on

Looking at the existing issues is a great way to find something to contribute on.
As our projects, by default, use the default GitHub issue labels
(enhancement/bug/duplicate/help wanted/invalid/question/wontfix), looking at any
'help wanted' issues is a great place to start.

## Code of Conduct

This project has adopted the [Amazon Open Source Code of Conduct](https://aws.github.io/code-of-conduct).
For more information see the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq)
or contact opensource-codeofconduct@amazon.com with any additional questions or
comments.

## Security issue notifications

If you discover a potential security issue in this project we ask that you notify
AWS/Amazon Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/).
Please do **not** create a public GitHub issue.

## Licensing

See the [LICENSE](LICENSE) file for our project's licensing. We will ask you to
confirm the licensing of your contribution.
