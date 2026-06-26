.PHONY: build build-cli build-cdk build-dashboard build-serve release test mock integration deploy synth clean lint lint-terms generate-types check-types generate-knowledge check-knowledge generate-policy check-policy

GOPACKAGES = ./internal/... ./pkg/... ./cmd/...
DIST       = ./dist
LAMBDA     = $(DIST)/lambda

build: build-cli build-cdk build-dashboard ## Build all artefacts

build-cli: ## Build the CryptaMap CLI for the host platform
	@mkdir -p $(DIST)
	go build -o $(DIST)/cryptamap ./cmd/cryptamap

build-lambda: ## Build the Lambda bootstrap binary (linux/arm64)
	@mkdir -p $(LAMBDA)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags lambda -ldflags="-s -w" -o $(LAMBDA)/bootstrap ./cmd/cryptamap

build-cdk: ## Build CDK TypeScript and synth templates
	cd cdk && npm run build && npx cdk synth >/dev/null

build-dashboard: ## Build the React dashboard
	cd dashboard && npm run build

build-serve: build-dashboard ## Build the CLI with the real dashboard embedded for `cryptamap serve`
	@rm -rf cmd/cryptamap/webdist
	@mkdir -p cmd/cryptamap/webdist
	cp -R dashboard/dist/. cmd/cryptamap/webdist/
	@# LEAK GUARD: never embed real-account data into the shipped binary. *.local.json
	@# is the local real-org-data convention; go:embed ignores .gitignore, so strip them
	@# from the staged bundle, then FAIL the build if any survive (a tripped guard means
	@# real data almost entered a distributable artifact).
	@find cmd/cryptamap/webdist -name '*.local.json' -delete
	@if find cmd/cryptamap/webdist -name '*.local.json' | grep -q .; then \
		echo "ERROR: *.local.json present in embed staging — refusing to build (real-data leak guard)"; exit 1; \
	fi
	@mkdir -p $(DIST)
	go build -o $(DIST)/cryptamap ./cmd/cryptamap
	@echo "Built $(DIST)/cryptamap with the dashboard embedded. Bundled /mock data is the SYNTHETIC demo (mode=mock); real-data *.local.json is stripped by the leak guard. NOTE: cmd/cryptamap/webdist is staged build output (gitignored); the committed placeholder keeps plain 'go build' working."

release: ## Cross-compile signed-ready air-gap release binaries into dist/release
	bash scripts/release-build.sh

generate-knowledge: ## Regenerate the embedded PQC knowledge JSON from the Go literals
	go run ./cmd/gen-knowledge

check-knowledge: ## Fail if the embedded PQC knowledge JSON is stale (CI staleness guard)
	go run ./cmd/gen-knowledge -check

generate-policy: ## Regenerate the scanner IAM action artifacts from the Go source list (single source of truth)
	go run ./cmd/gen-policy

check-policy: ## Fail if the scanner IAM action artifacts are stale (CI drift guard for least-privilege policy)
	go run ./cmd/gen-policy -check

generate-types: ## Generate dashboard TS types from the Go models (single source of truth)
	go run ./cmd/gen-ts

check-types: generate-types ## Fail if dashboard/src/types/generated.ts is stale (regenerate + diff)
	@git diff --exit-code -- dashboard/src/types/generated.ts \
		|| { echo "ERROR: dashboard/src/types/generated.ts is stale. Run 'make generate-types' and commit."; exit 1; }

test: ## Run Go unit tests with coverage
	go test $(GOPACKAGES) -cover

test-verbose: ## Run Go unit tests verbose
	go test $(GOPACKAGES) -v -cover

vet: ## Run go vet
	go vet $(GOPACKAGES)

mock: build-cli ## Run a mock end-to-end scan
	@mkdir -p $(DIST)/mock-output
	$(DIST)/cryptamap --mock --mock-scale 10 --regions us-east-1,ap-south-1 --output-dir $(DIST)/mock-output

mock-small: build-cli ## Run a small mock scan
	$(DIST)/cryptamap --mock --mock-scale 3 --regions ap-south-1 --output-dir $(DIST)/mock-output

scan: build-cli ## Run a live scan in the configured AWS account/region
	$(DIST)/cryptamap --regions ap-south-1 --output-dir $(DIST)/scan-output --verbose

synth: build-cdk ## CDK synth (no deploy)
	cd cdk && npx cdk synth

deploy: build-lambda build-cdk build-dashboard ## CDK deploy to current AWS account
	cd cdk && npx cdk deploy --all --require-approval never

destroy: ## Tear down CryptaMap CDK stacks (DESTRUCTIVE)
	cd cdk && npx cdk destroy --all --force

clean: ## Remove build artefacts
	rm -rf $(DIST) cdk/cdk.out dashboard/dist

lint-terms: ## Banned-term gate: fail if user-visible "quantum-safe" wording regresses (use "quantum-resistant")
	bash scripts/lint-terms.sh

lint: lint-terms ## Run linters
	go vet $(GOPACKAGES)
	cd dashboard && npm run lint || true

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
