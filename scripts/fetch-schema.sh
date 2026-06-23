#!/usr/bin/env bash
# Fetches the official CycloneDX 1.7 schema bundle into testdata/schemas/.
# The schema validation test (internal/output/cyclonedx_test.go) skips when
# the bundle is missing, so re-run this whenever upgrading CycloneDX versions.
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p testdata/schemas
curl -fsSL https://cyclonedx.org/schema/bom-1.7.schema.json -o testdata/schemas/cdx-bom-1.7.schema.json
curl -fsSL https://cyclonedx.org/schema/spdx.schema.json -o testdata/schemas/spdx.schema.json
curl -fsSL https://cyclonedx.org/schema/jsf-0.82.schema.json -o testdata/schemas/jsf-0.82.schema.json
curl -fsSL https://cyclonedx.org/schema/cryptography-defs.schema.json -o testdata/schemas/cryptography-defs.schema.json

echo "Fetched CycloneDX 1.7 schema bundle:"
ls -la testdata/schemas/
