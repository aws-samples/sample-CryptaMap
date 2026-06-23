package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// propPrefix is the cryptamap-namespaced property prefix emitted by buildCBOM.
const propPrefix = "cryptamap:"

// ParseCBOMFile reads a CycloneDX 1.7 CBOM JSON file from disk and reconstructs
// it into one or more models.ScanResult shards (one per distinct
// (accountId, region) tuple found in the components). It is the inverse of
// buildCBOM and reuses the same CDX* structs declared in cyclonedx.go.
//
// The returned ScanResults have Assets populated but Findings empty; callers
// regenerate findings deterministically via scanner.BuildFindings. Mode is set
// to "live" so the merge package's source-precedence matches a real live scan.
func ParseCBOMFile(path string) ([]models.ScanResult, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CBOM file %s: %w", path, err)
	}
	scans, err := ParseCBOM(raw)
	if err != nil {
		return nil, fmt.Errorf("parse CBOM file %s: %w", path, err)
	}
	return scans, nil
}

// ParseCBOM reconstructs models.ScanResult shards from CBOM JSON bytes. Pure
// (encoding/json + pkg/models), no AWS SDK and no other I/O.
func ParseCBOM(raw []byte) ([]models.ScanResult, error) {
	var bom CDXBOM
	if err := json.Unmarshal(raw, &bom); err != nil {
		return nil, fmt.Errorf("unmarshal CBOM: %w", err)
	}

	// Metadata-level scan context (best-effort; per-asset props are authoritative).
	meta := propMap(bom.Metadata.Properties)
	metaScanID := stripScanRefPrefix(bom.Metadata.Component.BomRef)
	if v := meta["scanId"]; v != "" {
		metaScanID = v
	}
	metaMode := meta["mode"]
	if metaMode == "" {
		metaMode = "live"
	}

	// Group assets by (accountId, region) so each tuple becomes one shard, which
	// is what merge.Merge / the per-shard coverage expects from a live scan.
	type shardKey struct{ account, region string }
	shards := make(map[shardKey]*models.ScanResult)
	order := make([]shardKey, 0)

	for _, c := range bom.Components {
		// Skip emitter-synthesized algorithm-definition nodes: they exist only so
		// the CycloneDX refType fields resolve (the crypto dependency graph) and are
		// NOT discovered AWS resources. Re-ingesting them would create a phantom
		// empty-(account,region) shard and inflate TotalAssets across the entire
		// merge/summary/export chain. See linkCryptoAssetGraph in cyclonedx.go.
		if isSyntheticComponent(c) {
			continue
		}
		asset := componentToAsset(c)
		key := shardKey{account: asset.AccountID, region: asset.Region}
		sr, ok := shards[key]
		if !ok {
			sr = &models.ScanResult{
				ScanID:      metaScanID,
				AccountID:   asset.AccountID,
				Region:      asset.Region,
				Mode:        metaMode,
				ToolVersion: toolVersionOf(bom),
			}
			shards[key] = sr
			order = append(order, key)
		}
		sr.Assets = append(sr.Assets, asset)
	}

	out := make([]models.ScanResult, 0, len(order))
	for _, k := range order {
		sr := shards[k]
		sr.Summary = models.ScanSummary{TotalAssets: len(sr.Assets)}
		out = append(out, *sr)
	}
	return out, nil
}

// componentToAsset reconstructs one models.CryptoAsset from a CDXComponent. It
// maps the cryptamap:* properties back onto the asset fields, rebuilds the
// free-form Properties map (with the cryptamap: prefix stripped, so
// Properties["posture"] is restored exactly as scanner.BuildFindings reads it),
// and folds the flat deeper-detail cryptamap:* props back into CryptoProps so
// roadmap.primitiveFor and the dashboard detail panel see them again.
func componentToAsset(c CDXComponent) models.CryptoAsset {
	props := propMap(c.Properties)

	asset := models.CryptoAsset{
		BomRef:      c.BomRef,
		Name:        c.Name,
		Description: c.Description,
		Service:     props["service"],
		Category:    models.Category(props["category"]),
		AccountID:   props["accountId"],
		Region:      props["region"],
		ResourceARN: props["resourceArn"],
	}
	// Prefer the explicit resourceType property (emitted since the region-less S3
	// ARN change); fall back to deriving from the ARN for older CBOMs that predate
	// it. ResourceID always comes from the ARN (stable across both paths).
	derivedType, derivedID := resourceFromARN(asset.ResourceARN)
	asset.ResourceID = derivedID
	if rt := props["resourceType"]; rt != "" {
		asset.ResourceType = rt
	} else {
		asset.ResourceType = derivedType
	}

	if c.CryptoProperties != nil {
		asset.CryptoProps = *c.CryptoProperties
	}

	// Free-form Properties: every cryptamap:* prop, de-prefixed. This restores
	// Properties["posture"] (read by BuildFindings) plus all other scanner k/v
	// (note, origin, rotationEnabled, runtime, etc.). The display/taxonomy props
	// (displayName/awsCategory/cryptoFunction/subAspect) and the structural ones
	// already mapped to dedicated fields (service/category/accountId/region/
	// resourceArn) are skipped so the map mirrors a live scanner's Properties.
	skip := map[string]struct{}{
		"service": {}, "category": {}, "accountId": {}, "region": {},
		"resourceArn": {}, "resourceType": {}, "displayName": {}, "awsCategory": {},
		"cryptoFunction": {}, "subAspect": {},
	}
	for k, v := range props {
		if _, drop := skip[k]; drop {
			continue
		}
		if isDeeperDetailProp(k) {
			continue // folded into CryptoProps below instead
		}
		if asset.Properties == nil {
			asset.Properties = make(map[string]string)
		}
		asset.Properties[k] = v
	}

	foldDeeperDetail(&asset.CryptoProps, props)
	return asset
}

// isDeeperDetailProp reports whether a (de-prefixed) property name is one of the
// flat deeper-detail props emitted by deeperDetailProps; those are folded back
// into CryptoProps rather than the free-form Properties map.
func isDeeperDetailProp(name string) bool {
	switch name {
	case "algorithmName", "keySizeBits", "kmsKeySpec",
		"keyExchangeGroup", "pqcHybrid", "certSignatureAlgorithm", "certKeySizeBits", "tlsMinVersion",
		"ikev2TransformTypes", "materialState", "pqEvidence":
		return true
	}
	return false
}

// foldDeeperDetail reconstructs the additive deeper-detail model fields (which
// buildCBOM/sanitizeForCDX strip out of cryptoProperties and re-emit as flat
// cryptamap:* props) back onto the CryptoProperties sub-objects, so the
// round-trip is lossless for roadmap.primitiveFor and the detail panel.
func foldDeeperDetail(cp *models.CryptoProperties, props map[string]string) {
	// Algorithm-side detail.
	if hasAny(props, "algorithmName", "keySizeBits", "kmsKeySpec") {
		if cp.AlgorithmProperties == nil {
			cp.AlgorithmProperties = &models.AlgorithmProperties{}
		}
		if v := props["algorithmName"]; v != "" {
			cp.AlgorithmProperties.AlgorithmName = v
		}
		if v := props["kmsKeySpec"]; v != "" {
			cp.AlgorithmProperties.KMSKeySpec = v
		}
		if n, err := strconv.Atoi(props["keySizeBits"]); err == nil && n != 0 {
			cp.AlgorithmProperties.KeySizeBits = n
		}
	}
	// Protocol-side detail.
	if hasAny(props, "keyExchangeGroup", "pqcHybrid", "certSignatureAlgorithm", "certKeySizeBits", "tlsMinVersion", "ikev2TransformTypes") {
		if cp.ProtocolProperties == nil {
			cp.ProtocolProperties = &models.ProtocolProperties{}
		}
		if v := props["ikev2TransformTypes"]; v != "" {
			cp.ProtocolProperties.IkeV2TransformTypes = strings.Split(v, ",")
		}
		if v := props["keyExchangeGroup"]; v != "" {
			cp.ProtocolProperties.KeyExchangeGroup = v
		}
		if props["pqcHybrid"] == "true" {
			cp.ProtocolProperties.PQCHybrid = true
		}
		if v := props["certSignatureAlgorithm"]; v != "" {
			cp.ProtocolProperties.CertSignatureAlgorithm = v
		}
		if n, err := strconv.Atoi(props["certKeySizeBits"]); err == nil && n != 0 {
			cp.ProtocolProperties.CertKeySizeBits = n
		}
		if v := props["tlsMinVersion"]; v != "" {
			cp.ProtocolProperties.TLSMinVersion = v
		}
	}
	// Related-crypto-material state (folded back from the flat prop that preserves a
	// non-CDX-enum state like "unknown", which sanitizeForCDX drops from the schema
	// field). Only restore when the asset is actually related-crypto-material.
	if v := props["materialState"]; v != "" && cp.RelatedCryptoMaterialProperties != nil {
		cp.RelatedCryptoMaterialProperties.State = models.CryptoState(v)
	}
}

func hasAny(props map[string]string, keys ...string) bool {
	for _, k := range keys {
		if _, ok := props[k]; ok {
			return true
		}
	}
	return false
}

// isSyntheticComponent reports whether a component is an emitter-synthesized
// algorithm-definition node (carries cryptamap:synthetic="true") rather than a
// discovered AWS resource. These nodes exist only to make the CycloneDX refType
// references resolvable and must be excluded from any asset/resource accounting.
func isSyntheticComponent(c CDXComponent) bool {
	for _, p := range c.Properties {
		if p.Name == syntheticProp && p.Value == "true" {
			return true
		}
	}
	return false
}

// propMap builds a de-prefixed lookup of cryptamap:* properties (keys without
// the "cryptamap:" prefix). Non-prefixed properties are kept under their raw key
// (defensive; the writer only ever emits the prefixed form).
func propMap(props []CDXProperty) map[string]string {
	m := make(map[string]string, len(props))
	for _, p := range props {
		k := strings.TrimPrefix(p.Name, propPrefix)
		m[k] = p.Value
	}
	return m
}

// resourceFromARN derives (ResourceType, ResourceID) from a resource ARN whose
// resource portion was built as "<ResourceType>/<ResourceID>" by the scanners
// (e.g. "AWS::Glue::DataCatalog/data-catalog"). It is best-effort and returns
// ("", arn) when the ARN does not have the expected 6-colon shape.
func resourceFromARN(arn string) (resourceType, resourceID string) {
	if arn == "" {
		return "", ""
	}
	// arn:aws:<service>:<region>:<account>:<resource>
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 {
		return "", arn
	}
	resource := parts[5]
	if idx := strings.LastIndex(resource, "/"); idx >= 0 {
		return resource[:idx], resource[idx+1:]
	}
	return "", resource
}

// stripScanRefPrefix recovers the scanId from the metadata component bom-ref,
// which buildCBOM writes as "cryptamap-scan-<scanId>".
func stripScanRefPrefix(ref string) string {
	return strings.TrimPrefix(ref, "cryptamap-scan-")
}

// toolVersionOf returns the CryptaMap tool version recorded in the BOM metadata,
// defaulting to empty when absent.
func toolVersionOf(bom CDXBOM) string {
	for _, t := range bom.Metadata.Tools {
		if t.Name == "CryptaMap" && t.Version != "" {
			return t.Version
		}
	}
	return ""
}

// SortScansByAccountRegion sorts shards deterministically by (accountId, region)
// so multi-file ingestion is order-independent. Exported for callers that want a
// stable shard order before merging.
func SortScansByAccountRegion(scans []models.ScanResult) {
	sort.SliceStable(scans, func(i, j int) bool {
		if scans[i].AccountID != scans[j].AccountID {
			return scans[i].AccountID < scans[j].AccountID
		}
		return scans[i].Region < scans[j].Region
	})
}
