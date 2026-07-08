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
// regenerate findings deterministically via scanner.BuildFindings. An ingested
// file is UNTRUSTED input: its assets are re-classified from scratch and it is
// NOT treated as a live scan (see ParseCBOM for the mode/source-precedence and
// property-allowlist handling that prevents a tampered file from suppressing or
// outranking a genuine live scan).
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
	// An ingested CBOM file is UNTRUSTED input, not a live scan. Defaulting its
	// mode to "live" (the prior behavior) gave a hand-edited file the same
	// source-precedence as a genuine scan in the merge package (merge.sourceOf
	// reads Properties["source"]), so a crafted shard could OUTRANK real results.
	// Force an explicit non-live mode for anything reconstructed from a file so
	// merge precedence can never favor file input over a live scan. A file that
	// self-declares mode="live" is not honored.
	metaMode := meta["mode"]
	if metaMode == "" || metaMode == "live" {
		metaMode = "ingested"
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
// free-form Properties map (with the cryptamap: prefix stripped; the untrusted
// "posture" claim is SANITIZED, not restored verbatim — see sanitizeIngestedPosture),
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
	// Prefer the explicit resourceType/resourceId properties (emitted verbatim by
	// buildCBOM); fall back to deriving from the ARN for older CBOMs that predate
	// them. The fallback resourceFromARN splits on the LAST "/", which corrupts a
	// slash-containing ResourceID (e.g. "alias/aws/dynamodb" would lose everything
	// before the final slash), so the verbatim property always wins when present.
	derivedType, derivedID := resourceFromARN(asset.ResourceARN)
	if id := props["resourceId"]; id != "" {
		asset.ResourceID = id
	} else {
		asset.ResourceID = derivedID
	}
	if rt := props["resourceType"]; rt != "" {
		asset.ResourceType = rt
	} else {
		asset.ResourceType = derivedType
	}

	if c.CryptoProperties != nil {
		asset.CryptoProps = *c.CryptoProperties
	}

	// Free-form Properties: every cryptamap:* prop, de-prefixed. This restores
	// all the scanner k/v (note, origin, rotationEnabled, runtime, etc.). The
	// display/taxonomy props (displayName/awsCategory/cryptoFunction/subAspect)
	// and the structural ones already mapped to dedicated fields (service/
	// category/accountId/region/resourceArn) are skipped so the map mirrors a
	// live scanner's Properties.
	//
	// SECURITY: "source" is deliberately NOT restored from the file. merge.sourceOf
	// reads Properties["source"] as the FIRST precedence signal (active-probe /
	// targeted-sdk outrank the config/tagging baselines), so honoring it from an
	// untrusted ingested file would let a crafted shard set source="active-probe"
	// and OUTRANK a genuine live scan in a merge. Dropping it forces sourceOf to
	// fall back to this shard's Mode ("ingested" -> SourceUnknown, the lowest
	// rank), so file input can never win a dedup collision against a live scan. No
	// current scanner sets this property, so real scans are unaffected.
	//
	// SECURITY: "posture" is likewise in the skip set and is NOT restored
	// verbatim. scanner.BuildFindings reads Properties["posture"] and SKIPS the
	// finding entirely for posture=symmetric-only (B3 inventory-only), so a
	// tampered CBOM could flip a vulnerable asset's posture to symmetric-only and
	// silence the finding on ingest. The claim is re-added below through
	// sanitizeIngestedPosture, which honors the finding-suppressing posture only
	// when the component's own cryptoProperties corroborate it.
	skip := map[string]struct{}{
		"service": {}, "category": {}, "accountId": {}, "region": {},
		"resourceArn": {}, "resourceType": {}, "resourceId": {}, "displayName": {}, "awsCategory": {},
		"cryptoFunction": {}, "subAspect": {}, "source": {}, "posture": {},
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
	// Re-add the posture claim only after the deeper detail is folded back, so
	// the corroboration check sees the reconstructed CryptoProps.
	sanitizeIngestedPosture(&asset, props["posture"])
	return asset
}

// sanitizeIngestedPosture restores the untrusted posture claim from an ingested
// CBOM onto asset.Properties["posture"], degrading the one FINDING-SUPPRESSING
// value when the file's own crypto evidence does not back it up.
//
// SECURITY: posture=symmetric-only is the single posture scanner.BuildFindings
// treats as inventory-only (B3) — it emits NO finding at all. A tampered CBOM
// that flips a vulnerable asset's posture to symmetric-only would therefore
// silence the finding on ingest (org-merge-files). We honor symmetric-only from
// a file only when the component's cryptoProperties corroborate a symmetric
// primitive; otherwise it degrades to PostureUnknown (MEDIUM, "needs
// investigation" — the same fail-safe BuildFindings applies to unreadable
// postures), with an explanatory note so the degradation is auditable. This is
// deliberate minimal hardening: it raises tamper effort from a one-field flip
// to a consistent multi-field forgery (mirroring the fail-closed
// risk.IsMoscaEscalatable allowlist pattern); full protection requires shard
// integrity verification (signing), which ingestion does not yet do — treat
// org-merge-files output as only as trustworthy as its input shards.
//
// All other posture values round-trip verbatim: they either produce a finding
// (vulnerable postures) or an Informational one (pqc-*), so they cannot make an
// asset vanish from the finding stream.
func sanitizeIngestedPosture(asset *models.CryptoAsset, claimed string) {
	if claimed == "" {
		return
	}
	if asset.Properties == nil {
		asset.Properties = make(map[string]string)
	}
	if models.CryptoPosture(claimed) == models.PostureSymmetricOnly && !symmetricOnlyCorroborated(*asset) {
		asset.Properties["posture"] = string(models.PostureUnknown)
		note := `ingested posture "symmetric-only" not corroborated by cryptoProperties; degraded to "unknown"`
		if prev := asset.Properties["note"]; prev != "" {
			note = prev + "; " + note
		}
		asset.Properties["note"] = note
		return
	}
	asset.Properties["posture"] = claimed
}

// symmetricOnlyCorroborated reports whether the reconstructed asset's own
// crypto evidence supports a symmetric-only (quantum-resistant-at-rest)
// posture: a symmetric algorithm primitive class, a symmetric algorithm/key
// spec token (AES/SYMMETRIC_*/HMAC/3DES/MACsec), a symmetric key-material
// block, a symmetric cipher suite (MACsec AES-GCM), or the documented
// AWS-managed-key guarantee marker kms_usage stamps.
func symmetricOnlyCorroborated(a models.CryptoAsset) bool {
	if ap := a.CryptoProps.AlgorithmProperties; ap != nil {
		switch ap.Primitive {
		case models.PrimitiveAE, models.PrimitiveBlockCipher, models.PrimitiveMAC,
			models.PrimitiveHash, models.PrimitiveKDF:
			return true
		}
		if symmetricAlgoToken(ap.AlgorithmName) || symmetricAlgoToken(ap.KMSKeySpec) {
			return true
		}
	}
	if rm := a.CryptoProps.RelatedCryptoMaterialProperties; rm != nil {
		// secret-key is symmetric by definition; a Secrets Manager "credential" is
		// a KMS-AES-encrypted stored value (secrets_rotation's symmetric default).
		if rm.Type == "secret-key" || rm.Type == "credential" || symmetricAlgoToken(rm.AlgorithmRef) {
			return true
		}
	}
	if pp := a.CryptoProps.ProtocolProperties; pp != nil {
		// Direct Connect MACsec (AES-GCM) is the symmetric-only protocol case.
		for _, cs := range pp.CipherSuites {
			if symmetricAlgoToken(cs.Name) {
				return true
			}
		}
	}
	// Free-form props that survive the round-trip: kms_usage's resolved target
	// key spec and its AWS-managed lazy-alias documented guarantee.
	if symmetricAlgoToken(a.Properties["targetKeySpec"]) {
		return true
	}
	if a.Properties["awsManagedKeyGuarantee"] == "symmetric-only" {
		return true
	}
	return false
}

// symmetricAlgoToken reports whether an algorithm/key-spec label names a
// symmetric (Grover-only, quantum-resistant-grade) primitive.
func symmetricAlgoToken(s string) bool {
	if s == "" {
		return false
	}
	u := strings.ToUpper(strings.ReplaceAll(s, "-", "_"))
	return strings.Contains(u, "AES") ||
		strings.HasPrefix(u, "SYMMETRIC") ||
		strings.Contains(u, "HMAC") ||
		strings.Contains(u, "TDES") || strings.Contains(u, "3DES") ||
		strings.Contains(u, "MACSEC") ||
		strings.Contains(u, "CHACHA")
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
