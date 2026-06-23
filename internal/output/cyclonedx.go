// Package output renders CryptaMap ScanResults to all supported formats:
// CycloneDX 1.7 CBOM, MITRE PQCC Excel, ASFF, S3, DynamoDB, and PDF.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/aws-samples/cryptamap/internal/pqc"
	"github.com/aws-samples/cryptamap/internal/taxonomy"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// CDXBOM is the top-level CycloneDX 1.7 BOM structure.
type CDXBOM struct {
	BomFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     CDXMetadata    `json:"metadata"`
	Components   []CDXComponent `json:"components"`
}

type CDXMetadata struct {
	Timestamp  string        `json:"timestamp"`
	Tools      []CDXTool     `json:"tools"`
	Component  CDXMetaComp   `json:"component"`
	Properties []CDXProperty `json:"properties,omitempty"`
}

type CDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CDXMetaComp struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	BomRef string `json:"bom-ref,omitempty"`
}

type CDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type CDXComponent struct {
	Type             string                   `json:"type"`
	BomRef           string                   `json:"bom-ref"`
	Name             string                   `json:"name"`
	Description      string                   `json:"description,omitempty"`
	CryptoProperties *models.CryptoProperties `json:"cryptoProperties,omitempty"`
	Properties       []CDXProperty            `json:"properties,omitempty"`
}

// WriteCBOM writes a CycloneDX 1.7 CBOM JSON document to w.
func WriteCBOM(w io.Writer, scan models.ScanResult) error {
	bom := buildCBOM(scan)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(bom)
}

func buildCBOM(scan models.ScanResult) CDXBOM {
	bom := CDXBOM{
		BomFormat:    "CycloneDX",
		SpecVersion:  "1.7",
		SerialNumber: "urn:uuid:" + uuid.NewString(),
		Version:      1,
		Metadata: CDXMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []CDXTool{{
				Vendor: "AWS", Name: "CryptaMap", Version: scan.ToolVersion,
			}},
			Component: CDXMetaComp{
				Type: "application", Name: "cryptamap-scan",
				BomRef: "cryptamap-scan-" + scan.ScanID,
			},
			Properties: append([]CDXProperty{
				{Name: "cryptamap:scanId", Value: scan.ScanID},
				{Name: "cryptamap:accountId", Value: scan.AccountID},
				{Name: "cryptamap:region", Value: scan.Region},
				{Name: "cryptamap:mode", Value: scan.Mode},
			}, knowledgeProvenanceProps()...),
		},
		Components: make([]CDXComponent, 0, len(scan.Assets)),
	}
	// CycloneDX requires components[] to be unique (the schema marks the array
	// uniqueItems). A component is keyed by its bom-ref, which scanners derive from
	// the resource ARN. A degraded/partial AWS List response (or duplicate entries
	// across pagination boundaries) can yield two resources with empty/identical
	// ids → identical ARNs → identical bom-refs → byte-identical components, which
	// fails schema validation. Dedup by bom-ref here, at the single emit choke
	// point, so EVERY scanner is protected regardless of what AWS returns (keeping
	// the first occurrence; order otherwise preserved/deterministic).
	seenRefs := make(map[string]struct{}, len(scan.Assets))
	for _, a := range scan.Assets {
		if _, dup := seenRefs[a.BomRef]; dup {
			continue
		}
		seenRefs[a.BomRef] = struct{}{}
		// Friendly taxonomy so internal scanner IDs (e.g. kms_spec) never leak.
		tx := taxonomy.MustLookup(a.Service)
		props := []CDXProperty{
			{Name: "cryptamap:service", Value: a.Service}, // raw scanner ID, kept for traceability
			{Name: "cryptamap:category", Value: string(a.Category)},
			{Name: "cryptamap:accountId", Value: a.AccountID},
			{Name: "cryptamap:region", Value: a.Region},
			{Name: "cryptamap:resourceArn", Value: a.ResourceARN},
		}
		// Emit ResourceType explicitly so the offline CBOM round-trip
		// (componentToAsset) never has to re-derive it from the ARN shape. Region-
		// less / no-slash ARNs (e.g. the canonical S3 arn:aws:s3:::bucket) carry no
		// "<type>/<id>" segment, so ARN-only re-derivation would drop the type;
		// carrying it as its own property keeps the round-trip lossless for every
		// service. Older CBOMs without this prop still fall back to resourceFromARN.
		if a.ResourceType != "" {
			props = append(props, CDXProperty{Name: "cryptamap:resourceType", Value: a.ResourceType})
		}
		// Emit friendly taxonomy only when non-empty so the unknown/fallback
		// case stays clean (all forms are schema-valid name/value properties).
		if tx.DisplayName != "" {
			props = append(props, CDXProperty{Name: "cryptamap:displayName", Value: tx.DisplayName})
		}
		if tx.AWSCategory != "" {
			props = append(props, CDXProperty{Name: "cryptamap:awsCategory", Value: tx.AWSCategory})
		}
		if tx.CryptoFunction != "" {
			props = append(props, CDXProperty{Name: "cryptamap:cryptoFunction", Value: tx.CryptoFunction})
		}
		if tx.SubAspect != "" {
			props = append(props, CDXProperty{Name: "cryptamap:subAspect", Value: tx.SubAspect})
		}
		// Iterate a.Properties in SORTED key order so the emitted CBOM is
		// deterministic (Go map iteration is randomized). Deterministic output makes
		// two scans diff cleanly (the CI/CD baseline-diff example) and lets the
		// committed demo artifact be byte-verified by `gen-dashboard-mock -check`.
		propKeys := make([]string, 0, len(a.Properties))
		for k := range a.Properties {
			propKeys = append(propKeys, k)
		}
		sort.Strings(propKeys)
		for _, k := range propKeys {
			props = append(props, CDXProperty{Name: "cryptamap:" + k, Value: a.Properties[k]})
		}
		// Surface the deeper crypto-detail model fields as flat, cryptamap:
		// namespaced properties. They are emitted ONLY here (NOT inside
		// cryptoProperties.algorithmProperties/protocolProperties) because the
		// CycloneDX 1.7 schema marks those sub-objects additionalProperties:false
		// and would reject the custom keys. The CBOM-marshaled cryptoProperties is
		// sanitized below; the model struct itself stays additive for other
		// consumers (UI/Excel/DynamoDB/internal JSON).
		props = append(props, deeperDetailProps(a.CryptoProps)...)
		// PQ EVIDENCE TIER (capable vs confirmed): a PQ-hybrid posture derived from a
		// security-policy NAME or AWS-doc capability means the endpoint PERMITS post-
		// quantum key exchange, NOT that a PQ handshake was observed — real
		// negotiation is client-dependent. Only the cloudtrail_evidence scanner
		// observes an actual negotiated KEX group. Stamp cryptamap:pqEvidence so the
		// dashboard/% can honestly distinguish "PQ-capable (config permits)" from
		// "PQ-confirmed (observed negotiation)" rather than conflating them. v2's
		// active prober + CloudTrail mining will graduate more rows to "confirmed".
		props = append(props, pqEvidenceProps(a)...)
		// Human-readable component name uses the friendly DisplayName, not the
		// internal scanner ID. a.Service is still emitted as cryptamap:service.
		name := fmt.Sprintf("%s — %s", tx.DisplayName, a.Name)
		comp := CDXComponent{
			Type:        "cryptographic-asset",
			BomRef:      a.BomRef,
			Name:        name,
			Description: a.Description,
			Properties:  props,
		}
		// Only attach cryptoProperties when the scanner reported observable crypto.
		// Assets with an empty CryptoProperties{} (e.g. lambda_runtime, which exposes
		// no observable crypto) would otherwise emit {assetType:""}, which is invalid
		// under CDX 1.7 (assetType is a required non-empty enum). Such components stay
		// valid inventory entries with posture "unknown" via their cryptamap:* props.
		if !isEmptyCryptoProperties(a.CryptoProps) {
			// Sanitized copy for the schema-validated CBOM marshal: zero out the
			// non-schema fields so cryptoProperties still validates against CDX 1.7.
			cp := sanitizeForCDX(a.CryptoProps)
			comp.CryptoProperties = &cp
		}
		bom.Components = append(bom.Components, comp)
	}
	// Make the CBOM's cryptographic-asset references resolvable: link every
	// algorithm token used in a refType field to a real algorithm component.
	linkCryptoAssetGraph(&bom)
	return bom
}

// syntheticProp marks an emitter-synthesized algorithm-definition component (a
// node added only so refType references resolve — NOT a discovered AWS resource).
// Every CryptaMap consumer that treats components as AWS assets (cbom_reader's
// ParseCBOM, the dashboard asset/summary builders) MUST skip components carrying
// this property so synthetic nodes never inflate asset counts or create phantom
// account/region shards.
const syntheticProp = "cryptamap:synthetic"

// linkCryptoAssetGraph turns the CycloneDX refType fields — which until now held
// plain algorithm-name strings that resolved to no component (dangling
// references) — into a real, traversable crypto dependency graph, as required by
// the CycloneDX 1.7 CBOM model and the OWASP Authoritative Guide to CBOM.
//
// CycloneDX types cipherSuites[].algorithms[] and certificateProperties.
// signatureAlgorithmRef as refType: each value MUST be the bom-ref of an
// algorithm cryptographic-asset component present in the same BOM (so a consumer
// can answer "which certificates are signed with a quantum-vulnerable algorithm",
// "which protocols use which algorithms"). The scanners populate these fields
// with genuine algorithm tokens (e.g. "RSA-PSS-SHA-256-2048", "ML-DSA-65",
// SSH/IPsec algorithm lists); the non-algorithm labels/sentinels/ARNs that used
// to pollute them are now kept out at the source (see services.TLSProtocolProps,
// the cert scanners, ssl_policy.go).
//
// For each DISTINCT token still present in those fields, this synthesizes one
// minimal algorithm component (assetType=algorithm, name=token, marked
// cryptamap:synthetic=true) with a deterministic bom-ref, and rewrites every
// occurrence of the token to that bom-ref. The synthesized nodes are deliberately
// minimal — name only, NO fabricated primitive/security-level/curve — because the
// honest fact is only "this named algorithm is referenced"; the per-resource PQC
// posture already lives on the resource components. Output is fully deterministic
// (tokens are processed in sorted order) so the committed mock fixture stays
// byte-stable.
func linkCryptoAssetGraph(bom *CDXBOM) {
	// 1. Collect the distinct algorithm tokens used across every refType field.
	tokenSet := make(map[string]struct{})
	for i := range bom.Components {
		cp := bom.Components[i].CryptoProperties
		if cp == nil {
			continue
		}
		if cp.CertificateProperties != nil {
			if t := cp.CertificateProperties.SignatureAlgorithmRef; t != "" {
				tokenSet[t] = struct{}{}
			}
		}
		if cp.ProtocolProperties != nil {
			for _, cs := range cp.ProtocolProperties.CipherSuites {
				for _, t := range cs.Algorithms {
					// Skip empty/whitespace-only tokens: real AWS APIs can return a
					// blank cipher/algorithm name, and CycloneDX refType requires
					// minLength>=1, so an empty entry would fail schema validation.
					// They are dropped from the rewritten array below too.
					if strings.TrimSpace(t) != "" {
						tokenSet[t] = struct{}{}
					}
				}
			}
		}
	}
	// NOTE: do NOT early-return when tokenSet is empty — the rewrite below still
	// has to strip empty/whitespace-only algorithm entries (a suite whose only
	// tokens were blank) so they don't fail the refType minLength constraint.

	// 2. Assign each token a deterministic, collision-free bom-ref (sorted order).
	tokens := make([]string, 0, len(tokenSet))
	for t := range tokenSet {
		tokens = append(tokens, t)
	}
	sort.Strings(tokens)
	tokenRef := make(map[string]string, len(tokens))
	usedRefs := make(map[string]struct{})
	for _, t := range tokens {
		ref := algorithmBomRef(t, usedRefs)
		tokenRef[t] = ref
		usedRefs[ref] = struct{}{}
	}

	// 3. Rewrite every refType occurrence from the token to its bom-ref.
	for i := range bom.Components {
		cp := bom.Components[i].CryptoProperties
		if cp == nil {
			continue
		}
		if cp.CertificateProperties != nil {
			if ref, ok := tokenRef[cp.CertificateProperties.SignatureAlgorithmRef]; ok {
				cp.CertificateProperties.SignatureAlgorithmRef = ref
			}
		}
		if cp.ProtocolProperties != nil {
			for ci := range cp.ProtocolProperties.CipherSuites {
				algs := cp.ProtocolProperties.CipherSuites[ci].Algorithms
				// Rebuild the slice: map each token to its algorithm-component
				// bom-ref and DROP empty/whitespace-only tokens (which would violate
				// the refType minLength>=1 constraint). A suite whose only entries
				// were blank ends up with an empty/nil Algorithms array, which is
				// schema-valid (the field is optional).
				rebuilt := algs[:0:0]
				for _, t := range algs {
					if ref, ok := tokenRef[t]; ok {
						rebuilt = append(rebuilt, ref)
					}
				}
				cp.ProtocolProperties.CipherSuites[ci].Algorithms = rebuilt
			}
		}
	}

	// 4. Append one synthetic algorithm component per token (sorted → stable).
	for _, t := range tokens {
		bom.Components = append(bom.Components, CDXComponent{
			Type:   "cryptographic-asset",
			BomRef: tokenRef[t],
			Name:   t,
			CryptoProperties: &models.CryptoProperties{
				AssetType: models.AssetTypeAlgorithm,
			},
			Properties: []CDXProperty{
				{Name: syntheticProp, Value: "true"},
				{Name: "cryptamap:algorithmName", Value: t},
			},
		})
	}
}

// algorithmBomRef derives a deterministic, schema-valid, collision-free bom-ref
// for an algorithm token. It slugifies the token (lowercased, non-alphanumeric
// runs → single '-') under a "crypto-alg-" prefix that cannot collide with the
// scanners' "crypto-<hex>" resource bom-refs, and appends a numeric suffix if two
// distinct tokens would otherwise slugify to the same ref.
func algorithmBomRef(token string, used map[string]struct{}) string {
	var b strings.Builder
	b.WriteString("crypto-alg-")
	prevDash := false
	for _, r := range strings.ToLower(token) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
		} else if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	base := strings.Trim(b.String(), "-")
	if base == "crypto-alg" || base == "" {
		base = "crypto-alg-x" // token had no alphanumerics (defensive)
	}
	ref := base
	for i := 2; ; i++ {
		if _, clash := used[ref]; !clash {
			return ref
		}
		ref = base + "-" + strconv.Itoa(i)
	}
}

// knowledgeProvenanceProps renders the active PQC-knowledge freshness/provenance
// snapshot as flat knowledge: namespaced metadata properties, so every CBOM
// records HOW FRESH the post-quantum knowledge was at scan time (source =
// embedded air-gap floor vs. a validated newer override; the knowledge version;
// and minAsOf — the conservative "oldest fact" / weakest-link freshness headline
// the dashboard surfaces). This is read back generically by cbom_reader/the
// dashboard via getProp(metadata, "knowledge:*"); it adds no schema fields (the
// CDX 1.7 metadata.properties array allows arbitrary namespaced name/value
// pairs). Side-effect-free: KnowledgeProvenanceInfo returns a cached singleton.
func knowledgeProvenanceProps() []CDXProperty {
	p := pqc.KnowledgeProvenanceInfo()
	out := []CDXProperty{
		{Name: "knowledge:source", Value: string(p.Source)},
		{Name: "knowledge:version", Value: p.KnowledgeVersion},
		{Name: "knowledge:asOf", Value: p.AsOf},
		{Name: "knowledge:minAsOf", Value: p.MinAsOf},
		{Name: "knowledge:maxAsOf", Value: p.MaxAsOf},
		{Name: "knowledge:factCount", Value: strconv.Itoa(p.FactCount)},
		{Name: "knowledge:digest", Value: p.Digest},
	}
	// Surface the override provenance only when an override is actually active or
	// was rejected — keeps the common embedded-only CBOM uncluttered.
	if p.OverridePath != "" {
		out = append(out, CDXProperty{Name: "knowledge:overridePath", Value: p.OverridePath})
	}
	if p.OverrideError != "" {
		out = append(out, CDXProperty{Name: "knowledge:overrideError", Value: p.OverrideError})
	}
	return out
}

// deeperDetailProps extracts the additive deeper-crypto-detail model fields and
// renders them as flat cryptamap: namespaced CDXProperty entries. These fields
// cannot live inside cryptoProperties.{algorithm,protocol}Properties because the
// CycloneDX 1.7 schema marks those additionalProperties:false; emitting them as
// component-level properties keeps the CBOM schema-valid while still surfacing
// the detail to flat consumers (UI/Excel).
// pqEvidenceProps emits the cryptamap:pqEvidence qualifier for an asset that
// carries a PQ-hybrid claim, distinguishing CONFIRMED (an actually-observed
// negotiated PQ key exchange — only the cloudtrail_evidence scanner does this)
// from CAPABLE (the endpoint's policy/config PERMITS PQ, but real negotiation is
// client-dependent and was not observed). Emitted ONLY when the asset is actually
// PQ-hybrid, so non-PQ assets stay clean. This lets the headline "% quantum-safe"
// honestly report a capable-vs-confirmed split without dropping capable endpoints.
func pqEvidenceProps(a models.CryptoAsset) []CDXProperty {
	pp := a.CryptoProps.ProtocolProperties
	if pp == nil || !pp.PQCHybrid {
		return nil
	}
	evidence := "capable"
	// cloudtrail_evidence is the only scanner whose PQ-hybrid rests on an OBSERVED
	// negotiated key-exchange group (a real handshake recorded in CloudTrail).
	if a.Service == "cloudtrail_evidence" {
		evidence = "confirmed"
	}
	return []CDXProperty{{Name: "cryptamap:pqEvidence", Value: evidence}}
}

func deeperDetailProps(cp models.CryptoProperties) []CDXProperty {
	var out []CDXProperty
	if ap := cp.AlgorithmProperties; ap != nil {
		if ap.AlgorithmName != "" {
			out = append(out, CDXProperty{Name: "cryptamap:algorithmName", Value: ap.AlgorithmName})
		}
		if ap.KeySizeBits != 0 {
			out = append(out, CDXProperty{Name: "cryptamap:keySizeBits", Value: strconv.Itoa(ap.KeySizeBits)})
		}
		if ap.KMSKeySpec != "" {
			out = append(out, CDXProperty{Name: "cryptamap:kmsKeySpec", Value: ap.KMSKeySpec})
		}
		// Preserve the TRUE cipher mode when it is not a CDX enum member (e.g. "xts"),
		// since sanitizeForCDX remaps the schema field to "other". Emitted only for
		// the non-enum case so the common gcm/cbc/etc. stay solely in the schema field.
		if ap.Mode != "" && !validCDXMode(ap.Mode) {
			out = append(out, CDXProperty{Name: "cryptamap:mode", Value: ap.Mode})
		}
	}
	if pp := cp.ProtocolProperties; pp != nil {
		if pp.KeyExchangeGroup != "" {
			out = append(out, CDXProperty{Name: "cryptamap:keyExchangeGroup", Value: pp.KeyExchangeGroup})
		}
		// ikev2TransformTypes is a []string in the model (and the dashboard reads it
		// as such), but the CycloneDX 1.7 schema types protocolProperties.
		// ikev2TransformTypes as an OBJECT ({encr,prf,integ,ke}), not a string array.
		// Emit it as a flat comma-joined cryptamap: property and strip it from the
		// schema-validated cryptoProperties (sanitizeForCDX) so the CBOM stays valid;
		// the reader folds it back into the []string field. Same pattern as Source.
		if len(pp.IkeV2TransformTypes) > 0 {
			out = append(out, CDXProperty{Name: "cryptamap:ikev2TransformTypes", Value: strings.Join(pp.IkeV2TransformTypes, ",")})
		}
		if pp.PQCHybrid {
			out = append(out, CDXProperty{Name: "cryptamap:pqcHybrid", Value: "true"})
		}
		if pp.CertSignatureAlgorithm != "" {
			out = append(out, CDXProperty{Name: "cryptamap:certSignatureAlgorithm", Value: pp.CertSignatureAlgorithm})
		}
		if pp.CertKeySizeBits != 0 {
			out = append(out, CDXProperty{Name: "cryptamap:certKeySizeBits", Value: strconv.Itoa(pp.CertKeySizeBits)})
		}
		if pp.TLSMinVersion != "" {
			out = append(out, CDXProperty{Name: "cryptamap:tlsMinVersion", Value: pp.TLSMinVersion})
		}
	}
	// Related-crypto-material: preserve the human material state as a flat prop so a
	// state that is NOT a valid CDX enum member (e.g. "unknown") — which
	// sanitizeForCDX drops from the schema field — is still visible to the dashboard.
	if rcm := cp.RelatedCryptoMaterialProperties; rcm != nil && rcm.State != "" {
		out = append(out, CDXProperty{Name: "cryptamap:materialState", Value: string(rcm.State)})
	}
	return out
}

// validCDXMaterialState reports whether s is a valid CycloneDX 1.7
// relatedCryptoMaterialProperties.state enum member. models.StateUnknown
// ("unknown") is deliberately NOT valid here (it is valid for the .type field
// only), so it is excluded.
func validCDXMaterialState(s models.CryptoState) bool {
	switch s {
	case "pre-activation", models.StateActive, models.StateSuspended,
		"deactivated", "compromised", models.StateDestroyed:
		return true
	}
	return false
}

// validCDXMode reports whether m is a valid CycloneDX 1.7
// algorithmProperties.mode enum member.
func validCDXMode(m string) bool {
	switch m {
	case "cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown":
		return true
	}
	return false
}

// sanitizeForCDX returns a copy of cp with the additive deeper-detail fields
// zeroed, so the cryptoProperties object validates against the CycloneDX 1.7
// schema (which forbids unknown keys inside algorithmProperties/protocolProperties).
// The originating model is not mutated. The canonical CycloneDX fields
// (ParameterSetIdentifier, Mode, ClassicalSecurityLevel, ...) are preserved.
func sanitizeForCDX(cp models.CryptoProperties) models.CryptoProperties {
	out := cp
	if cp.AlgorithmProperties != nil {
		ap := *cp.AlgorithmProperties
		ap.AlgorithmName = ""
		ap.KeySizeBits = 0
		ap.KMSKeySpec = ""
		// CDX 1.7 algorithmProperties.mode is an ENUM (cbc/ecb/ccm/gcm/cfb/ofb/ctr/
		// other/unknown). Scanners may set a real-but-non-enum mode (e.g. "xts" for
		// EBS/FSx/MGN disk encryption); remap it to "other" so the component
		// validates. The precise mode survives on cryptamap:mode (emitted in
		// deeperDetailProps) and in the algorithmName (e.g. "AES-256-XTS").
		if ap.Mode != "" && !validCDXMode(ap.Mode) {
			ap.Mode = "other"
		}
		out.AlgorithmProperties = &ap
	}
	if cp.ProtocolProperties != nil {
		pp := *cp.ProtocolProperties
		pp.KeyExchangeGroup = ""
		pp.PQCHybrid = false
		pp.CertSignatureAlgorithm = ""
		pp.CertKeySizeBits = 0
		pp.TLSMinVersion = ""
		// CDX 1.7 types ikev2TransformTypes as an object, not the model's []string;
		// strip it here (re-emitted as the flat cryptamap:ikev2TransformTypes prop)
		// so protocolProperties validates.
		pp.IkeV2TransformTypes = nil
		// Source is non-schema provenance: the CDX 1.7 protocolProperties node is
		// additionalProperties:false, so a leaked "source" key fails validation. The
		// provenance is preserved as the top-level cryptamap:source component property
		// (a.Properties["source"] -> deeperDetailProps emits nothing for it, but the
		// raw scanner property is carried via the a.Properties loop in buildCBOM).
		pp.Source = ""
		out.ProtocolProperties = &pp
	}
	if cp.RelatedCryptoMaterialProperties != nil {
		rcm := *cp.RelatedCryptoMaterialProperties
		// CDX 1.7 relatedCryptoMaterialProperties.state is an ENUM that does NOT
		// include "unknown" (valid: pre-activation/active/suspended/deactivated/
		// compromised/destroyed). The scanner state mappers default to
		// models.StateUnknown on an unrecognized AWS state; emitting "unknown" here
		// fails schema validation. Drop any non-enum state from the schema artifact
		// (it is preserved as the flat cryptamap:materialState prop). Defensive for
		// every related-material path, not just today's two mappers.
		if !validCDXMaterialState(rcm.State) {
			rcm.State = ""
		}
		out.RelatedCryptoMaterialProperties = &rcm
	}
	return out
}

// isEmptyCryptoProperties reports whether cp carries no observable cryptographic
// posture — i.e. the scanner emitted a zero-value models.CryptoProperties{} (no
// assetType, no sub-objects, no OID). The Lambda runtime scanner does this on
// purpose (it exposes no observable crypto; posture stays "unknown" via the
// component's cryptamap:* properties). The CDX 1.7 cryptoProperties node REQUIRES
// a non-empty assetType enum, so an empty object would be schema-invalid; such
// components must omit the cryptoProperties object entirely.
func isEmptyCryptoProperties(cp models.CryptoProperties) bool {
	return cp.AssetType == "" &&
		cp.AlgorithmProperties == nil &&
		cp.CertificateProperties == nil &&
		cp.ProtocolProperties == nil &&
		cp.RelatedCryptoMaterialProperties == nil &&
		cp.OID == ""
}

// AsBytes returns the CBOM as JSON bytes (helpful for unit tests + S3 upload).
func AsBytes(scan models.ScanResult) ([]byte, error) {
	return json.MarshalIndent(buildCBOM(scan), "", "  ")
}
