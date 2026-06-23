// Package services provides helpers shared by all per-service scanners.
package services

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/aws-samples/cryptamap/internal/pqc"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// MaxAssetsPerScanner is the per-scanner safety cap on emitted assets. It exists
// to bound memory/time for a single pathological service in one (account,region)
// shard; it is NOT meant to be hit in normal operation. Raised from the previous
// silent 1000 to a value that comfortably covers dense real accounts while still
// protecting a Lambda shard. Override per scanner only with good reason.
const MaxAssetsPerScanner = 25000

// TruncationCapReached reports whether a scanner has hit MaxAssetsPerScanner and,
// when it has, logs a LOUD warning to stderr exactly once-per-call-site so the cap
// is never silent (silent truncation = under-reported crypto assets = a false
// "all clear"). Scanners call it in place of the old bare `if len(assets) >= 1000`
// early return:
//
//	if services.TruncationCapReached(len(assets), s.Name(), region) {
//	    return assets, nil
//	}
//
// The companion cryptamap:truncated property should also be stamped on the shard's
// assets by the engine when this fires; for now the stderr signal + ServiceStats
// error surfacing is the operator-visible trail.
func TruncationCapReached(count int, scanner, region string) bool {
	if count >= MaxAssetsPerScanner {
		fmt.Fprintf(os.Stderr,
			"[scanner:%s] WARNING: hit MaxAssetsPerScanner=%d in region %s; results TRUNCATED — this account/region has more resources than the per-scanner cap and the CBOM under-reports. Raise services.MaxAssetsPerScanner or shard finer.\n",
			scanner, MaxAssetsPerScanner, region)
		return true
	}
	return false
}

// bomRefFromARN derives a stable bom-ref from a resource ARN. It delegates to
// models.BomRefForARN, the single source of truth shared with the mock path.
func bomRefFromARN(arn string) string {
	return models.BomRefForARN(arn)
}

// Context is the shared per-scan invocation context passed to scanners.
type Context struct {
	AccountID string
	Region    string
}

// AccountID returns the active caller's account ID. Falls back to "unknown".
func AccountID(ctx context.Context, cfg aws.Config) string {
	c := sts.NewFromConfig(cfg)
	out, err := c.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || out.Account == nil {
		return "unknown"
	}
	return *out.Account
}

// NewAsset constructs a baseline CryptoAsset with sensible defaults. The ARN
// embeds the scanning region (correct for regional resources, which are distinct
// per region). For global / region-less resources such as S3 buckets, use
// NewAssetWithARN with the canonical region-less ARN instead.
func NewAsset(service string, category models.Category, accountID, region, resourceID, resourceType string, props models.CryptoProperties) models.CryptoAsset {
	arn := fmt.Sprintf("arn:aws:%s:%s:%s:%s/%s", service, region, accountID, resourceType, resourceID)
	return NewAssetWithARN(arn, service, category, accountID, region, resourceID, resourceType, props)
}

// NewAssetWithARN is NewAsset with a caller-supplied canonical ARN, for resources
// whose real ARN is region-less / account-less (e.g. S3 buckets: arn:aws:s3:::name)
// and must NOT embed the scanning region. If the region were baked into the ARN,
// the SAME bucket scanned from multiple region shards would hash to different
// bom-refs (BomRefForARN) and escape org-merge dedup, producing one real row plus
// N-1 phantom duplicates. Region is still recorded on the asset for
// display/coverage; only the ARN (and thus the dedup key) is region-independent.
func NewAssetWithARN(arn, service string, category models.Category, accountID, region, resourceID, resourceType string, props models.CryptoProperties) models.CryptoAsset {
	return models.CryptoAsset{
		BomRef:       bomRefFromARN(arn),
		Name:         resourceID,
		Service:      service,
		Category:     category,
		AccountID:    accountID,
		Region:       region,
		ResourceID:   resourceID,
		ResourceType: resourceType,
		ResourceARN:  arn,
		CryptoProps:  props,
		DiscoveredAt: time.Now().UTC(),
		Properties:   map[string]string{},
	}
}

// AESAtRest is the canonical AES-256 at-rest CryptoProperties (mode UNSPECIFIED).
// Most AWS at-rest services document "AES-256" without committing to a specific
// block mode per resource, and the previous unconditional Mode="gcm" /
// AlgorithmName="AES-256-GCM" was a guess that was simply wrong for some services
// (e.g. EBS is XTS — use AESXTSAtRest there). So this baseline asserts only what
// is universally true (AES-256, 256-bit, quantum-resistant) and leaves Mode empty;
// scanners that KNOW the mode set a mode-specific variant.
func AESAtRest() models.CryptoProperties {
	return models.CryptoProperties{
		AssetType: models.AssetTypeAlgorithm,
		AlgorithmProperties: &models.AlgorithmProperties{
			Primitive:                models.PrimitiveAE,
			ParameterSetIdentifier:   "256", // CycloneDX-canonical field
			ClassicalSecurityLevel:   256,
			NistQuantumSecurityLevel: pqc.SymmetricNISTCategory(256), // AES-256 anchors NIST Category 5
			AlgorithmName:            "AES-256",
			KeySizeBits:              256,
		},
	}
}

// AESAtRestKMS is AESAtRest enriched with the AWS KMS KeySpec backing the key
// (e.g. SYMMETRIC_DEFAULT, RSA_2048) for data-at-rest scanners that know the KMS
// key spec. (KMS at-rest envelope keys are symmetric; there is no ML-KEM keyspec.)
func AESAtRestKMS(keySpec string) models.CryptoProperties {
	cp := AESAtRest()
	cp.AlgorithmProperties.KMSKeySpec = keySpec
	return cp
}

// AESXTSAtRest is the canonical AES-256-XTS at-rest CryptoProperties. EBS volume
// encryption uses AES-256-XTS (two 256-bit keys / 512-bit total), NOT AES-256-GCM
// — per the AWS KMS Cryptographic Details doc ("Each volume is encrypted using
// AES-256-XTS"). XTS is the disk/block-encryption mode; using the GCM helper for
// EBS mislabels the at-rest cipher mode. Still symmetric AES-256 (quantum-safe).
func AESXTSAtRest() models.CryptoProperties {
	return models.CryptoProperties{
		AssetType: models.AssetTypeAlgorithm,
		AlgorithmProperties: &models.AlgorithmProperties{
			Primitive:                models.PrimitiveAE,
			Mode:                     "xts",
			ParameterSetIdentifier:   "256",
			ClassicalSecurityLevel:   256,
			NistQuantumSecurityLevel: pqc.SymmetricNISTCategory(256), // AES-256 anchors NIST Category 5
			AlgorithmName:            "AES-256-XTS",
			KeySizeBits:              256, // per-key; XTS uses two 256-bit keys (512-bit total)
		},
	}
}

// Asset property keys for the documented-fact provenance convention. When a
// classification rests on an authoritative AWS-doc UNIVERSAL guarantee (rather
// than a per-resource API observation), stamp these so the basis is auditable and
// a later self-update pass (docs/SELF-UPDATING-KNOWLEDGE.md) can refresh it.
const (
	PropSource     = "source"     // "observed" (from API) | "aws-doc" (universal guarantee)
	PropConfidence = "confidence" // "high" | "medium" | "low"
	PropSourceURL  = "sourceUrl"  // AWS doc URL backing an aws-doc fact
	PropAsOf       = "asOf"       // verification date of an aws-doc fact (YYYY-MM-DD)
	// PropDocFact carries the knowledge KEY ({package}/{scanner}/{fact-slug}) of
	// the Type-C documented guarantee this classification rests on. It lets the
	// freshness surface + dashboard resolve the full fact (value/url/date) from the
	// loaded knowledge on demand instead of bloating every asset with the prose.
	PropDocFact = "docFact"

	SourceObserved = "observed"
	SourceAWSDoc   = "aws-doc"
)

// StampDocFact records the provenance of a classification that rests on an
// authoritative AWS-doc universal guarantee (no per-resource API exposes it). Use
// ONLY for universal guarantees ("service ALWAYS does X"), never for overridable
// defaults. asOf is the date the guarantee was verified (YYYY-MM-DD).
//
// Prefer StampDocFactKeyed: it sources the confidence/url/asOf from the loaded
// knowledge (internal/pqc) so a refreshed knowledge file updates the provenance,
// and ties the asset to the documented fact by key. This literal form remains for
// the rare case where no knowledge key applies.
func StampDocFact(a *models.CryptoAsset, confidence, sourceURL, asOf string) {
	if a.Properties == nil {
		a.Properties = map[string]string{}
	}
	a.Properties[PropSource] = SourceAWSDoc
	a.Properties[PropConfidence] = confidence
	if sourceURL != "" {
		a.Properties[PropSourceURL] = sourceURL
	}
	if asOf != "" {
		a.Properties[PropAsOf] = asOf
	}
}

// StampDocFactKeyed records doc-fact provenance sourced from the loaded knowledge
// (internal/pqc) by key — the migrated form of StampDocFact. It writes the SAME
// properties StampDocFact did (source=aws-doc, confidence, sourceUrl, asOf) plus
// the fact key (PropDocFact) so the full documented guarantee is resolvable from
// the knowledge file rather than copied onto every asset. When a refreshed
// knowledge override is active, the confidence/url/date follow it automatically.
//
// If the key is unknown (knowledge file out of sync) it FAILS SAFE: it stamps the
// key + source=aws-doc but no fabricated date/confidence — a missing provenance
// detail, never a wrong classification (posture is set separately by the caller).
func StampDocFactKeyed(a *models.CryptoAsset, key string) {
	if a.Properties == nil {
		a.Properties = map[string]string{}
	}
	a.Properties[PropSource] = SourceAWSDoc
	a.Properties[PropDocFact] = key
	f, ok := pqc.ScannerDocFactByKey(key)
	if !ok {
		return
	}
	if f.Confidence != "" {
		a.Properties[PropConfidence] = f.Confidence
	}
	if f.SourceURL != "" {
		a.Properties[PropSourceURL] = f.SourceURL
	}
	if f.AsOf != "" {
		a.Properties[PropAsOf] = f.AsOf
	}
}

// StampDocFactSubclaimKeyed records ONLY the source-URL + asOf of a documented
// sub-claim (e.g. KMS rotation-inapplicability), sourced from the loaded knowledge
// by key, WITHOUT touching source/confidence. Use when an asset's primary basis is
// already an observed API result (StampObserved) and the doc fact is an additive
// secondary citation that must NOT clobber the observed source. Mirrors the
// previous direct PropSourceURL/PropAsOf write in kms_rotation.go.
func StampDocFactSubclaimKeyed(a *models.CryptoAsset, key string) {
	if a.Properties == nil {
		a.Properties = map[string]string{}
	}
	a.Properties[PropDocFact] = key
	f, ok := pqc.ScannerDocFactByKey(key)
	if !ok {
		return
	}
	if f.SourceURL != "" {
		a.Properties[PropSourceURL] = f.SourceURL
	}
	if f.AsOf != "" {
		a.Properties[PropAsOf] = f.AsOf
	}
}

// StampObserved marks a classification as derived from a live per-resource API
// observation (the strongest basis). confidence is typically "high".
func StampObserved(a *models.CryptoAsset, confidence string) {
	if a.Properties == nil {
		a.Properties = map[string]string{}
	}
	a.Properties[PropSource] = SourceObserved
	if confidence != "" {
		a.Properties[PropConfidence] = confidence
	}
}

// MapConcurrent applies fn to each item with at most `workers` goroutines in
// flight, returning results in the SAME order as items (deterministic output).
// fn returns (result, keep): keep=false drops the item (mirrors a per-item
// `continue` on an error the caller logs). The first ctx cancellation stops
// dispatch. This is the bounded inner-concurrency primitive for per-resource
// Describe loops (s3 GetBucketEncryption, dynamodb DescribeTable, kms DescribeKey)
// so a dense region does not exceed the 15-min shard timeout. It does NO retry —
// each fn call is a single SDK op whose adaptive retryer handles throttle; the
// engine's outer retry still wraps the whole Scan. SDK clients are safe for
// concurrent use. Order is preserved via an index-addressed result slice (no
// shared-slice race, no hot-path mutex), mirroring the merge prefetch idiom.
func MapConcurrent[In any, Out any](ctx context.Context, workers int, items []In, fn func(context.Context, In) (Out, bool)) []Out {
	if len(items) == 0 {
		return nil
	}
	if workers <= 0 {
		workers = DefaultInnerConcurrency
	}
	if workers > len(items) {
		workers = len(items)
	}
	results := make([]Out, len(items))
	keep := make([]bool, len(items))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i := range items {
		if ctx.Err() != nil {
			break // stop dispatch on cancellation
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			out, ok := fn(ctx, items[i])
			results[i] = out
			keep[i] = ok
		}(i)
	}
	wg.Wait()
	out := results[:0]
	for i := range results {
		if keep[i] {
			out = append(out, results[i])
		}
	}
	return out
}

// DefaultInnerConcurrency is the worker count for per-resource inner fan-out
// (SCALING.md §4.5: 8-16). 12 balances 15-min-shard throughput against added load
// on the SDK adaptive rate limiter.
const DefaultInnerConcurrency = 12

// NoEncryption is the at-rest property block for a resource that has encryption disabled.
func NoEncryption() models.CryptoProperties {
	return models.CryptoProperties{
		AssetType: models.AssetTypeAlgorithm,
		AlgorithmProperties: &models.AlgorithmProperties{
			Primitive:              models.PrimitiveAE,
			ParameterSetIdentifier: "none",
		},
	}
}

// UnknownAtRest is the at-rest property block for a resource whose encryption
// state is genuinely UNDETERMINED — neither a confirmed AES cipher (AESAtRest)
// nor a confirmed disabled state (NoEncryption). Use it with PostureUnknown when
// no API field and no universal AWS-doc guarantee establishes the at-rest cipher,
// so the asset is accounted for without fabricating either an all-clear or an alarm.
func UnknownAtRest() models.CryptoProperties {
	return models.CryptoProperties{
		AssetType: models.AssetTypeAlgorithm,
		AlgorithmProperties: &models.AlgorithmProperties{
			Primitive:              models.PrimitiveAE,
			ParameterSetIdentifier: "unknown",
		},
	}
}

// TLSProtocolProps is the canonical CycloneDX protocol block for a TLS endpoint.
//
// suiteName labels the negotiated/permitted cipher suite (or, for most config
// scanners, a service/policy label like "eks-tls" or an AWS security-policy
// name). It is recorded ONLY as the cipher suite's Name. It is deliberately NOT
// copied into CipherSuite.Algorithms: per CycloneDX 1.7, cipherSuites[].algorithms
// is a refType array — bom-refs to algorithm cryptographic-asset components — not
// a place for the suite/label string. The emitter (internal/output) links any
// genuine algorithm tokens to synthesized algorithm components; a service label is
// not an algorithm and must not become a (dangling) reference.
func TLSProtocolProps(version, suiteName string) models.CryptoProperties {
	return models.CryptoProperties{
		AssetType: models.AssetTypeProtocol,
		ProtocolProperties: &models.ProtocolProperties{
			Type:    "tls",
			Version: version,
			CipherSuites: []models.CipherSuite{{
				Name: suiteName,
			}},
		},
	}
}

// TLSProtocolPropsDoc is TLSProtocolProps for a TLS posture that rests on an
// AWS-DOCUMENTED guarantee rather than a live-observed handshake/policy (e.g. a
// managed endpoint whose TLS floor AWS documents but no per-resource API exposes).
// It records source=aws-doc on the protocol block; the caller should also
// StampDocFact the asset with the same confidence/URL/asOf. An empty version
// means the floor is not a universal guarantee and is left UNKNOWN (do not assert
// a version that isn't documented as universal).
func TLSProtocolPropsDoc(version, suiteName, confidence, docURL string) models.CryptoProperties {
	cp := TLSProtocolProps(version, suiteName)
	cp.ProtocolProperties.Source = SourceAWSDoc
	return cp
}

// TLSProtocolPropsDetailed is TLSProtocolProps enriched with the negotiated key
// exchange group, the served leaf certificate's signature algorithm and key
// size, and a PQC-hybrid flag. Existing TLSProtocolProps(version, suiteName) is
// kept unchanged for current callers.
func TLSProtocolPropsDetailed(version, suiteName, kexGroup, certSigAlgo string, certKeyBits int, pqcHybrid bool) models.CryptoProperties {
	return models.CryptoProperties{
		AssetType: models.AssetTypeProtocol,
		ProtocolProperties: &models.ProtocolProperties{
			Type:    "tls",
			Version: version,
			CipherSuites: []models.CipherSuite{{
				Name: suiteName,
			}},
			KeyExchangeGroup:       kexGroup,
			PQCHybrid:              pqcHybrid,
			CertSignatureAlgorithm: certSigAlgo,
			CertKeySizeBits:        certKeyBits,
		},
	}
}

// CertProps is the canonical CycloneDX certificate block.
func CertProps(subject, issuer, sigAlgo string, notBefore, notAfter time.Time) models.CryptoProperties {
	return models.CryptoProperties{
		AssetType: models.AssetTypeCertificate,
		CertificateProperties: &models.CertificateProperties{
			SubjectName:           subject,
			IssuerName:            issuer,
			SignatureAlgorithmRef: sigAlgo,
			NotValidBefore:        notBefore,
			NotValidAfter:         notAfter,
			CertificateFormat:     "X.509",
		},
	}
}

// KeyMaterialProps is the canonical CycloneDX related-crypto-material block (KMS keys, HSM, etc).
func KeyMaterialProps(kind string, state models.CryptoState, size int, algoRef string) models.CryptoProperties {
	return models.CryptoProperties{
		AssetType: models.AssetTypeRelatedMaterial,
		RelatedCryptoMaterialProperties: &models.RelatedCryptoMaterialProperties{
			Type:         kind,
			State:        state,
			Size:         size,
			AlgorithmRef: algoRef,
		},
	}
}

// PostureProperty annotates an asset with the inferred CryptoPosture.
func PostureProperty(asset *models.CryptoAsset, posture models.CryptoPosture) {
	if asset.Properties == nil {
		asset.Properties = map[string]string{}
	}
	asset.Properties["posture"] = string(posture)
}
