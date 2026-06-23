// Package datarest contains scanners for AWS data-at-rest services.
package datarest

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// Bucket-encryption confidence values surfaced as the cryptamap:encryptionConfidence
// property, so the absence of an explicit SSE rule is distinguishable downstream
// from a bucket we could not assess (AccessDenied, redirect, throttle).
//
// IMPORTANT (default-encryption history): since 2023-01-05 S3 applies SSE-S3
// (AES-256) as the base level of encryption to every bucket, and new object
// uploads are always encrypted. But per the AWS default-encryption FAQ this is
// NOT retroactive — "Objects that are already in an existing unencrypted bucket
// won't be automatically encrypted." So the absence of an explicit
// PutBucketEncryption rule (ServerSideEncryptionConfigurationNotFoundError) does
// NOT prove the bucket's data is unencrypted (new objects are encrypted), nor
// that it is fully encrypted (pre-2023 objects might not be). The bucket-level
// API cannot see per-object state. The honest verdict is therefore UNKNOWN with a
// qualifier — never a "confirmed no-encryption" headline (a false alarm) and
// never a clean all-clear (a false-safe over legacy objects).
const (
	encConfidenceDefaultSSE = "default-sse-s3" // no explicit rule: SSE-S3 default for new objects; pre-2023 objects may be unencrypted
	encConfidenceUnknown    = "unknown"        // assessment failed (access denied / other error)
)

// bucketRegionMatches reports whether a bucket whose home region is bucketRegion
// should be scanned by the shard running in scanRegion. ListBuckets is a GLOBAL
// call, so every regional shard sees every bucket; we process each bucket ONLY in
// its home-region shard. An empty BucketRegion is treated as us-east-1 (S3 reports
// the legacy null LocationConstraint for us-east-1). An empty/unknown scanRegion
// (single-region or test contexts) disables the filter so nothing is dropped.
func bucketRegionMatches(bucketRegion, scanRegion string) bool {
	if scanRegion == "" {
		return true
	}
	if bucketRegion == "" {
		bucketRegion = "us-east-1"
	}
	return bucketRegion == scanRegion
}

// isNoSSERuleError reports whether a GetBucketEncryption error is the benign
// "no explicit SSE rule configured" case (ServerSideEncryptionConfigurationNotFoundError)
// as opposed to a real assessment failure (AccessDenied, PermanentRedirect,
// throttle, network). The former is NOT a no-encryption finding: SSE-S3 still
// applies to new objects by default (since 2023-01-05), but the bucket-level API
// cannot prove the state of pre-2023 objects — so the caller records an Unknown
// posture with the default-sse-s3 qualifier. The latter is a true Unknown.
func isNoSSERuleError(err error) bool {
	var apiErr smithy.APIError
	return errors.As(err, &apiErr) && apiErr.ErrorCode() == "ServerSideEncryptionConfigurationNotFoundError"
}

// s3API is the minimal slice of the s3 client this scanner uses. ListBuckets is
// ContinuationToken-paginated and is a GLOBAL call (every regional shard sees every
// bucket), so the scanner loops and region-filters; defining it as an interface
// keeps the pagination, region-scoping, and SSE classification unit-testable with a
// fake (the concrete *s3.Client satisfies it).
type s3API interface {
	ListBuckets(ctx context.Context, in *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	GetBucketEncryption(ctx context.Context, in *s3.GetBucketEncryptionInput, optFns ...func(*s3.Options)) (*s3.GetBucketEncryptionOutput, error)
}

// s3KMSAPI is the minimal slice of the kms client the SSE-KMS branch uses to read
// a configured master key's KeySpec. The concrete *kms.Client satisfies it.
type s3KMSAPI interface {
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

// S3Scanner discovers S3 buckets and inspects their default encryption.
type S3Scanner struct{}

// Name returns the canonical service identifier.
func (S3Scanner) Name() string { return "s3" }

// Category returns the primary CryptaMap category.
func (S3Scanner) Category() models.Category { return models.CategoryDataAtRest }

// Scan enumerates buckets in the active account, then probes each for SSE.
func (s S3Scanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := s3.NewFromConfig(cfg)
	kmsClient := kms.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, kmsClient, accountID, region)
}

// scan holds the testable core: it paginates the GLOBAL ListBuckets call,
// region-filters each bucket to its home-region shard, and classifies each
// bucket's default SSE (resolving the SSE-KMS key spec via the kms client). A
// ListBuckets error is returned (not swallowed) so a denied/throttled scan stays
// VISIBLY incomplete.
func (s S3Scanner) scan(ctx context.Context, client s3API, kmsClient s3KMSAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := make([]models.CryptoAsset, 0, 256)
	// Paginate ListBuckets (ContinuationToken) — a single call truncates at the
	// service page cap (~10k buckets), silently dropping buckets in large accounts.
	// Filter server-side by BucketRegion so each shard lists only its own region's
	// buckets (less data, fewer cross-region rows to skip); empty region (single-
	// region/test) lists all and relies on bucketRegionMatches below.
	var continuationToken *string
	scanRegionFilter := region
	for {
		in := &s3.ListBucketsInput{ContinuationToken: continuationToken}
		if scanRegionFilter != "" {
			in.BucketRegion = &scanRegionFilter
		}
		out, err := client.ListBuckets(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("s3 ListBuckets: %w", err)
		}
		// Cap the per-page bucket batch to the remaining per-scanner budget before
		// the concurrent fan-out, so a pathological account never launches more than
		// the cap's worth of GetBucketEncryption/DescribeKey goroutines. Region-
		// filtered buckets drop to (zero,false), so a page may yield fewer than its
		// length — the cap is the per-page MAXIMUM, not a guaranteed count.
		buckets := out.Buckets
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(buckets) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			buckets = buckets[:remaining]
		}
		// Probe each bucket's SSE concurrently (bounded, order-preserving). A nil
		// name or a bucket outside this shard's home region drops to (zero,false).
		page := services.MapConcurrent(ctx, services.DefaultInnerConcurrency, buckets,
			func(ctx context.Context, b s3types.Bucket) (models.CryptoAsset, bool) {
				if b.Name == nil {
					return models.CryptoAsset{}, false
				}
				bucketName := *b.Name
				// ListBuckets is global: only process each bucket in its HOME-region shard,
				// so we neither make doomed cross-region GetBucketEncryption calls nor emit
				// a phantom no-encryption row (mis-stamped with the scanning region) for the
				// same bucket in every other region. BucketRegion comes back on the
				// ListBuckets response — no extra API call.
				bucketRegion := ""
				if b.BucketRegion != nil {
					bucketRegion = *b.BucketRegion
				}
				if !bucketRegionMatches(bucketRegion, region) {
					return models.CryptoAsset{}, false
				}
				// Record the bucket's resolved home region (not the scan region) for display.
				homeRegion := bucketRegion
				if homeRegion == "" {
					homeRegion = "us-east-1"
				}

				posture := models.PostureSymmetricOnly
				props := services.AESAtRest()
				// Deeper-detail fields captured from the SSE rule we previously discarded.
				sseAlgorithm := ""
				kmsMasterKeyID := ""
				bucketKeyEnabled := ""
				kmsKeySpec := ""
				encConfidence := "" // set only on a no-encryption posture

				enc, eerr := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: b.Name})
				if eerr != nil {
					if isNoSSERuleError(eerr) {
						// No explicit SSE rule. This is NOT a no-encryption finding:
						// SSE-S3 (AES-256) is the default for new objects since 2023-01-05,
						// but the bucket-level API cannot prove pre-2023 objects are
						// encrypted. Honest verdict = Unknown with the default-sse-s3
						// qualifier (neither a false "unencrypted" alarm nor a false
						// all-clear over legacy objects).
						posture = models.PostureUnknown
						props = services.UnknownAtRest()
						encConfidence = encConfidenceDefaultSSE
					} else {
						// Real assessment failure (access denied / redirect / throttle):
						// state genuinely undetermined.
						posture = models.PostureUnknown
						props = services.UnknownAtRest()
						encConfidence = encConfidenceUnknown
						fmt.Fprintf(os.Stderr, "s3:%s GetBucketEncryption (%s): %v\n", bucketName, encConfidence, eerr)
					}
				} else if enc == nil || enc.ServerSideEncryptionConfiguration == nil {
					// No error but no config block: same as no explicit rule -> default
					// SSE-S3 for new objects, pre-2023 objects undetermined -> Unknown.
					posture = models.PostureUnknown
					props = services.UnknownAtRest()
					encConfidence = encConfidenceDefaultSSE
				} else {
					// Read inside the SSE config (data we used to throw away). The first
					// rule's ApplyServerSideEncryptionByDefault carries SSEAlgorithm,
					// KMSMasterKeyID and BucketKeyEnabled — all already in this response,
					// no extra API call.
					rules := enc.ServerSideEncryptionConfiguration.Rules
					if len(rules) > 0 {
						rule := rules[0]
						if rule.BucketKeyEnabled != nil {
							bucketKeyEnabled = fmt.Sprintf("%t", *rule.BucketKeyEnabled)
						}
						if def := rule.ApplyServerSideEncryptionByDefault; def != nil {
							sseAlgorithm = string(def.SSEAlgorithm)
							if def.KMSMasterKeyID != nil {
								kmsMasterKeyID = *def.KMSMasterKeyID
							}
							props = s3PropsForSSE(ctx, kmsClient, sseAlgorithm, kmsMasterKeyID, &kmsKeySpec)
						}
					}
				}

				// Canonical region-less S3 ARN (arn:aws:s3:::bucket) so the dedup bom-ref is
				// region-independent and org-merge collapses the same bucket seen from
				// multiple shards. Region is still carried as homeRegion for display.
				arn := fmt.Sprintf("arn:aws:s3:::%s", bucketName)
				a := services.NewAssetWithARN(arn, "s3", models.CategoryDataAtRest, accountID, homeRegion, bucketName, "AWS::S3::Bucket", props)
				services.PostureProperty(&a, posture)
				if encConfidence != "" {
					a.Properties["encryptionConfidence"] = encConfidence
				}
				if encConfidence == encConfidenceDefaultSSE {
					a.Properties["note"] = "No explicit bucket encryption rule. Since 2023-01-05 new object uploads are encrypted with SSE-S3 (AES-256) by default, but objects uploaded before then (or before any prior unencrypted period) may be unencrypted; the bucket-level API cannot determine per-object state."
				}
				// Surface the deeper detail as flat properties (cryptamap:* in CBOM).
				if sseAlgorithm != "" {
					a.Properties["sseAlgorithm"] = sseAlgorithm
				}
				if kmsMasterKeyID != "" {
					a.Properties["kmsMasterKeyId"] = kmsMasterKeyID
				}
				if bucketKeyEnabled != "" {
					a.Properties["bucketKeyEnabled"] = bucketKeyEnabled
				}
				if kmsKeySpec != "" {
					a.Properties["kmsKeySpec"] = kmsKeySpec
				}
				return a, true
			})
		assets = append(assets, page...)
		if out.ContinuationToken == nil || *out.ContinuationToken == "" {
			break
		}
		continuationToken = out.ContinuationToken
	}
	return assets, nil
}

// s3PropsForSSE builds the AES at-rest CryptoProperties for an S3 SSE rule,
// branching on the SSEAlgorithm. For SSE-KMS it issues one kms.DescribeKey on
// the configured master key to read its KeySpec (the only genuinely additional
// API call needed to fill the S3 'KMS key spec' blank), then carries the spec
// via AESAtRestKMS. An empty/aws-managed key (no explicit KMSMasterKeyID, or a
// DescribeKey failure) degrades gracefully to plain AESAtRest. *outKeySpec is
// populated with the resolved KeySpec for the flat property.
func s3PropsForSSE(ctx context.Context, kmsClient s3KMSAPI, sseAlgorithm, kmsMasterKeyID string, outKeySpec *string) models.CryptoProperties {
	switch sseAlgorithm {
	case "aws:kms", "aws:kms:dsse":
		keySpec := ""
		if kmsMasterKeyID != "" {
			if d, derr := kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &kmsMasterKeyID}); derr != nil {
				fmt.Fprintf(os.Stderr, "s3 SSE-KMS DescribeKey %s: %v\n", kmsMasterKeyID, derr)
			} else if d.KeyMetadata != nil {
				keySpec = string(d.KeyMetadata.KeySpec)
			}
		}
		if keySpec == "" {
			// SSE-KMS with an AWS-managed/aws/s3 key (no readable spec) is still
			// AES-256-GCM under the hood; record SYMMETRIC_DEFAULT.
			keySpec = "SYMMETRIC_DEFAULT"
		}
		*outKeySpec = keySpec
		cp := services.AESAtRestKMS(keySpec)
		labelS3KMS(cp)
		return cp
	default: // "AES256" (SSE-S3) or unset -> plain AES-256-GCM
		return services.AESAtRest()
	}
}

// labelS3KMS renames the algorithm label to make the SSE-KMS provenance visible
// in the detail panel, keeping the 256-bit AES facts intact.
func labelS3KMS(cp models.CryptoProperties) {
	if cp.AlgorithmProperties != nil {
		cp.AlgorithmProperties.AlgorithmName = "AES-256-GCM (SSE-KMS)"
	}
}
