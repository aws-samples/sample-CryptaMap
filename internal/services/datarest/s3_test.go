package datarest

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
)

// TestBucketRegionMatches verifies the region-scoping gate that keeps each S3
// bucket processed ONLY in its home-region shard (Finding 1 phantom-bucket fix).
// ListBuckets is global, so without this gate a bucket would be re-emitted —
// mis-stamped and as a cross-region no-encryption phantom — in every other shard.
func TestBucketRegionMatches(t *testing.T) {
	cases := []struct {
		name         string
		bucketRegion string
		scanRegion   string
		want         bool
	}{
		{"same-non-default", "eu-west-1", "eu-west-1", true},
		{"mismatch", "us-west-2", "us-east-1", false},
		{"empty-bucket-is-use1", "", "us-east-1", true},  // null LocationConstraint == us-east-1
		{"empty-bucket-vs-usw2", "", "us-west-2", false}, // us-east-1 bucket, not this shard
		{"empty-scan-disables", "us-west-2", "", true},   // single-region/test: filter off
		{"both-empty", "", "", true},
		{"use1-vs-usw2", "us-east-1", "us-west-2", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := bucketRegionMatches(c.bucketRegion, c.scanRegion); got != c.want {
				t.Errorf("bucketRegionMatches(%q, %q) = %v, want %v", c.bucketRegion, c.scanRegion, got, c.want)
			}
		})
	}
}

// TestIsNoSSERuleError verifies that a GetBucketEncryption error is recognized as
// the benign "no explicit SSE rule" case ONLY for the exact AWS error code
// ServerSideEncryptionConfigurationNotFoundError (including when wrapped), and as
// a real assessment failure for any other error (access denied, redirect,
// throttle, network, non-API). This predicate is the hinge of the S3 default-
// encryption fix: the "no rule" case is reported as Unknown + default-sse-s3
// (NOT a confirmed no-encryption finding, because SSE-S3 applies to new objects
// since 2023-01-05 but pre-2023 objects cannot be assessed at the bucket level),
// while a true failure is a plain Unknown. A typo or SDK rename must fail here.
func TestIsNoSSERuleError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			"sse-not-found",
			&smithy.GenericAPIError{Code: "ServerSideEncryptionConfigurationNotFoundError"},
			true,
		},
		{
			"sse-not-found-wrapped",
			fmt.Errorf("s3 GetBucketEncryption: %w", &smithy.GenericAPIError{Code: "ServerSideEncryptionConfigurationNotFoundError"}),
			true,
		},
		{"access-denied", &smithy.GenericAPIError{Code: "AccessDenied"}, false},
		{"redirect", &smithy.GenericAPIError{Code: "PermanentRedirect"}, false},
		{"throttle", &smithy.GenericAPIError{Code: "SlowDown"}, false},
		{"non-api-error", errors.New("dial tcp: connection refused"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isNoSSERuleError(c.err); got != c.want {
				t.Errorf("isNoSSERuleError(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// fakeS3KMSDescribe is a minimal s3KMSAPI fake for exercising s3PropsForSSE.
type fakeS3KMSDescribe struct {
	spec string
	err  error
}

func (f *fakeS3KMSDescribe) DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{KeySpec: kmstypes.KeySpec(f.spec)}}, nil
}

// TestS3PropsForSSEKeySpecHonesty pins the SSE-KMS key-spec evidence rules:
//   - an observed DescribeKey spec is recorded verbatim;
//   - NO configured key (AWS-managed aws/s3) records the documented
//     SYMMETRIC_DEFAULT;
//   - a configured key whose DescribeKey FAILS must NOT fabricate an "observed"
//     SYMMETRIC_DEFAULT — the spec stays unresolved (empty, property omitted)
//     while the AES posture stands on the bucket's own SSE configuration.
func TestS3PropsForSSEKeySpecHonesty(t *testing.T) {
	cases := []struct {
		name     string
		kmsKeyID string
		client   *fakeS3KMSDescribe
		wantSpec string
	}{
		{"observed-spec", "arn:aws:kms:us-east-1:111122223333:key/abc", &fakeS3KMSDescribe{spec: "RSA_2048"}, "RSA_2048"},
		{"aws-managed-no-key-configured", "", &fakeS3KMSDescribe{}, "SYMMETRIC_DEFAULT"},
		{"describe-denied-not-fabricated", "arn:aws:kms:us-east-1:111122223333:key/abc", &fakeS3KMSDescribe{err: errors.New("AccessDeniedException: kms:DescribeKey")}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			keySpec := "sentinel-unset"
			cp := s3PropsForSSE(context.Background(), c.client, "aws:kms", c.kmsKeyID, &keySpec)
			if keySpec != c.wantSpec {
				t.Errorf("outKeySpec = %q, want %q", keySpec, c.wantSpec)
			}
			if cp.AlgorithmProperties == nil {
				t.Fatal("expected AES at-rest algorithm properties for SSE-KMS")
			}
		})
	}
}
