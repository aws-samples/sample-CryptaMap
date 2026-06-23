package output

import (
	"testing"
	"time"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestPartitionForRegion proves the region→partition mapping that keeps ASFF
// output valid in GovCloud and China. ARNs are partition-scoped, so a finding
// emitted with the wrong partition prefix is rejected by BatchImportFindings.
func TestPartitionForRegion(t *testing.T) {
	cases := []struct {
		region string
		want   string
	}{
		{"us-gov-west-1", "aws-us-gov"},
		{"us-gov-east-1", "aws-us-gov"},
		{"cn-north-1", "aws-cn"},
		{"cn-northwest-1", "aws-cn"},
		{"ap-south-1", "aws"},
		{"us-east-1", "aws"},
		{"", "aws"}, // unknown/empty region defaults to commercial
	}
	for _, c := range cases {
		if got := PartitionForRegion(c.region); got != c.want {
			t.Errorf("PartitionForRegion(%q) = %q, want %q", c.region, got, c.want)
		}
	}
}

// partitionScanForRegion builds a single-finding scan in the given region so we
// can assert the emitted ASFF partition tracks the finding's region.
func partitionScanForRegion(region string) models.ScanResult {
	now := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	return models.ScanResult{
		AccountID: "111122223333",
		Region:    region,
		Findings: []models.Finding{
			{
				ID:           "abc-123",
				AccountID:    "111122223333",
				Region:       region,
				ResourceID:   "my-bucket",
				ResourceARN:  "arn:aws:s3:::my-bucket",
				ResourceType: "AwsS3Bucket",
				Title:        "S3 bucket uses RSA-2048 key wrapping",
				Description:  "quantum-vulnerable key wrapping",
				Severity:     models.SeverityHigh,
				CreatedAt:    now,
				UpdatedAt:    now,
			},
		},
	}
}

// TestASFFPartitionFollowsRegion proves both partition-bearing fields — the
// resource Partition and the ProductArn prefix — derive from the finding's
// region, so GovCloud/China findings carry aws-us-gov / aws-cn while commercial
// regions stay byte-for-byte "aws".
func TestASFFPartitionFollowsRegion(t *testing.T) {
	// The default loader template carries the hardcoded "arn:aws:" prefix that
	// must be rewritten in non-commercial partitions.
	const tmpl = "arn:aws:securityhub:${REGION}:${ACCOUNT}:product/${ACCOUNT}/default"
	cases := []struct {
		region        string
		wantPartition string
		wantProduct   string
	}{
		{
			region:        "us-gov-west-1",
			wantPartition: "aws-us-gov",
			wantProduct:   "arn:aws-us-gov:securityhub:us-gov-west-1:111122223333:product/111122223333/default",
		},
		{
			region:        "cn-north-1",
			wantPartition: "aws-cn",
			wantProduct:   "arn:aws-cn:securityhub:cn-north-1:111122223333:product/111122223333/default",
		},
		{
			region:        "ap-south-1",
			wantPartition: "aws",
			wantProduct:   "arn:aws:securityhub:ap-south-1:111122223333:product/111122223333/default",
		},
		{
			region:        "us-east-1",
			wantPartition: "aws",
			wantProduct:   "arn:aws:securityhub:us-east-1:111122223333:product/111122223333/default",
		},
	}
	for _, c := range cases {
		findings := BuildASFFFindings(partitionScanForRegion(c.region), tmpl)
		if len(findings) != 1 {
			t.Fatalf("region %s: want 1 finding, got %d", c.region, len(findings))
		}
		f := findings[0]
		if len(f.Resources) != 1 {
			t.Fatalf("region %s: want 1 resource, got %d", c.region, len(f.Resources))
		}
		if got := f.Resources[0].Partition; got != c.wantPartition {
			t.Errorf("region %s: Resources[0].Partition = %q, want %q", c.region, got, c.wantPartition)
		}
		if got := f.ProductARN; got != c.wantProduct {
			t.Errorf("region %s: ProductArn = %q, want %q", c.region, got, c.wantProduct)
		}
	}
}
