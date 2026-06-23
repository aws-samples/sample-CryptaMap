package datarest

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	kintypes "github.com/aws/aws-sdk-go-v2/service/kinesis/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// KinesisScanner inspects Kinesis Data Streams for KMS encryption.
type KinesisScanner struct{}

// Name returns the canonical service identifier.
func (KinesisScanner) Name() string { return "kinesis" }

// Category returns the primary CryptaMap category.
func (KinesisScanner) Category() models.Category { return models.CategoryDataAtRest }

// kinesisAPI is the minimal slice of the kinesis client this scanner uses.
// ListStreams is NextToken/HasMoreStreams-paginated, so the scanner must loop; a
// single call returns only the first page, silently dropping streams in dense
// accounts. Defining it as an interface keeps the pagination + per-stream error
// handling unit-testable with a fake (the concrete *kinesis.Client satisfies it).
type kinesisAPI interface {
	ListStreams(ctx context.Context, in *kinesis.ListStreamsInput, optFns ...func(*kinesis.Options)) (*kinesis.ListStreamsOutput, error)
	DescribeStreamSummary(ctx context.Context, in *kinesis.DescribeStreamSummaryInput, optFns ...func(*kinesis.Options)) (*kinesis.DescribeStreamSummaryOutput, error)
}

// Scan paginates ListStreams, then DescribeStreamSummary for the encryption type.
func (s KinesisScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := kinesis.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core. A ListStreams error is propagated (the scan is
// visibly incomplete, never a clean empty success); a per-stream
// DescribeStreamSummary error is NOT dropped — it yields a PostureUnknown asset
// with a note so a read failure never reads as a clean all-clear by omission.
func (s KinesisScanner) scan(ctx context.Context, client kinesisAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListStreams(ctx, &kinesis.ListStreamsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("kinesis ListStreams: %w", err)
		}
		// Cap the per-page batch to the remaining per-scanner budget BEFORE
		// describing, so a pathological region never exceeds the cap.
		names := out.StreamNames
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(names) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			names = names[:remaining]
		}
		for _, name := range names {
			n := name
			summary, derr := client.DescribeStreamSummary(ctx, &kinesis.DescribeStreamSummaryInput{StreamName: &n})
			if derr != nil {
				// Do NOT drop the stream: emit a PostureUnknown asset with a note
				// so a read failure never reads as a clean all-clear by omission
				// (and never as a fabricated NoEncryption false alarm).
				fmt.Fprintf(os.Stderr, "kinesis:%s DescribeStreamSummary: %v\n", n, derr)
				a := services.NewAsset("kinesis", models.CategoryDataAtRest, accountID, region, n, "AWS::Kinesis::Stream", services.UnknownAtRest())
				services.PostureProperty(&a, models.PostureUnknown)
				a.Properties["note"] = "Could not read stream encryption summary; at-rest state undetermined."
				assets = append(assets, a)
				continue
			}
			posture := models.PostureNoEncryption
			props := services.NoEncryption()
			if summary.StreamDescriptionSummary != nil &&
				summary.StreamDescriptionSummary.EncryptionType == kintypes.EncryptionTypeKms {
				posture = models.PostureSymmetricOnly
				props = services.AESAtRest()
			}
			a := services.NewAsset("kinesis", models.CategoryDataAtRest, accountID, region, n, "AWS::Kinesis::Stream", props)
			services.PostureProperty(&a, posture)
			assets = append(assets, a)
		}
		if out.HasMoreStreams == nil || !*out.HasMoreStreams {
			break
		}
		nextToken = out.NextToken
		if nextToken == nil {
			break
		}
	}
	return assets, nil
}
