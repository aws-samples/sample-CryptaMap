package datarest

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	fhtypes "github.com/aws/aws-sdk-go-v2/service/firehose/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// FirehoseScanner inspects Amazon Data Firehose (Kinesis Data Firehose) delivery
// streams for at-rest server-side encryption.
//
// IMPORTANT (opt-in, Type-B): Firehose SSE is NOT on by default — a stream that
// never enabled it has a nil/DISABLED encryption config, which is a GENUINE
// no-encryption finding (the at-rest interim-buffer surface), never a false
// all-clear. Posture is driven by the encryption STATUS enum, not merely the
// presence of the config struct. When ENABLED it is a symmetric AES-256 KMS
// envelope (asymmetric CMKs are rejected) — SymmetricOnly. (Data in transit is
// always TLS, but that is a separate surface and does not make the at-rest data
// safe.)
type FirehoseScanner struct{}

// Name returns the canonical service identifier.
func (FirehoseScanner) Name() string { return "firehose" }

// Category returns the primary CryptaMap category.
func (FirehoseScanner) Category() models.Category { return models.CategoryDataAtRest }

// firehoseAPI is the minimal slice of the firehose client this scanner uses.
// ListDeliveryStreams uses a name-based cursor (ExclusiveStartDeliveryStreamName
// + HasMoreDeliveryStreams), NOT a NextToken — a single call returns only the
// first page (default ~10), silently dropping streams in dense accounts unless
// the scanner loops. DescribeDeliveryStream reads each stream's encryption
// status. Defining this as an interface keeps the pagination + per-resource
// error-handling logic unit-testable with a fake (the concrete *firehose.Client
// satisfies it).
type firehoseAPI interface {
	ListDeliveryStreams(ctx context.Context, in *firehose.ListDeliveryStreamsInput, optFns ...func(*firehose.Options)) (*firehose.ListDeliveryStreamsOutput, error)
	DescribeDeliveryStream(ctx context.Context, in *firehose.DescribeDeliveryStreamInput, optFns ...func(*firehose.Options)) (*firehose.DescribeDeliveryStreamOutput, error)
}

// Scan enumerates delivery streams (name-based cursor, not a NextToken), then
// DescribeDeliveryStream for each to read its encryption status.
func (s FirehoseScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := firehose.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListDeliveryStreams via the
// name-based cursor and DescribeDeliveryStream-classifies each stream. A
// ListDeliveryStreams error is propagated (the scan is recorded as errored /
// visibly incomplete, never a clean empty success); a per-stream
// DescribeDeliveryStream error does NOT silently drop the stream — it is emitted
// as a PostureUnknown asset with a note so a denied/throttled detail read stays
// accounted-for (HONESTY CONTRACT: never an all-clear by omission, never a
// fabricated NoEncryption false alarm).
func (s FirehoseScanner) scan(ctx context.Context, client firehoseAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var exclusiveStart *string
	for {
		out, err := client.ListDeliveryStreams(ctx, &firehose.ListDeliveryStreamsInput{
			ExclusiveStartDeliveryStreamName: exclusiveStart,
		})
		if err != nil {
			return nil, fmt.Errorf("firehose ListDeliveryStreams: %w", err)
		}
		names := out.DeliveryStreamNames
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(names) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			names = names[:remaining]
		}
		page := services.MapConcurrent(ctx, services.DefaultInnerConcurrency, names,
			func(ctx context.Context, name string) (models.CryptoAsset, bool) {
				n := name
				desc, derr := client.DescribeDeliveryStream(ctx, &firehose.DescribeDeliveryStreamInput{DeliveryStreamName: &n})
				if derr != nil {
					// Never silently drop the stream on a per-resource read error:
					// emit it as a PostureUnknown asset rather than vanishing it
					// (HONESTY CONTRACT: never an all-clear by omission, never a
					// fabricated NoEncryption false alarm).
					fmt.Fprintf(os.Stderr, "firehose:%s DescribeDeliveryStream: %v\n", n, derr)
					a := services.NewAsset("firehose", models.CategoryDataAtRest, accountID, region, n, "AWS::KinesisFirehose::DeliveryStream", services.UnknownAtRest())
					services.PostureProperty(&a, models.PostureUnknown)
					a.Properties["note"] = "Could not read delivery-stream encryption (DescribeDeliveryStream failed); at-rest key custody undetermined."
					return a, true
				}

				// Drive posture off the encryption STATUS, not struct presence: a
				// config with Status DISABLED/ENABLING/*_FAILED is NOT protecting data.
				posture := models.PostureNoEncryption
				props := services.NoEncryption()
				statusStr := ""
				keyType := ""
				kmsKey := ""
				streamType := ""
				if d := desc.DeliveryStreamDescription; d != nil {
					streamType = string(d.DeliveryStreamType)
					if ec := d.DeliveryStreamEncryptionConfiguration; ec != nil {
						statusStr = string(ec.Status)
						keyType = string(ec.KeyType)
						if ec.KeyARN != nil {
							kmsKey = *ec.KeyARN
						}
						if ec.Status == fhtypes.DeliveryStreamEncryptionStatusEnabled {
							// Symmetric AES-256 KMS envelope (asymmetric CMKs unsupported).
							posture = models.PostureSymmetricOnly
							props = services.AESAtRest()
						}
					}
				}

				a := services.NewAsset("firehose", models.CategoryDataAtRest, accountID, region, n, "AWS::KinesisFirehose::DeliveryStream", props)
				services.PostureProperty(&a, posture)
				if statusStr != "" {
					a.Properties["encryptionStatus"] = statusStr
				}
				if keyType != "" {
					a.Properties["keyType"] = keyType
				}
				if kmsKey != "" {
					a.Properties["kmsKeyId"] = kmsKey
				}
				if streamType != "" {
					a.Properties["deliveryStreamType"] = streamType
				}
				if posture == models.PostureNoEncryption {
					note := "Firehose server-side encryption is opt-in and not active on this stream; interim-buffer data at rest is unencrypted."
					if streamType == "KinesisStreamAsSource" {
						note += " (KinesisStreamAsSource streams get at-rest protection from the source Kinesis stream, scanned separately.)"
					}
					a.Properties["note"] = note
				}
				return a, true
			})
		assets = append(assets, page...)
		if out.HasMoreDeliveryStreams == nil || !*out.HasMoreDeliveryStreams || len(out.DeliveryStreamNames) == 0 {
			break
		}
		exclusiveStart = &out.DeliveryStreamNames[len(out.DeliveryStreamNames)-1]
	}
	return assets, nil
}
