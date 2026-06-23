package datarest

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/timestreamwrite"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// isTimestreamNotSubscribed reports whether err is the AccessDenied that AWS
// returns when the account is NOT a Timestream-for-LiveAnalytics customer (the
// service is opt-in / being deprecated to new customers). This is a "service not
// in use" signal, NOT a permission defect or a scan failure, so it is treated as
// a graceful skip (zero assets, nil error) — mirroring the QLDB retired-endpoint
// skip. A GENUINE AccessDenied for an account that DOES use Timestream lacks this
// specific message and still surfaces as a hard error.
func isTimestreamNotSubscribed(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "Only existing Timestream") ||
		(strings.Contains(msg, "AccessDenied") && strings.Contains(msg, "LiveAnalytics"))
}

// TimestreamScanner inspects Timestream databases for KMS encryption.
type TimestreamScanner struct{}

// Name returns the canonical service identifier.
func (TimestreamScanner) Name() string { return "timestream" }

// Category returns the primary CryptaMap category.
func (TimestreamScanner) Category() models.Category { return models.CategoryDataAtRest }

// timestreamWriteAPI is the minimal slice of the timestreamwrite client this
// scanner uses. ListDatabases is NextToken-paginated, so the scanner must loop;
// a single call returns only the first page, silently dropping databases in
// dense accounts. Defining it as an interface keeps the pagination + error
// propagation logic unit-testable with a fake (the concrete *timestreamwrite.Client
// satisfies it).
type timestreamWriteAPI interface {
	ListDatabases(ctx context.Context, in *timestreamwrite.ListDatabasesInput, optFns ...func(*timestreamwrite.Options)) (*timestreamwrite.ListDatabasesOutput, error)
}

// Scan paginates ListDatabases. Timestream encryption at rest is on by default
// and cannot be turned off (AES-256), so every database is SymmetricOnly; a
// missing KmsKeyId means the AWS-managed default key (alias/aws/timestream), not
// no-encryption.
func (s TimestreamScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := timestreamwrite.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListDatabases and classifies each
// database into a CryptoAsset. A "not a Timestream customer" AccessDenied is a
// service-not-in-use signal (graceful skip, zero assets, nil error); any other
// ListDatabases error is propagated so a denied/throttled scan is VISIBLY
// incomplete rather than a clean-looking empty success.
func (s TimestreamScanner) scan(ctx context.Context, client timestreamWriteAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListDatabases(ctx, &timestreamwrite.ListDatabasesInput{NextToken: nextToken})
		if err != nil {
			// "Not a Timestream customer" AccessDenied is a service-not-in-use
			// signal, not a scan failure — skip gracefully so it does not flag the
			// whole (account,region) shard as errored. Genuine errors still surface.
			if isTimestreamNotSubscribed(err) {
				fmt.Fprintf(os.Stderr, "timestream: not subscribed in %s, skipping: %v\n", region, err)
				return []models.CryptoAsset{}, nil
			}
			return nil, fmt.Errorf("timestream ListDatabases: %w", err)
		}
		for _, db := range out.Databases {
			if db.DatabaseName == nil {
				continue
			}
			name := *db.DatabaseName
			// Always-on at-rest encryption (cannot be disabled) -> unconditionally
			// SymmetricOnly; absent KmsKeyId is the AWS-managed default key.
			kmsKey := "AWS_OWNED_KMS_KEY"
			if db.KmsKeyId != nil && *db.KmsKeyId != "" {
				kmsKey = *db.KmsKeyId
			}
			a := services.NewAsset("timestream", models.CategoryDataAtRest, accountID, region, name, "AWS::Timestream::Database", services.AESAtRest())
			services.PostureProperty(&a, models.PostureSymmetricOnly)
			services.StampDocFactKeyed(&a, "datarest/timestream/at-rest-aes256")
			a.Properties["kmsKeyId"] = kmsKey
			assets = append(assets, a)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
