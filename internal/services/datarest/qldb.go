package datarest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/qldb"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// isEndpointUnavailable reports whether err is an endpoint-resolution / DNS
// failure (no such host). QLDB has been retired and qldb.<region>.amazonaws.com
// no longer resolves, so such failures are treated as a graceful skip rather
// than a hard scanner error. Genuine errors (throttling, AccessDenied) return
// false so they still surface.
func isEndpointUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	return strings.Contains(err.Error(), "no such host")
}

// qldbAPI is the minimal slice of the qldb client this scanner uses. ListLedgers
// is NextToken-paginated; defining it as an interface keeps the pagination +
// DescribeLedger key classification unit-testable with a fake (the concrete
// *qldb.Client satisfies it).
type qldbAPI interface {
	ListLedgers(ctx context.Context, in *qldb.ListLedgersInput, optFns ...func(*qldb.Options)) (*qldb.ListLedgersOutput, error)
	DescribeLedger(ctx context.Context, in *qldb.DescribeLedgerInput, optFns ...func(*qldb.Options)) (*qldb.DescribeLedgerOutput, error)
}

// QLDBScanner enumerates QLDB ledgers (deprecated service; always encrypts at rest).
type QLDBScanner struct{}

// Name returns the canonical service identifier.
func (QLDBScanner) Name() string { return "qldb" }

// Category returns the primary CryptaMap category.
func (QLDBScanner) Category() models.Category { return models.CategoryDataAtRest }

// Scan paginates ListLedgers, then DescribeLedger to read the KMS key.
//
// QLDB always encrypts data at rest, so we always report SymmetricOnly. We
// preserve the customer-managed KMS key when present, and use the literal
// `AWS_OWNED_KMS_KEY` to denote the AWS-owned default.
func (s QLDBScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := qldb.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListLedgers and reads each ledger's
// KMS key via DescribeLedger. Endpoint/DNS failures (QLDB is retired) are a
// graceful skip; other ListLedgers errors are returned so they surface.
func (s QLDBScanner) scan(ctx context.Context, client qldbAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListLedgers(ctx, &qldb.ListLedgersInput{NextToken: nextToken})
		if err != nil {
			// QLDB is retired: its regional endpoint no longer resolves in many
			// regions. Treat endpoint/DNS failures as a graceful skip (no assets,
			// no error) so they stop counting as scanner failures. Genuine errors
			// (throttling, AccessDenied) still surface as a hard error.
			if isEndpointUnavailable(err) {
				fmt.Fprintf(os.Stderr, "qldb: endpoint unavailable in %s, skipping: %v\n", region, err)
				return []models.CryptoAsset{}, nil
			}
			return nil, fmt.Errorf("qldb ListLedgers: %w", err)
		}
		// Cap the per-page batch to the remaining per-scanner budget BEFORE
		// describing ledgers, so an account with a pathological ListLedgers
		// result never exceeds the cap.
		ledgers := out.Ledgers
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(ledgers) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			ledgers = ledgers[:remaining]
		}
		for _, l := range ledgers {
			if l.Name == nil {
				continue
			}
			name := *l.Name
			desc, derr := client.DescribeLedger(ctx, &qldb.DescribeLedgerInput{Name: l.Name})
			kmsKey := "AWS_OWNED_KMS_KEY"
			if derr != nil {
				fmt.Fprintf(os.Stderr, "qldb:%s DescribeLedger: %v\n", name, derr)
			} else if desc.EncryptionDescription != nil &&
				desc.EncryptionDescription.KmsKeyArn != nil &&
				*desc.EncryptionDescription.KmsKeyArn != "" {
				kmsKey = *desc.EncryptionDescription.KmsKeyArn
			}
			a := services.NewAsset("qldb", models.CategoryDataAtRest, accountID, region, name, "AWS::QLDB::Ledger", services.AESAtRest())
			services.PostureProperty(&a, models.PostureSymmetricOnly)
			services.StampDocFactKeyed(&a, "datarest/qldb/at-rest-aes256")
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
