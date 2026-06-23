package certmgmt

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// IAMCertsScanner discovers legacy IAM-uploaded server certificates.
type IAMCertsScanner struct{}

// Name returns the canonical scanner identifier.
func (IAMCertsScanner) Name() string { return "iam_certs" }

// Category returns the primary category for this scanner.
func (IAMCertsScanner) Category() models.Category { return models.CategoryCertificate }

// iamCertsAPI is the minimal slice of the iam client this scanner uses.
// ListServerCertificates is Marker/IsTruncated-paginated (a single call returns
// only the first page, silently dropping certs in dense accounts), and
// GetServerCertificate fetches each cert's PEM body for real algorithm parsing.
// Defining it as an interface keeps the pagination + error-propagation logic
// unit-testable with a fake (the concrete *iam.Client satisfies it).
type iamCertsAPI interface {
	ListServerCertificates(ctx context.Context, in *iam.ListServerCertificatesInput, optFns ...func(*iam.Options)) (*iam.ListServerCertificatesOutput, error)
	GetServerCertificate(ctx context.Context, in *iam.GetServerCertificateInput, optFns ...func(*iam.Options)) (*iam.GetServerCertificateOutput, error)
}

// Scan lists IAM server certificates and parses each cert PEM for its real
// signature/public-key algorithm; posture follows the parse result (classical
// when confirmed, Unknown otherwise) rather than assuming all IAM certs are RSA.
// Pagination via Marker/IsTruncated; capped at 1000 items.
func (s IAMCertsScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := iam.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListServerCertificates, fetches and
// parses each cert PEM, and classifies it into a CryptoAsset. A
// ListServerCertificates error is NOT swallowed — it is returned so the engine
// records this scanner as errored, keeping a denied/throttled scan VISIBLY
// incomplete rather than a clean-looking empty success.
func (s IAMCertsScanner) scan(ctx context.Context, client iamCertsAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	const maxItems = 1000
	var marker *string
	for {
		out, err := client.ListServerCertificates(ctx, &iam.ListServerCertificatesInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("iam ListServerCertificates: %w", err)
		}
		for _, m := range out.ServerCertificateMetadataList {
			if m.Arn == nil {
				continue
			}
			id := *m.Arn
			name := ""
			if m.ServerCertificateName != nil {
				name = *m.ServerCertificateName
			}
			var nb, na time.Time
			if m.UploadDate != nil {
				nb = *m.UploadDate
			}
			if m.Expiration != nil {
				na = *m.Expiration
			}

			// ListServerCertificates does not expose the cert algorithm, but the
			// per-cert GetServerCertificate returns the PEM body — fetch and PARSE
			// it for the real signature/public-key algorithm rather than guessing.
			// ReadOnlyAccess grants iam:GetServerCertificate.
			var parsed parsedCert
			if m.ServerCertificateName != nil {
				gout, gerr := client.GetServerCertificate(ctx, &iam.GetServerCertificateInput{ServerCertificateName: m.ServerCertificateName})
				if gerr != nil {
					fmt.Fprintf(os.Stderr, "iam GetServerCertificate %s: %v\n", name, gerr)
				} else if gout.ServerCertificate != nil && gout.ServerCertificate.CertificateBody != nil {
					parsed = parseCertPEM(*gout.ServerCertificate.CertificateBody)
				}
			}

			props := services.CertProps(name, "", parsed.SigAlgo, nb, na)
			if parsed.AlgoProps != nil {
				props.AlgorithmProperties = parsed.AlgoProps
			}
			a := services.NewAsset("iam_certs", models.CategoryCertificate, accountID, region, id, "AWS::IAM::ServerCertificate", props)
			a.Properties["serverCertificateName"] = name
			if parsed.PubKeyAlgo != "" {
				a.Properties["publicKeyAlgorithm"] = parsed.PubKeyAlgo
			}
			// Posture follows what we actually PARSED from the cert PEM, not a blanket
			// assumption. IAM imposes no key-algorithm allowlist on uploaded certs, so
			// unconditionally stamping NonPQCClassical was a FALSE-SAFE: a parse
			// failure, an unrecognized key OID, or a genuine PQC leaf would all be
			// hidden behind a confident "classical" label. When the parse confirmed a
			// classical leaf we record that as an observation; otherwise the posture is
			// Unknown (honest) rather than a fabricated classical verdict.
			if parsed.Posture == models.PostureNonPQCClassical {
				services.PostureProperty(&a, models.PostureNonPQCClassical)
				services.StampObserved(&a, "high")
			} else {
				services.PostureProperty(&a, models.PostureUnknown)
			}
			assets = append(assets, a)
			if len(assets) >= maxItems {
				return assets, nil
			}
		}
		if !out.IsTruncated || out.Marker == nil || *out.Marker == "" {
			break
		}
		marker = out.Marker
	}
	return assets, nil
}
