package certmgmt

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iot"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// IoTCertsScanner discovers AWS IoT Core certificates.
type IoTCertsScanner struct{}

// Name returns the canonical scanner identifier.
func (IoTCertsScanner) Name() string { return "iot_certs" }

// Category returns the primary category for this scanner.
func (IoTCertsScanner) Category() models.Category { return models.CategoryCertificate }

// iotCertsAPI is the minimal slice of the iot client this scanner uses.
// ListCertificates is Marker-paginated (a single call returns only the first
// page, silently dropping certs in dense fleets), and DescribeCertificate is a
// per-resource fetch of the leaf PEM. Defining it as an interface keeps the
// pagination + parse + error-handling logic unit-testable with a fake (the
// concrete *iot.Client satisfies it).
type iotCertsAPI interface {
	ListCertificates(ctx context.Context, in *iot.ListCertificatesInput, optFns ...func(*iot.Options)) (*iot.ListCertificatesOutput, error)
	DescribeCertificate(ctx context.Context, in *iot.DescribeCertificateInput, optFns ...func(*iot.Options)) (*iot.DescribeCertificateOutput, error)
}

// Scan lists IoT certificates and emits one asset per certificate.
// Pagination via Marker; capped at 1000 items.
func (s IoTCertsScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := iot.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListCertificates (Marker) and, for
// each cert, fetches and PARSES the leaf PEM to read the real signature/key
// algorithm. A top-level ListCertificates error is NOT swallowed — it is
// returned so the engine records this scanner as errored, keeping a
// denied/throttled scan VISIBLY incomplete rather than a clean-looking empty
// success. A per-certificate DescribeCertificate failure does NOT abort or
// silently drop: the cert is still emitted with PostureUnknown (logged to
// stderr), never disguised as a confident classical classification.
func (s IoTCertsScanner) scan(ctx context.Context, client iotCertsAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	const maxItems = 1000
	var marker *string
	for {
		out, err := client.ListCertificates(ctx, &iot.ListCertificatesInput{Marker: marker})
		if err != nil {
			return nil, fmt.Errorf("iot ListCertificates: %w", err)
		}
		for _, c := range out.Certificates {
			if c.CertificateArn == nil {
				continue
			}
			id := *c.CertificateArn
			var nb time.Time
			if c.CreationDate != nil {
				nb = *c.CreationDate
			}
			subject := ""
			if c.CertificateId != nil {
				subject = *c.CertificateId
			}

			// ListCertificates exposes no algorithm field, so fetch and PARSE the
			// leaf to read the real signature/public-key algorithm. AWS IoT documents
			// support for RSA (>= 2048-bit) and ECC NIST P-256/384/521 device-cert
			// keys; we still parse rather than hardcode, so an unrecognized OID (e.g.
			// a future PQC/EdDSA leaf) is left PostureUnknown instead of mislabeled.
			// ReadOnlyAccess grants iot:DescribeCertificate.
			parsed := parsedCert{Posture: models.PostureUnknown}
			observed := false
			if c.CertificateId != nil {
				dout, derr := client.DescribeCertificate(ctx, &iot.DescribeCertificateInput{CertificateId: c.CertificateId})
				if derr != nil {
					fmt.Fprintf(os.Stderr, "iot DescribeCertificate %s: %v\n", *c.CertificateId, derr)
				} else if dout.CertificateDescription != nil && dout.CertificateDescription.CertificatePem != nil {
					parsed = parseCertPEM(*dout.CertificateDescription.CertificatePem)
					observed = true
				}
			}

			props := services.CertProps(subject, "", parsed.SigAlgo, nb, time.Time{})
			if parsed.AlgoProps != nil {
				props.AlgorithmProperties = parsed.AlgoProps
			}
			a := services.NewAsset("iot_certs", models.CategoryCertificate, accountID, region, id, "AWS::IoT::Certificate", props)
			a.Properties["status"] = string(c.Status)
			a.Properties["certificateMode"] = string(c.CertificateMode)
			if parsed.PubKeyAlgo != "" {
				a.Properties["publicKeyAlgorithm"] = parsed.PubKeyAlgo
			}
			services.PostureProperty(&a, parsed.Posture)
			// A successfully parsed leaf is a real per-resource observation; a
			// failed/empty parse leaves posture Unknown and is not stamped.
			if observed && parsed.Posture != models.PostureUnknown {
				services.StampObserved(&a, "high")
			}
			assets = append(assets, a)
			if len(assets) >= maxItems {
				return assets, nil
			}
		}
		if out.NextMarker == nil || *out.NextMarker == "" {
			break
		}
		marker = out.NextMarker
	}
	return assets, nil
}
