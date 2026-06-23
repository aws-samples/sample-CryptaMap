package output

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// S3Writer uploads CryptaMap artifacts to a results bucket.
type S3Writer struct {
	Bucket string
	Prefix string
	Client *s3.Client
}

// NewS3Writer constructs an S3Writer from an aws.Config.
func NewS3Writer(cfg aws.Config, bucket, prefix string) *S3Writer {
	return &S3Writer{Bucket: bucket, Prefix: prefix, Client: s3.NewFromConfig(cfg)}
}

// Key builds the canonical CBOM key for a scan.
func Key(prefix, accountID, region, scanID string) string {
	return fmt.Sprintf("%scryptamap-scan-%s-%s-%s.json", prefix, accountID, region, scanID)
}

// PutCBOM writes the CycloneDX CBOM JSON for a scan.
func (w *S3Writer) PutCBOM(ctx context.Context, scan models.ScanResult) (string, error) {
	body, err := AsBytes(scan)
	if err != nil {
		return "", err
	}
	key := Key(w.Prefix, scan.AccountID, scan.Region, scan.ScanID)
	_, err = w.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:               aws.String(w.Bucket),
		Key:                  aws.String(key),
		Body:                 bytes.NewReader(body),
		ContentType:          aws.String("application/json"),
		ServerSideEncryption: types.ServerSideEncryptionAes256,
	})
	if err != nil {
		return "", fmt.Errorf("S3 PutObject %s/%s: %w", w.Bucket, key, err)
	}
	return key, nil
}

// PutLatest writes the "latest" pointer for a (account, region) tuple.
func (w *S3Writer) PutLatest(ctx context.Context, scan models.ScanResult) (string, error) {
	body, err := json.MarshalIndent(scan.Summary, "", "  ")
	if err != nil {
		return "", err
	}
	key := fmt.Sprintf("%slatest/%s-%s.json", w.Prefix, scan.AccountID, scan.Region)
	_, err = w.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:               aws.String(w.Bucket),
		Key:                  aws.String(key),
		Body:                 bytes.NewReader(body),
		ContentType:          aws.String("application/json"),
		ServerSideEncryption: types.ServerSideEncryptionAes256,
	})
	return key, err
}

// PutBytes uploads any artefact (excel, asff, pdf) under the same prefix.
func (w *S3Writer) PutBytes(ctx context.Context, key string, body []byte, contentType string) (string, error) {
	fullKey := w.Prefix + key
	_, err := w.Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:               aws.String(w.Bucket),
		Key:                  aws.String(fullKey),
		Body:                 bytes.NewReader(body),
		ContentType:          aws.String(contentType),
		ServerSideEncryption: types.ServerSideEncryptionAes256,
	})
	return fullKey, err
}
