// Package scanner orchestrates parallel discovery across all service scanners.
package scanner

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// ServiceScanner is the contract every per-service scanner implements.
// One Scan call corresponds to scanning the service in one (account, region).
type ServiceScanner interface {
	Name() string              // canonical service identifier (e.g. "s3", "alb")
	Category() models.Category // primary category for severity defaults
	Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error)
}
