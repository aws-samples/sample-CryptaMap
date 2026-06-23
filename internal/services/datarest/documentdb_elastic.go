package datarest

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/docdbelastic"
	deltypes "github.com/aws/aws-sdk-go-v2/service/docdbelastic/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// DocumentDBElasticScanner inspects Amazon DocumentDB ELASTIC clusters for at-rest
// encryption. This closes the coverage gap left by DocumentDBScanner, which uses
// the instance-based DescribeDBClusters API and never sees elastic clusters (a
// separate docdb-elastic service/API).
//
// Elastic clusters are always KMS envelope-encrypted at rest with no opt-out, so
// posture is unconditionally SymmetricOnly; an absent KmsKeyId is the AWS-owned
// default key, not no-encryption.
type DocumentDBElasticScanner struct{}

// docDBElasticAPI is the minimal slice of the docdbelastic client this scanner
// uses. ListClusters is NextToken-paginated; defining it as an interface keeps
// the pagination + per-cluster key classification unit-testable with a fake (the
// concrete *docdbelastic.Client satisfies it).
type docDBElasticAPI interface {
	ListClusters(ctx context.Context, in *docdbelastic.ListClustersInput, optFns ...func(*docdbelastic.Options)) (*docdbelastic.ListClustersOutput, error)
	GetCluster(ctx context.Context, in *docdbelastic.GetClusterInput, optFns ...func(*docdbelastic.Options)) (*docdbelastic.GetClusterOutput, error)
}

// Name returns the canonical service identifier.
func (DocumentDBElasticScanner) Name() string { return "documentdb_elastic" }

// Category returns the primary CryptaMap category.
func (DocumentDBElasticScanner) Category() models.Category { return models.CategoryDataAtRest }

// Scan lists elastic clusters, then GetCluster for the KMS key (ListClusters does
// not carry KmsKeyId).
func (s DocumentDBElasticScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := docdbelastic.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListClusters and reads each
// cluster's KmsKeyId via GetCluster. A ListClusters error is returned (not
// swallowed) so a denied/throttled scan stays VISIBLY incomplete.
func (s DocumentDBElasticScanner) scan(ctx context.Context, client docDBElasticAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListClusters(ctx, &docdbelastic.ListClustersInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("docdbelastic ListClusters: %w", err)
		}
		clusters := out.Clusters
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(clusters) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			clusters = clusters[:remaining]
		}
		page := services.MapConcurrent(ctx, services.DefaultInnerConcurrency, clusters,
			func(ctx context.Context, c deltypes.ClusterInList) (models.CryptoAsset, bool) {
				if c.ClusterArn == nil {
					return models.CryptoAsset{}, false
				}
				arn := *c.ClusterArn
				// GetCluster carries the per-cluster KmsKeyId; an empty key, nil
				// cluster, or a describe failure all fall back to the AWS-owned
				// default key (posture is unchanged either way).
				kmsKey := ""
				if d, derr := client.GetCluster(ctx, &docdbelastic.GetClusterInput{ClusterArn: c.ClusterArn}); derr != nil {
					fmt.Fprintf(os.Stderr, "docdbelastic GetCluster %s: %v\n", arn, derr)
				} else if d.Cluster != nil && d.Cluster.KmsKeyId != nil {
					kmsKey = *d.Cluster.KmsKeyId
				}
				clusterName := ""
				if c.ClusterName != nil {
					clusterName = *c.ClusterName
				}
				return classifyDocumentDBElasticCluster(accountID, region, arn, clusterName, kmsKey), true
			})
		assets = append(assets, page...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}

// classifyDocumentDBElasticCluster builds the at-rest asset for a single elastic
// cluster from already-resolved fields. Posture is unconditionally SymmetricOnly:
// elastic clusters are always KMS-encrypted at rest with no opt-out, so a
// describe failure (empty kmsKeyId) NEVER downgrades posture — it only falls the
// recorded key back to the AWS-owned default. A non-empty kmsKeyId is recorded
// verbatim as the backing key.
func classifyDocumentDBElasticCluster(accountID, region, arn, clusterName, kmsKeyId string) models.CryptoAsset {
	if kmsKeyId == "" {
		kmsKeyId = "AWS_OWNED_KMS_KEY"
	}
	a := services.NewAsset("documentdb_elastic", models.CategoryDataAtRest, accountID, region, arn, "AWS::DocDBElastic::Cluster", services.AESAtRest())
	services.PostureProperty(&a, models.PostureSymmetricOnly)
	a.Properties["kmsKeyId"] = kmsKeyId
	if clusterName != "" {
		a.Properties["clusterName"] = clusterName
	}
	return a
}
