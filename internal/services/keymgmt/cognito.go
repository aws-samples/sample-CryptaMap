package keymgmt

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// CognitoScanner inventories Amazon Cognito user pools as JWT token-signing assets.
//
// The PQC-relevant asset is the user pool's token signature: every Cognito user
// pool signs its ID and access tokens with RS256 (RSA-2048 + SHA-256). This is a
// CLASSICAL, quantum-vulnerable SIGNATURE (forgeable under Shor's algorithm), and
// it is INTRINSIC and NON-CONFIGURABLE — there is no PQC/hybrid option and the
// customer cannot change it. So every user pool is unconditionally NonPQCClassical
// for token signing. This is an always-on classical-crypto finding (a quantum-
// migration target), NOT an "encryption is off" finding — and it must never be
// reported as safe. (Category is KeyManagement: the asset is the service-managed
// RSA signing key pair.)
type CognitoScanner struct{}

// Name returns the canonical scanner identifier.
func (CognitoScanner) Name() string { return "cognito" }

// Category returns the primary category for this scanner.
func (CognitoScanner) Category() models.Category { return models.CategoryKeyManagement }

// cognitoUserPoolsAPI is the minimal slice of the cognitoidentityprovider client
// this scanner uses. ListUserPools is NextToken-paginated (and capped at
// MaxResults=60 per call), so the scanner must loop; a single call silently drops
// user pools beyond the first page in dense accounts. Defining it as an interface
// keeps the pagination + error propagation logic unit-testable with a fake (the
// concrete *cognitoidentityprovider.Client satisfies it).
type cognitoUserPoolsAPI interface {
	ListUserPools(ctx context.Context, in *cognitoidentityprovider.ListUserPoolsInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUserPoolsOutput, error)
}

// Scan enumerates user pools and emits one RS256 token-signing asset per pool.
// ListUserPools requires MaxResults (1-60); paginate via NextToken.
func (s CognitoScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := cognitoidentityprovider.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListUserPools and emits one RS256
// token-signing asset per user pool. A ListUserPools error is NOT swallowed — it
// is returned so the engine records this scanner as errored, keeping a
// denied/throttled scan VISIBLY incomplete rather than a clean-looking empty
// success.
func (s CognitoScanner) scan(ctx context.Context, client cognitoUserPoolsAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListUserPools(ctx, &cognitoidentityprovider.ListUserPoolsInput{
			MaxResults: aws.Int32(60), // REQUIRED, max 60
			NextToken:  nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("cognito ListUserPools: %w", err)
		}
		pools := out.UserPools
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(pools) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			pools = pools[:remaining]
		}
		for _, p := range pools {
			if p.Id == nil {
				continue
			}
			id := *p.Id
			// RS256 = RSA-2048 + SHA-256 signature: classical, quantum-vulnerable,
			// intrinsic to every user pool. Emit the signing key pair as a
			// private-key asset with a classical signature algorithm.
			props := services.KeyMaterialProps("private-key", models.StateActive, 2048, "RS256")
			if props.AlgorithmProperties == nil {
				props.AlgorithmProperties = &models.AlgorithmProperties{}
			}
			props.AlgorithmProperties.Primitive = models.PrimitiveSignature
			props.AlgorithmProperties.AlgorithmName = "RS256 (RSA-2048 + SHA-256)"
			props.AlgorithmProperties.KeySizeBits = 2048
			props.AlgorithmProperties.ClassicalSecurityLevel = 112
			props.AlgorithmProperties.NistQuantumSecurityLevel = 0

			a := services.NewAsset("cognito", models.CategoryKeyManagement, accountID, region, id, "AWS::Cognito::UserPool", props)
			services.PostureProperty(&a, models.PostureNonPQCClassical)
			services.StampDocFactKeyed(&a, "keymgmt/cognito/rs256-token-signing")
			if p.Name != nil {
				a.Properties["userPoolName"] = *p.Name
			}
			a.Properties["tokenSigningAlgorithm"] = "RS256"
			a.Properties["note"] = "Cognito ID/access tokens are signed with RS256 (RSA-2048), a classical quantum-vulnerable signature that cannot be changed; a quantum-migration target with no current PQC option."
			assets = append(assets, a)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
