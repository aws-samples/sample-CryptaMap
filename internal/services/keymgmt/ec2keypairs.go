package keymgmt

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// EC2KeyPairsScanner inventories EC2 SSH key pairs as quantum-migration targets.
//
// Every EC2 key pair is either RSA or Ed25519 — both CLASSICAL public-key
// signature/auth algorithms that fall to Shor's algorithm (RSA: factoring;
// Ed25519: elliptic-curve discrete log). There is no PQC SSH key option in EC2
// today, so every key pair is NonPQCClassical. This is a key-inventory surface
// (no encryption-at-rest toggle): a discovered key pair is always a finding to
// migrate, never a pass/fail check, and a missing/empty KeyType is treated as
// classical-unknown, never as safe.
type EC2KeyPairsScanner struct{}

// Name returns the canonical scanner identifier.
func (EC2KeyPairsScanner) Name() string { return "ec2keypairs" }

// Category returns the primary category for this scanner.
func (EC2KeyPairsScanner) Category() models.Category { return models.CategoryKeyManagement }

// ec2KeyPairsAPI is the minimal slice of the ec2 client this scanner uses.
// DescribeKeyPairs is unpaginated (it returns every key pair in one call), so
// there is no NextToken loop; defining the dependency as an interface keeps the
// error-propagation and classification logic unit-testable with a fake (the
// concrete *ec2.Client satisfies it).
type ec2KeyPairsAPI interface {
	DescribeKeyPairs(ctx context.Context, in *ec2.DescribeKeyPairsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeKeyPairsOutput, error)
}

// Scan calls DescribeKeyPairs (unpaginated — returns all key pairs in one call)
// and emits one asset per key pair.
func (s EC2KeyPairsScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := ec2.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it lists key pairs and classifies each into a
// CryptoAsset. A DescribeKeyPairs error is NOT swallowed — it is returned so the
// engine records this scanner as errored (which surfaces in coverage), keeping a
// denied/throttled scan VISIBLY incomplete rather than a clean-looking empty
// success.
func (s EC2KeyPairsScanner) scan(ctx context.Context, client ec2KeyPairsAPI, accountID, region string) ([]models.CryptoAsset, error) {
	out, err := client.DescribeKeyPairs(ctx, &ec2.DescribeKeyPairsInput{})
	if err != nil {
		return nil, fmt.Errorf("ec2 DescribeKeyPairs: %w", err)
	}

	assets := []models.CryptoAsset{}
	for _, kp := range out.KeyPairs {
		if kp.KeyPairId == nil {
			continue
		}
		id := *kp.KeyPairId
		keyType := string(kp.KeyType) // "rsa" | "ed25519" | "" (field-population gap)

		// Map the SSH key algorithm to a classical signature profile. Both RSA and
		// Ed25519 are quantum-vulnerable; size/curve differ for display only.
		algoName, keyBits, classical := ec2KeyAlgo(keyType)
		props := services.KeyMaterialProps("private-key", models.StateActive, keyBits, keyType)
		if props.AlgorithmProperties == nil {
			props.AlgorithmProperties = &models.AlgorithmProperties{}
		}
		props.AlgorithmProperties.Primitive = models.PrimitiveSignature
		props.AlgorithmProperties.AlgorithmName = algoName
		props.AlgorithmProperties.KeySizeBits = keyBits
		props.AlgorithmProperties.ClassicalSecurityLevel = classical
		props.AlgorithmProperties.NistQuantumSecurityLevel = 0
		if kp.CreateTime != nil && props.RelatedCryptoMaterialProperties != nil {
			props.RelatedCryptoMaterialProperties.CreationDate = kp.CreateTime.UTC()
		}

		a := services.NewAsset("ec2keypairs", models.CategoryKeyManagement, accountID, region, id, "AWS::EC2::KeyPair", props)
		services.PostureProperty(&a, models.PostureNonPQCClassical)
		if keyType != "" {
			a.Properties["keyType"] = keyType
			services.StampObserved(&a, "high")
		} else {
			a.Properties["note"] = "Key type not reported by the API; an EC2 key pair always has an underlying classical algorithm, so this is treated as classical-unknown, never quantum-resistant."
		}
		if kp.KeyName != nil {
			a.Properties["keyName"] = *kp.KeyName
		}
		if kp.KeyFingerprint != nil {
			a.Properties["keyFingerprint"] = *kp.KeyFingerprint
		}
		if kp.CreateTime != nil {
			a.Properties["createTime"] = kp.CreateTime.UTC().Format(time.RFC3339)
		}
		assets = append(assets, a)
		if services.TruncationCapReached(len(assets), s.Name(), region) {
			return assets, nil
		}
	}
	return assets, nil
}

// ec2KeyAlgo maps an EC2 KeyType to (display name, key size bits, classical
// security level). Both supported types are classical / quantum-vulnerable.
func ec2KeyAlgo(keyType string) (name string, bits int, classical int) {
	switch strings.ToLower(keyType) {
	case "rsa":
		// EC2 RSA key pairs are 2048-bit (SSH-2 RSA).
		return "RSA-2048 (SSH)", 2048, 112
	case "ed25519":
		return "Ed25519 (SSH)", 256, 128
	default:
		return "classical SSH key (algorithm unreported)", 0, 0
	}
}
