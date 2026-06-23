package keymgmt

// fuzz_invariant_test.go is the ADVERSARIAL property/invariant test for the
// key-management scanner cores PLUS a Go-native fuzz target for the kmsSpecPosture
// mapper. See the datarest sibling for the cross-package rationale.
//
// Scanner cores covered (Scanner{}.scan(ctx, fakeClient, acct, region)) with the
// hostile shapes (top-level List error / per-resource Describe error / nil-empty
// output / empty page). Invariants: no panic; top-level error propagates with
// nil/empty assets; every emitted asset has a 7-enum posture + non-empty Service;
// no asset from a FAILED read carries a confident no-encryption / symmetric-only
// verdict (key-material scanners legitimately emit NonPQCClassical for a classical
// key whose detail read failed — that is the conservative quantum-vulnerable
// verdict, not a fabricated all-clear).

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

var keyValidPostures = map[models.CryptoPosture]bool{
	models.PostureNoEncryption:    true,
	models.PostureLegacyTLS:       true,
	models.PostureNonPQCClassical: true,
	models.PostureSymmetricOnly:   true,
	models.PosturePQCHybrid:       true,
	models.PosturePQCReady:        true,
	models.PostureUnknown:         true,
}

func keyAssertHonest(t *testing.T, scanner string, assets []models.CryptoAsset, fromFailedRead bool) {
	t.Helper()
	for i, a := range assets {
		if a.Service == "" {
			t.Errorf("[%s] asset #%d has empty Service (escapes the registry)", scanner, i)
		}
		p := models.CryptoPosture(a.Properties["posture"])
		if !keyValidPostures[p] {
			t.Errorf("[%s] asset #%d has posture %q outside the 7-value enum", scanner, i, p)
		}
		if fromFailedRead && (p == models.PostureNoEncryption || p == models.PostureSymmetricOnly) {
			t.Errorf("[%s] asset #%d produced a confident %q verdict on a FAILED read (fabricated verdict); note=%q",
				scanner, i, p, a.Properties["note"])
		}
		if fromFailedRead && (p == models.PosturePQCHybrid || p == models.PosturePQCReady) {
			t.Errorf("[%s] asset #%d produced a PQC-SAFE verdict %q on a FAILED read (fabricated all-clear)", scanner, i, p)
		}
	}
}

func keyRunCase(t *testing.T, scanner, scenario string, wantErr, fromFailedRead bool, fn func() ([]models.CryptoAsset, error)) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("[%s/%s] PANIC on hostile input: %v", scanner, scenario, r)
		}
	}()
	assets, err := fn()
	if wantErr {
		if err == nil {
			t.Errorf("[%s/%s] expected a propagated error, got nil (silent empty success)", scanner, scenario)
		}
		if len(assets) != 0 {
			t.Errorf("[%s/%s] expected no assets on a top-level read error, got %d", scanner, scenario, len(assets))
		}
	}
	keyAssertHonest(t, scanner, assets, fromFailedRead)
}

var keyErrHostile = errors.New("AccessDeniedException: hostile-fuzz denied read")

// kms_spec: ListKeys + DescribeKey.
type fuzzKMSSpecClient struct{ errTop, errResource bool }

func (f *fuzzKMSSpecClient) ListKeys(ctx context.Context, in *kms.ListKeysInput, _ ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	if f.errTop {
		return nil, keyErrHostile
	}
	if f.errResource {
		id := "key-1"
		return &kms.ListKeysOutput{Keys: []kmstypes.KeyListEntry{{KeyId: &id}}}, nil
	}
	return &kms.ListKeysOutput{}, nil
}
func (f *fuzzKMSSpecClient) DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if f.errResource {
		return nil, keyErrHostile
	}
	return &kms.DescribeKeyOutput{}, nil // nil metadata -> dropped
}

// cognito: ListUserPools.
type fuzzCognitoClient struct{ errTop bool }

func (f *fuzzCognitoClient) ListUserPools(ctx context.Context, in *cognitoidentityprovider.ListUserPoolsInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUserPoolsOutput, error) {
	if f.errTop {
		return nil, keyErrHostile
	}
	return &cognitoidentityprovider.ListUserPoolsOutput{}, nil
}

// ec2keypairs: DescribeKeyPairs.
type fuzzEC2KeyPairsClient struct{ errTop bool }

func (f *fuzzEC2KeyPairsClient) DescribeKeyPairs(ctx context.Context, in *ec2.DescribeKeyPairsInput, _ ...func(*ec2.Options)) (*ec2.DescribeKeyPairsOutput, error) {
	if f.errTop {
		return nil, keyErrHostile
	}
	return &ec2.DescribeKeyPairsOutput{}, nil
}

// TestFuzzKeyMgmtScannerInvariants drives the key-management cores hostilely.
func TestFuzzKeyMgmtScannerInvariants(t *testing.T) {
	ctx := context.Background()
	const acct, region = "111122223333", "us-east-1"

	t.Run("topLevelError_propagates", func(t *testing.T) {
		keyRunCase(t, "kms_spec", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return KMSSpecScanner{}.scan(ctx, &fuzzKMSSpecClient{errTop: true}, acct, region)
		})
		keyRunCase(t, "cognito", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return CognitoScanner{}.scan(ctx, &fuzzCognitoClient{errTop: true}, acct, region)
		})
		keyRunCase(t, "ec2keypairs", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return EC2KeyPairsScanner{}.scan(ctx, &fuzzEC2KeyPairsClient{errTop: true}, acct, region)
		})
	})

	t.Run("perResourceError_neverFabricatesVerdict", func(t *testing.T) {
		// kms_spec DROPS a key whose DescribeKey fails; the property guarded is no
		// panic + no fabricated verdict on any emitted asset.
		keyRunCase(t, "kms_spec", "resErr", false, true, func() ([]models.CryptoAsset, error) {
			return KMSSpecScanner{}.scan(ctx, &fuzzKMSSpecClient{errResource: true}, acct, region)
		})
	})

	t.Run("emptyAndNilOutput_noPanic", func(t *testing.T) {
		keyRunCase(t, "kms_spec", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return KMSSpecScanner{}.scan(ctx, &fuzzKMSSpecClient{}, acct, region)
		})
		keyRunCase(t, "cognito", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return CognitoScanner{}.scan(ctx, &fuzzCognitoClient{}, acct, region)
		})
		keyRunCase(t, "ec2keypairs", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return EC2KeyPairsScanner{}.scan(ctx, &fuzzEC2KeyPairsClient{}, acct, region)
		})
	})
}

// FuzzKMSSpecPosture is a Go-native fuzz target for the KMS KeySpec -> posture
// mapper. kmsSpecPosture takes an arbitrary KeySpec string (attacker- or
// future-AWS-influenced) and must NEVER panic and NEVER false-safe an
// unrecognized spec to symmetric-only / PQC: any spec it does not positively
// recognize as symmetric (SYMMETRIC_*/HMAC_*) or PQC (ML_DSA) must classify as
// Unknown or NonPQCClassical — never a fabricated quantum-safe verdict. This is
// the exact false-safe trap the honesty contract calls out (a new asymmetric
// spec must not silently read as quantum-safe).
func FuzzKMSSpecPosture(f *testing.F) {
	seeds := []string{
		"", "SYMMETRIC_DEFAULT", "HMAC_256", "RSA_2048", "RSA_4096",
		"ECC_NIST_P256", "ECC_SECG_P256K1", "SM2", "ML_DSA_65", "ML-DSA-87",
		"FUTURE_KEM_SPEC", "ml_kem_768", "\x00garbage", "rsa_2048",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	valid := map[models.CryptoPosture]bool{
		models.PostureNoEncryption:    true,
		models.PostureLegacyTLS:       true,
		models.PostureNonPQCClassical: true,
		models.PostureSymmetricOnly:   true,
		models.PosturePQCHybrid:       true,
		models.PosturePQCReady:        true,
		models.PostureUnknown:         true,
	}

	f.Fuzz(func(t *testing.T, keySpec string) {
		p := kmsSpecPosture(keySpec) // must not panic

		if !valid[p] {
			t.Fatalf("kmsSpecPosture returned out-of-enum posture %q for spec %q", p, keySpec)
		}

		// False-safe guard: an asymmetric / unrecognized spec must not be reported
		// symmetric-only or PQC. Re-derive the recognition the mapper itself uses,
		// then assert symmetric/PQC verdicts ONLY arise from the positively
		// recognized prefixes.
		up := upperUnderscore(keySpec)
		recognizedSymmetric := startsWith(up, "SYMMETRIC") || startsWith(up, "HMAC")
		recognizedPQC := contains(up, "ML_DSA")

		if p == models.PostureSymmetricOnly && !recognizedSymmetric {
			t.Fatalf("kmsSpecPosture FALSE-SAFE: spec %q classified symmetric-only without a SYMMETRIC_/HMAC_ prefix (a new asymmetric spec could be silently called quantum-safe)", keySpec)
		}
		if (p == models.PosturePQCReady || p == models.PosturePQCHybrid) && !recognizedPQC {
			t.Fatalf("kmsSpecPosture fabricated a PQC verdict %q for spec %q without an ML_DSA token", p, keySpec)
		}
	})
}

// upperUnderscore / startsWith / contains mirror the normalization kmsSpecPosture
// applies, kept tiny and dependency-free for the fuzz target's re-derivation.
func upperUnderscore(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		if c == '-' {
			c = '_'
		}
		out[i] = c
	}
	return string(out)
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func contains(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
