package sdkpqc

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// containerimagesStrptr is a local string-pointer helper. It is deliberately
// prefixed with the scanner short name to avoid colliding with similarly named
// helpers other sdkpqc test files in this shared package may define.
func containerimagesStrptr(s string) *string { return &s }

// fakeContainerImagesClient is a hand-rolled ecrImagesAPI for unit-testing the
// scanner's pagination, per-repository error degradation, and KMS spec mapping
// without a live AWS client. repoPages is returned page-by-page (each
// DescribeRepositories call consumes the next page) with the NextToken wired so
// the scanner loops through every page; repoErr forces a top-level
// DescribeRepositories failure; imagesErr forces a per-repository DescribeImages
// failure; describeKeySpec / describeKeyErr drive the KMS DescribeKey result.
type fakeContainerImagesClient struct {
	repoPages []*ecr.DescribeRepositoriesOutput
	repoCalls int
	repoErr   error

	imagesOut *ecr.DescribeImagesOutput
	imagesErr error

	describeKeySpec string
	describeKeyErr  error
	describeKeyHits int
}

func (f *fakeContainerImagesClient) DescribeRepositories(ctx context.Context, in *ecr.DescribeRepositoriesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	if f.repoErr != nil {
		return nil, f.repoErr
	}
	if f.repoCalls >= len(f.repoPages) {
		return &ecr.DescribeRepositoriesOutput{}, nil
	}
	out := f.repoPages[f.repoCalls]
	f.repoCalls++
	return out, nil
}

func (f *fakeContainerImagesClient) DescribeImages(ctx context.Context, in *ecr.DescribeImagesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
	if f.imagesErr != nil {
		return nil, f.imagesErr
	}
	if f.imagesOut != nil {
		return f.imagesOut, nil
	}
	return &ecr.DescribeImagesOutput{}, nil
}

func (f *fakeContainerImagesClient) DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	f.describeKeyHits++
	if f.describeKeyErr != nil {
		return nil, f.describeKeyErr
	}
	if f.describeKeySpec == "" {
		return &kms.DescribeKeyOutput{}, nil
	}
	return &kms.DescribeKeyOutput{
		KeyMetadata: &kmstypes.KeyMetadata{KeySpec: kmstypes.KeySpec(f.describeKeySpec)},
	}, nil
}

// containerimagesAssetByID indexes the returned assets by ResourceID for lookup.
func containerimagesAssetByID(assets []models.CryptoAsset) map[string]models.CryptoAsset {
	m := map[string]models.CryptoAsset{}
	for _, a := range assets {
		m[a.ResourceID] = a
	}
	return m
}

// TestContainerImagesScanPaginatesRepos verifies the DescribeRepositories
// NextToken loop: a fake that returns 2 pages (NextToken on page 1) must yield
// BOTH pages' repositories as assets. Without the pagination loop, only the first
// page's repository would survive, silently dropping repos in dense accounts.
func TestContainerImagesScanPaginatesRepos(t *testing.T) {
	client := &fakeContainerImagesClient{
		repoPages: []*ecr.DescribeRepositoriesOutput{
			{
				Repositories: []ecrtypes.Repository{
					{
						RepositoryName: containerimagesStrptr("repo-page1"),
						RepositoryArn:  containerimagesStrptr("arn:aws:ecr:us-east-1:111122223333:repository/repo-page1"),
					},
				},
				NextToken: containerimagesStrptr("tok-page2"),
			},
			{
				Repositories: []ecrtypes.Repository{
					{
						RepositoryName: containerimagesStrptr("repo-page2"),
						RepositoryArn:  containerimagesStrptr("arn:aws:ecr:us-east-1:111122223333:repository/repo-page2"),
					},
				},
				// no NextToken -> last page
			},
		},
	}
	assets, err := ContainerImagesScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.repoCalls; c != 2 {
		t.Errorf("expected DescribeRepositories to be called 2 times (paginated), got %d", c)
	}
	byID := containerimagesAssetByID(assets)
	for _, want := range []string{
		"arn:aws:ecr:us-east-1:111122223333:repository/repo-page1",
		"arn:aws:ecr:us-east-1:111122223333:repository/repo-page2",
	} {
		if _, ok := byID[want]; !ok {
			t.Errorf("expected repository %q from a paginated page to appear as an asset; got %v", want, mapKeysContainerImages(byID))
		}
	}
}

// TestContainerImagesScanReposErrorPropagates verifies the incompleteness posture:
// a DescribeRepositories failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error wrapping the failure — NOT a silent
// empty success.
func TestContainerImagesScanReposErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform ecr:DescribeRepositories")
	client := &fakeContainerImagesClient{repoErr: sentinel}
	_, err := ContainerImagesScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeRepositories fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeRepositories failure, got: %v", err)
	}
}

// TestContainerImagesScanImagesErrorNoSilentDrop verifies a per-repository
// DescribeImages failure degrades only the informational image count and never
// drops the repository asset itself (the at-rest crypto fact is read from the
// already-fetched Repository, independent of the image listing).
func TestContainerImagesScanImagesErrorNoSilentDrop(t *testing.T) {
	client := &fakeContainerImagesClient{
		repoPages: []*ecr.DescribeRepositoriesOutput{
			{Repositories: []ecrtypes.Repository{
				{
					RepositoryName: containerimagesStrptr("repo-img-err"),
					RepositoryArn:  containerimagesStrptr("arn:repo-img-err"),
				},
			}},
		},
		imagesErr: errors.New("AccessDeniedException: ecr:DescribeImages"),
	}
	assets, err := ContainerImagesScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("a per-repository DescribeImages error must NOT fail the scan, got: %v", err)
	}
	byID := containerimagesAssetByID(assets)
	a, ok := byID["arn:repo-img-err"]
	if !ok {
		t.Fatalf("repository asset was silently dropped on DescribeImages error; assets=%v", mapKeysContainerImages(byID))
	}
	if a.Properties["imageCount"] != "0" {
		t.Errorf("expected imageCount to degrade to 0 on DescribeImages error, got %q", a.Properties["imageCount"])
	}
}

// TestContainerImagesScanDefaultAES256SymmetricOnly verifies the honesty posture
// for an always-encrypted at-rest domain: a repository with no explicit
// EncryptionConfiguration (ECR default AES256 / SSE-S3) must be classified
// SymmetricOnly (quantum-safe at rest) and NEVER NoEncryption.
func TestContainerImagesScanDefaultAES256SymmetricOnly(t *testing.T) {
	client := &fakeContainerImagesClient{
		repoPages: []*ecr.DescribeRepositoriesOutput{
			{Repositories: []ecrtypes.Repository{
				{RepositoryName: containerimagesStrptr("repo-aes"), RepositoryArn: containerimagesStrptr("arn:repo-aes")},
			}},
		},
	}
	assets, err := ContainerImagesScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	a := containerimagesAssetByID(assets)["arn:repo-aes"]
	if got := a.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
		t.Errorf("expected default-AES256 repo posture %q, got %q", models.PostureSymmetricOnly, got)
	}
	if a.Properties["encryptionType"] != string(ecrtypes.EncryptionTypeAes256) {
		t.Errorf("expected encryptionType %q, got %q", ecrtypes.EncryptionTypeAes256, a.Properties["encryptionType"])
	}
	// Defensive: at-rest must never present as NoEncryption.
	if a.Properties["posture"] == string(models.PostureNoEncryption) {
		t.Error("always-encrypted ECR repo must never be classified NoEncryption")
	}
}

// TestContainerImagesScanKMSSpecMapping verifies the KMS spec-mapping honesty
// posture: a KMS-encrypted repository whose backing key reports a symmetric spec
// maps to SymmetricOnly, while a (defensive) RSA key spec maps to NonPQCClassical.
func TestContainerImagesScanKMSSpecMapping(t *testing.T) {
	cases := []struct {
		name        string
		keySpec     string
		wantPosture models.CryptoPosture
	}{
		{"symmetric_default", "SYMMETRIC_DEFAULT", models.PostureSymmetricOnly},
		{"hmac_recognized_symmetric", "HMAC_256", models.PostureSymmetricOnly},
		{"rsa_classical", "RSA_2048", models.PostureNonPQCClassical},
		{"ecc_classical", "ECC_NIST_P256", models.PostureNonPQCClassical},
		// FIX #7: a genuinely-unrecognized / future KeySpec must NOT false-safe to
		// SymmetricOnly — it is the conservative PostureUnknown (mirrors
		// keymgmt/kms_spec.go's kmsSpecPosture default). A future asymmetric spec
		// must never be silently credited as a quantum-safe symmetric envelope.
		{"unknown_future_spec", "ML_KEM_9999_FUTURE", models.PostureUnknown},
		{"unrecognized_garbage_spec", "TOTALLY_UNKNOWN_SPEC", models.PostureUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeContainerImagesClient{
				repoPages: []*ecr.DescribeRepositoriesOutput{
					{Repositories: []ecrtypes.Repository{
						{
							RepositoryName: containerimagesStrptr("repo-kms"),
							RepositoryArn:  containerimagesStrptr("arn:repo-kms"),
							EncryptionConfiguration: &ecrtypes.EncryptionConfiguration{
								EncryptionType: ecrtypes.EncryptionTypeKms,
								KmsKey:         containerimagesStrptr("arn:aws:kms:us-east-1:111122223333:key/abc"),
							},
						},
					}},
				},
				describeKeySpec: tc.keySpec,
			}
			assets, err := ContainerImagesScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			a := containerimagesAssetByID(assets)["arn:repo-kms"]
			if got := a.Properties["posture"]; got != string(tc.wantPosture) {
				t.Errorf("keySpec %q: expected posture %q, got %q", tc.keySpec, tc.wantPosture, got)
			}
			if a.Properties["kmsKeySpec"] != tc.keySpec {
				t.Errorf("keySpec %q: expected kmsKeySpec prop %q, got %q", tc.keySpec, tc.keySpec, a.Properties["kmsKeySpec"])
			}
			if client.describeKeyHits != 1 {
				t.Errorf("expected exactly 1 DescribeKey call for the KMS repo, got %d", client.describeKeyHits)
			}
		})
	}
}

// TestContainerImagesScanKMSDescribeKeyErrorDegrades verifies the no-silent-classical
// rule: when DescribeKey fails for a KMS-encrypted repository, the scanner degrades
// to SYMMETRIC_DEFAULT (still SymmetricOnly, quantum-safe at rest) rather than
// silently downgrading the at-rest fact to classical or NoEncryption.
func TestContainerImagesScanKMSDescribeKeyErrorDegrades(t *testing.T) {
	client := &fakeContainerImagesClient{
		repoPages: []*ecr.DescribeRepositoriesOutput{
			{Repositories: []ecrtypes.Repository{
				{
					RepositoryName: containerimagesStrptr("repo-kms-err"),
					RepositoryArn:  containerimagesStrptr("arn:repo-kms-err"),
					EncryptionConfiguration: &ecrtypes.EncryptionConfiguration{
						EncryptionType: ecrtypes.EncryptionTypeKms,
						KmsKey:         containerimagesStrptr("arn:aws:kms:us-east-1:111122223333:key/denied"),
					},
				},
			}},
		},
		describeKeyErr: errors.New("AccessDeniedException: kms:DescribeKey"),
	}
	assets, err := ContainerImagesScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("a DescribeKey error must degrade, not fail the scan, got: %v", err)
	}
	a := containerimagesAssetByID(assets)["arn:repo-kms-err"]
	if got := a.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
		t.Errorf("expected DescribeKey-error degradation to SymmetricOnly, got %q", got)
	}
	if a.Properties["kmsKeySpec"] != "SYMMETRIC_DEFAULT" {
		t.Errorf("expected degraded kmsKeySpec SYMMETRIC_DEFAULT, got %q", a.Properties["kmsKeySpec"])
	}
}

// mapKeysContainerImages returns the keys of an asset map for test diagnostics.
func mapKeysContainerImages(m map[string]models.CryptoAsset) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
