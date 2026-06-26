package keymgmt

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// secretsrotationStrptr is a local *string helper, prefixed to avoid colliding
// with helpers defined by sibling scanner tests in this shared package.
func secretsrotationStrptr(s string) *string { return &s }

// secretsrotationFakeSM is a hand-rolled secretsRotationAPI for unit-testing the
// scanner's pagination + error propagation without a live AWS client. pages is
// returned page-by-page (each call consumes the next), with NextToken wired so
// the scanner loops through every page; listErr forces a ListSecrets failure.
type secretsrotationFakeSM struct {
	pages   []*secretsmanager.ListSecretsOutput
	calls   int
	listErr error
}

func (f *secretsrotationFakeSM) ListSecrets(ctx context.Context, in *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.calls >= len(f.pages) {
		return &secretsmanager.ListSecretsOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

// secretsrotationFakeKMS is a hand-rolled secretsRotationKMSAPI. spec is the
// KeySpec returned by DescribeKey; err forces a DescribeKey failure.
type secretsrotationFakeKMS struct {
	spec  string
	err   error
	calls int
}

func (f *secretsrotationFakeKMS) DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &kms.DescribeKeyOutput{
		KeyMetadata: &kmstypes.KeyMetadata{KeySpec: kmstypes.KeySpec(f.spec)},
	}, nil
}

func secretsrotationAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

func secretsrotationPostureOf(a models.CryptoAsset) string {
	if a.Properties == nil {
		return ""
	}
	return a.Properties["posture"]
}

// TestSecretsRotationScanPaginates verifies the ListSecrets NextToken loop: a
// fake returning 2 pages (NextToken on page 1) must yield BOTH pages' secrets as
// assets. Without the pagination loop, only the first page's secret survives.
func TestSecretsRotationScanPaginates(t *testing.T) {
	client := &secretsrotationFakeSM{
		pages: []*secretsmanager.ListSecretsOutput{
			{
				SecretList: []smtypes.SecretListEntry{
					{ARN: secretsrotationStrptr("arn:aws:secretsmanager:us-east-1:111122223333:secret:page1")},
				},
				NextToken: secretsrotationStrptr("tok-page2"),
			},
			{
				SecretList: []smtypes.SecretListEntry{
					{ARN: secretsrotationStrptr("arn:aws:secretsmanager:us-east-1:111122223333:secret:page2")},
				},
				// no NextToken -> last page
			},
		},
	}
	assets, err := SecretsRotationScanner{}.scan(context.Background(), client, &secretsrotationFakeKMS{}, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Errorf("expected ListSecrets to be called 2 times (paginated), got %d", client.calls)
	}
	for _, want := range []string{
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:page1",
		"arn:aws:secretsmanager:us-east-1:111122223333:secret:page2",
	} {
		if _, ok := secretsrotationAssetByID(assets, want); !ok {
			t.Errorf("expected secret %q from a paginated page to appear as an asset", want)
		}
	}
}

// TestSecretsRotationListErrorPropagates verifies the incompleteness decision: a
// ListSecrets failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success.
func TestSecretsRotationListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform secretsmanager:ListSecrets")
	client := &secretsrotationFakeSM{listErr: sentinel}
	_, err := SecretsRotationScanner{}.scan(context.Background(), client, &secretsrotationFakeKMS{}, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListSecrets fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListSecrets failure, got: %v", err)
	}
}

// TestSecretsRotationDefaultManagedKeyIsSymmetricOnly verifies the honesty
// posture for the common case: a secret with NO customer KmsKeyId is encrypted
// at rest with the AWS-managed key (AES-256). It MUST be SymmetricOnly (quantum
// safe), never NoEncryption — the secret value is always encrypted. DescribeKey
// must NOT be called when there is no customer CMK.
func TestSecretsRotationDefaultManagedKeyIsSymmetricOnly(t *testing.T) {
	client := &secretsrotationFakeSM{
		pages: []*secretsmanager.ListSecretsOutput{
			{SecretList: []smtypes.SecretListEntry{
				{ARN: secretsrotationStrptr("arn:secret:managed")},
			}},
		},
	}
	kmsFake := &secretsrotationFakeKMS{}
	assets, err := SecretsRotationScanner{}.scan(context.Background(), client, kmsFake, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	a, ok := secretsrotationAssetByID(assets, "arn:secret:managed")
	if !ok {
		t.Fatal("expected an asset for the managed-key secret")
	}
	if got := secretsrotationPostureOf(a); got != string(models.PostureSymmetricOnly) {
		t.Errorf("expected SymmetricOnly posture for AWS-managed-key secret, got %q", got)
	}
	if got := a.Properties["kmsKeyId"]; got != "aws/secretsmanager" {
		t.Errorf("expected kmsKeyId 'aws/secretsmanager' for default-encrypted secret, got %q", got)
	}
	if kmsFake.calls != 0 {
		t.Errorf("expected DescribeKey NOT called when no customer CMK, got %d calls", kmsFake.calls)
	}
}

// TestSecretsRotationCustomerKeySpecRefinesPosture verifies spec mapping through
// kmsSpecPosture: an asymmetric (RSA) customer CMK refines the posture to
// NonPQCClassical (quantum-vulnerable), never staying SymmetricOnly. This is the
// false-safe guard — an asymmetric CMK must not masquerade as quantum-resistant.
func TestSecretsRotationCustomerKeySpecRefinesPosture(t *testing.T) {
	client := &secretsrotationFakeSM{
		pages: []*secretsmanager.ListSecretsOutput{
			{SecretList: []smtypes.SecretListEntry{
				{
					ARN:      secretsrotationStrptr("arn:secret:rsa"),
					KmsKeyId: secretsrotationStrptr("arn:aws:kms:us-east-1:111122223333:key/rsa-cmk"),
				},
			}},
		},
	}
	kmsFake := &secretsrotationFakeKMS{spec: "RSA_2048"}
	assets, err := SecretsRotationScanner{}.scan(context.Background(), client, kmsFake, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	a, ok := secretsrotationAssetByID(assets, "arn:secret:rsa")
	if !ok {
		t.Fatal("expected an asset for the RSA-CMK secret")
	}
	if got := secretsrotationPostureOf(a); got != string(models.PostureNonPQCClassical) {
		t.Errorf("expected NonPQCClassical posture for RSA customer CMK, got %q", got)
	}
	if got := a.Properties["kmsKeySpec"]; got != "RSA_2048" {
		t.Errorf("expected kmsKeySpec 'RSA_2048' recorded, got %q", got)
	}
	if kmsFake.calls != 1 {
		t.Errorf("expected DescribeKey called once for customer CMK, got %d", kmsFake.calls)
	}
}

// TestSecretsRotationDescribeKeyErrorKeepsSymmetricOnly verifies a per-resource
// DescribeKey failure is NOT silently dropped and does NOT abort the scan: the
// secret still surfaces as an asset (the value IS encrypted), keeping the safe
// SymmetricOnly default rather than fabricating a refined posture from a failed
// lookup.
func TestSecretsRotationDescribeKeyErrorKeepsSymmetricOnly(t *testing.T) {
	client := &secretsrotationFakeSM{
		pages: []*secretsmanager.ListSecretsOutput{
			{SecretList: []smtypes.SecretListEntry{
				{
					ARN:      secretsrotationStrptr("arn:secret:denied-cmk"),
					KmsKeyId: secretsrotationStrptr("arn:aws:kms:us-east-1:111122223333:key/denied"),
				},
			}},
		},
	}
	kmsFake := &secretsrotationFakeKMS{err: errors.New("AccessDeniedException: kms:DescribeKey")}
	assets, err := SecretsRotationScanner{}.scan(context.Background(), client, kmsFake, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("a per-resource DescribeKey error must NOT abort the scan, got: %v", err)
	}
	a, ok := secretsrotationAssetByID(assets, "arn:secret:denied-cmk")
	if !ok {
		t.Fatal("expected the secret to still surface as an asset despite DescribeKey failure")
	}
	if got := secretsrotationPostureOf(a); got != string(models.PostureSymmetricOnly) {
		t.Errorf("expected SymmetricOnly retained when DescribeKey fails, got %q", got)
	}
}
