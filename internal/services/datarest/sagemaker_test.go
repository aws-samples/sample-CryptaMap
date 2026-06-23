package datarest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	smtypes "github.com/aws/aws-sdk-go-v2/service/sagemaker/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeSageMakerClient is a hand-rolled sageMakerAPI for unit-testing the scanner's
// pagination + error propagation + key-tier classification without a live AWS
// client. listPages is returned page-by-page (each ListDomains call consumes the
// next page) with NextToken wired so the scanner loops through every page; listErr
// forces a top-level ListDomains failure. describeByID returns a canned
// DescribeDomain output per domain id, and describeErrByID forces a per-domain
// DescribeDomain failure.
type fakeSageMakerClient struct {
	listPages       []*sagemaker.ListDomainsOutput
	listCalls       int
	listErr         error
	describeByID    map[string]*sagemaker.DescribeDomainOutput
	describeErrByID map[string]error
}

func (f *fakeSageMakerClient) ListDomains(ctx context.Context, in *sagemaker.ListDomainsInput, optFns ...func(*sagemaker.Options)) (*sagemaker.ListDomainsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listCalls >= len(f.listPages) {
		return &sagemaker.ListDomainsOutput{}, nil
	}
	out := f.listPages[f.listCalls]
	f.listCalls++
	return out, nil
}

func (f *fakeSageMakerClient) DescribeDomain(ctx context.Context, in *sagemaker.DescribeDomainInput, optFns ...func(*sagemaker.Options)) (*sagemaker.DescribeDomainOutput, error) {
	id := ""
	if in.DomainId != nil {
		id = *in.DomainId
	}
	if err, ok := f.describeErrByID[id]; ok {
		return nil, err
	}
	if out, ok := f.describeByID[id]; ok {
		return out, nil
	}
	return &sagemaker.DescribeDomainOutput{}, nil
}

func smSP(s string) *string { return &s }

// smIndexByResourceID maps every emitted asset by its ResourceID for assertion.
func smIndexByResourceID(assets []models.CryptoAsset) map[string]models.CryptoAsset {
	m := map[string]models.CryptoAsset{}
	for _, a := range assets {
		m[a.ResourceID] = a
	}
	return m
}

func smKeys(m map[string]models.CryptoAsset) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestSageMakerScanPaginates verifies the ListDomains NextToken loop: a fake that
// returns 2 pages (NextToken on page 1) must yield BOTH pages' domains as assets.
// Without the pagination loop, only the first page's domain survives — the single
// commonest real scanner bug.
func TestSageMakerScanPaginates(t *testing.T) {
	client := &fakeSageMakerClient{
		listPages: []*sagemaker.ListDomainsOutput{
			{
				Domains:   []smtypes.DomainDetails{{DomainId: smSP("d-page1")}},
				NextToken: smSP("tok-page2"),
			},
			{
				Domains: []smtypes.DomainDetails{{DomainId: smSP("d-page2")}},
				// no NextToken -> last page
			},
		},
		describeByID: map[string]*sagemaker.DescribeDomainOutput{
			"d-page1": {},
			"d-page2": {},
		},
	}
	assets, err := SageMakerScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.listCalls != 2 {
		t.Errorf("expected ListDomains to be called 2 times (paginated), got %d", client.listCalls)
	}
	got := smIndexByResourceID(assets)
	for _, want := range []string{"d-page1", "d-page2"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected domain %q from a paginated page to appear as an asset; got %v", want, smKeys(got))
		}
	}
}

// TestSageMakerScanListErrorPropagates verifies that a top-level ListDomains failure
// (denied/rate-limited) makes the scan VISIBLY incomplete by returning a non-nil
// error wrapping the cause — NOT a silent empty success.
func TestSageMakerScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform sagemaker:ListDomains")
	client := &fakeSageMakerClient{listErr: sentinel}
	_, err := SageMakerScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListDomains fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListDomains failure, got: %v", err)
	}
}

// TestSageMakerScanDescribeErrorNotDropped verifies the HONESTY CONTRACT for a
// per-domain DescribeDomain failure: the domain is known to exist (it came back
// from ListDomains) so it must NOT be silently dropped, and must NOT be emitted as
// a clean AWS-owned-key SymmetricOnly default (a false-safe). It must surface as a
// PostureUnknown asset carrying an explanatory note. (This guards the pre-fix
// behavior, which `continue`d on DescribeDomain error and dropped the domain.)
func TestSageMakerScanDescribeErrorNotDropped(t *testing.T) {
	client := &fakeSageMakerClient{
		listPages: []*sagemaker.ListDomainsOutput{
			{Domains: []smtypes.DomainDetails{{DomainId: smSP("d-denied")}}},
		},
		describeErrByID: map[string]error{
			"d-denied": errors.New("AccessDeniedException: not authorized to perform sagemaker:DescribeDomain"),
		},
	}
	assets, err := SageMakerScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	got := smIndexByResourceID(assets)
	a, ok := got["d-denied"]
	if !ok {
		t.Fatalf("domain with a failed DescribeDomain was silently dropped; assets=%v", smKeys(got))
	}
	if a.Properties["posture"] != string(models.PostureUnknown) {
		t.Errorf("posture for un-describable domain = %q, want %q (must not be a clean SymmetricOnly false-safe)", a.Properties["posture"], models.PostureUnknown)
	}
	if note := a.Properties["note"]; !strings.Contains(strings.ToLower(note), "undetermined") {
		t.Errorf("un-describable domain must carry an undetermined-custody note; got note=%q", note)
	}
	// It must NOT be presented as a clean AWS-owned-key default.
	if a.Properties["kmsKeyId"] == "AWS_OWNED_KMS_KEY" {
		t.Errorf("un-describable domain must not be stamped with the clean AWS_OWNED_KMS_KEY default (false-safe)")
	}
}

// TestSageMakerScanKeyTierClassification verifies the at-rest posture/key-tier
// HONESTY mapping. A SageMaker Domain's EFS volume is always encrypted at rest with
// AES (no off switch), so posture is unconditionally SymmetricOnly — NEVER
// NoEncryption — and only the KEY TIER varies:
//   - DescribeDomain.KmsKeyId set    -> that CMK is recorded verbatim;
//   - DescribeDomain.KmsKeyId absent  -> AWS-owned key default sentinel, still
//     encrypted (recorded, not a no-encryption finding).
func TestSageMakerScanKeyTierClassification(t *testing.T) {
	cmkARN := "arn:aws:kms:us-east-1:111122223333:key/abcd1234-ab12-cd34-ef56-abcdef123456"
	client := &fakeSageMakerClient{
		listPages: []*sagemaker.ListDomainsOutput{
			{Domains: []smtypes.DomainDetails{
				{DomainId: smSP("d-cmk")},
				{DomainId: smSP("d-owned")},
			}},
		},
		describeByID: map[string]*sagemaker.DescribeDomainOutput{
			"d-cmk": {KmsKeyId: &cmkARN},
			// AWS-owned key: no KmsKeyId -> default sentinel, still encrypted.
			"d-owned": {},
		},
	}
	assets, err := SageMakerScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	got := smIndexByResourceID(assets)

	cmk, ok := got["d-cmk"]
	if !ok {
		t.Fatalf("CMK domain missing from assets; got %v", smKeys(got))
	}
	if cmk.Properties["posture"] != string(models.PostureSymmetricOnly) {
		t.Errorf("CMK domain posture = %q, want %q (SageMaker EFS is always AES at rest)", cmk.Properties["posture"], models.PostureSymmetricOnly)
	}
	if cmk.Properties["kmsKeyId"] != cmkARN {
		t.Errorf("CMK domain kmsKeyId = %q, want the CMK ARN %q", cmk.Properties["kmsKeyId"], cmkARN)
	}

	owned, ok := got["d-owned"]
	if !ok {
		t.Fatalf("AWS-owned-key domain missing from assets; got %v", smKeys(got))
	}
	if owned.Properties["posture"] != string(models.PostureSymmetricOnly) {
		t.Errorf("AWS-owned domain posture = %q, want %q — absent KmsKeyId is the AWS-owned key, NOT no-encryption", owned.Properties["posture"], models.PostureSymmetricOnly)
	}
	if owned.Properties["posture"] == string(models.PostureNoEncryption) {
		t.Errorf("AWS-owned domain must never be classified as no-encryption (SageMaker EFS has no at-rest off switch)")
	}
	if owned.Properties["kmsKeyId"] != "AWS_OWNED_KMS_KEY" {
		t.Errorf("AWS-owned domain kmsKeyId = %q, want the AWS_OWNED_KMS_KEY default sentinel (still encrypted)", owned.Properties["kmsKeyId"])
	}
}
