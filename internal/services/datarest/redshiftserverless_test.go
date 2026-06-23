package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/redshiftserverless"
	rsstypes "github.com/aws/aws-sdk-go-v2/service/redshiftserverless/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeRedshiftServerlessClient is a hand-rolled redshiftServerlessAPI for
// unit-testing the scanner's pagination + error propagation without a live AWS
// client. nsPages is returned page-by-page (each call consumes the next page)
// and the NextToken is wired so the scanner loops through every page; listErr
// forces a ListNamespaces failure.
type fakeRedshiftServerlessClient struct {
	nsPages   []*redshiftserverless.ListNamespacesOutput
	listCalls int
	listErr   error
}

func (f *fakeRedshiftServerlessClient) ListNamespaces(ctx context.Context, in *redshiftserverless.ListNamespacesInput, optFns ...func(*redshiftserverless.Options)) (*redshiftserverless.ListNamespacesOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listCalls >= len(f.nsPages) {
		return &redshiftserverless.ListNamespacesOutput{}, nil
	}
	out := f.nsPages[f.listCalls]
	f.listCalls++
	return out, nil
}

// strptr is shared across the datarest package's tests (defined in ebs_test.go).

// TestRedshiftServerlessScanPaginates verifies the ListNamespaces NextToken loop:
// a fake that returns 2 pages (NextToken on page 1) must yield BOTH pages'
// namespaces as assets. Without the pagination loop, only the first page's
// namespace would survive — the commonest real scanner bug.
func TestRedshiftServerlessScanPaginates(t *testing.T) {
	client := &fakeRedshiftServerlessClient{
		nsPages: []*redshiftserverless.ListNamespacesOutput{
			{
				Namespaces: []rsstypes.Namespace{
					{NamespaceName: strptr("ns-page1"), NamespaceArn: strptr("arn:aws:redshift-serverless:us-east-1:111122223333:namespace/ns-page1")},
				},
				NextToken: strptr("tok-page2"),
			},
			{
				Namespaces: []rsstypes.Namespace{
					{NamespaceName: strptr("ns-page2"), NamespaceArn: strptr("arn:aws:redshift-serverless:us-east-1:111122223333:namespace/ns-page2")},
				},
				// no NextToken -> last page
			},
		},
	}
	assets, err := RedshiftServerlessScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.listCalls; c != 2 {
		t.Errorf("expected ListNamespaces to be called 2 times (paginated), got %d", c)
	}
	got := map[string]bool{}
	for _, a := range assets {
		got[a.ResourceID] = true
	}
	for _, want := range []string{
		"arn:aws:redshift-serverless:us-east-1:111122223333:namespace/ns-page1",
		"arn:aws:redshift-serverless:us-east-1:111122223333:namespace/ns-page2",
	} {
		if !got[want] {
			t.Errorf("expected namespace %q from a paginated page to appear as an asset; assets=%v", want, got)
		}
	}
}

// TestRedshiftServerlessScanListErrorPropagates verifies the owner's
// incompleteness decision: a ListNamespaces failure (denied/rate-limited) must
// make the scan VISIBLY incomplete by returning a non-nil error — NOT a silent
// empty success. A top-level List error is the one that, if swallowed, would
// masquerade as a clean all-clear.
func TestRedshiftServerlessScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform redshift-serverless:ListNamespaces")
	client := &fakeRedshiftServerlessClient{listErr: sentinel}
	assets, err := RedshiftServerlessScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListNamespaces fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListNamespaces failure, got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets on top-level List error, got %d", len(assets))
	}
}

// TestRedshiftServerlessPostureAlwaysSymmetricOnly verifies the honesty mapping
// for an ALWAYS-encrypted-at-rest service: Redshift Serverless data is always KMS
// AES-256 with no opt-out, so posture must be SymmetricOnly and MUST NEVER be
// NoEncryption — even when KmsKeyId is absent (which means the AWS-owned default
// key, not the absence of encryption). It also asserts the at-rest cipher is the
// symmetric AES-256 algorithm (quantum-safe), not a quantum-vulnerable primitive.
func TestRedshiftServerlessPostureAlwaysSymmetricOnly(t *testing.T) {
	cases := []struct {
		name       string
		ns         rsstypes.Namespace
		wantKmsKey string
	}{
		{
			name:       "customer CMK present is recorded verbatim",
			ns:         rsstypes.Namespace{NamespaceName: strptr("ns-cmk"), KmsKeyId: strptr("arn:aws:kms:us-east-1:111122223333:key/abc-123")},
			wantKmsKey: "arn:aws:kms:us-east-1:111122223333:key/abc-123",
		},
		{
			name:       "absent KmsKeyId falls back to AWS-owned default key, still encrypted",
			ns:         rsstypes.Namespace{NamespaceName: strptr("ns-default")},
			wantKmsKey: "AWS_OWNED_KMS_KEY",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &fakeRedshiftServerlessClient{
				nsPages: []*redshiftserverless.ListNamespacesOutput{
					{Namespaces: []rsstypes.Namespace{tc.ns}},
				},
			}
			assets, err := RedshiftServerlessScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
			if err != nil {
				t.Fatalf("scan returned unexpected error: %v", err)
			}
			if len(assets) != 1 {
				t.Fatalf("expected exactly 1 asset, got %d", len(assets))
			}
			a := assets[0]

			if a.Properties["posture"] != string(models.PostureSymmetricOnly) {
				t.Errorf("expected posture %q, got %q", models.PostureSymmetricOnly, a.Properties["posture"])
			}
			if a.Properties["posture"] == string(models.PostureNoEncryption) {
				t.Errorf("always-encrypted service must NEVER map to NoEncryption")
			}
			if a.Properties["kmsKeyId"] != tc.wantKmsKey {
				t.Errorf("expected kmsKeyId %q, got %q", tc.wantKmsKey, a.Properties["kmsKeyId"])
			}
			// At-rest cipher must be the symmetric AES-256 algorithm (quantum-safe).
			if a.Properties == nil {
				t.Fatal("expected asset properties to be populated")
			}
			if a.CryptoProps.AlgorithmProperties == nil || a.CryptoProps.AlgorithmProperties.AlgorithmName != "AES-256" {
				t.Errorf("expected AES-256 at-rest algorithm, got %+v", a.CryptoProps.AlgorithmProperties)
			}
		})
	}
}
