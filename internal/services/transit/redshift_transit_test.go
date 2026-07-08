package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	redshifttypes "github.com/aws/aws-sdk-go-v2/service/redshift/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeRedshiftTransitClient is a hand-rolled redshiftTransitAPI for
// unit-testing the scanner's pagination + error propagation + require_ssl
// resolution without a live AWS client. pages is returned page-by-page (each
// call consumes the next page) and the Marker is wired so the scanner loops
// through every page; err forces a DescribeClusters failure on the first call.
// paramsByGroup maps a cluster parameter-group name to its DescribeClusterParameters
// output; paramsErr forces every DescribeClusterParameters call to fail.
type fakeRedshiftTransitClient struct {
	pages         []*redshift.DescribeClustersOutput
	calls         int
	err           error
	paramsByGroup map[string]*redshift.DescribeClusterParametersOutput
	paramsErr     error
	paramsCalls   int
}

func (f *fakeRedshiftTransitClient) DescribeClusters(ctx context.Context, in *redshift.DescribeClustersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClustersOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.calls >= len(f.pages) {
		return &redshift.DescribeClustersOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func (f *fakeRedshiftTransitClient) DescribeClusterParameters(ctx context.Context, in *redshift.DescribeClusterParametersInput, optFns ...func(*redshift.Options)) (*redshift.DescribeClusterParametersOutput, error) {
	f.paramsCalls++
	if f.paramsErr != nil {
		return nil, f.paramsErr
	}
	if in.ParameterGroupName != nil {
		if out, ok := f.paramsByGroup[*in.ParameterGroupName]; ok {
			return out, nil
		}
	}
	return &redshift.DescribeClusterParametersOutput{}, nil
}

func redshifttransitStrptr(s string) *string { return &s }

// redshifttransitCluster builds a cluster attached to the named parameter group.
func redshifttransitCluster(id, groupName string) redshifttypes.Cluster {
	c := redshifttypes.Cluster{ClusterIdentifier: redshifttransitStrptr(id)}
	if groupName != "" {
		c.ClusterParameterGroups = []redshifttypes.ClusterParameterGroupStatus{
			{ParameterGroupName: redshifttransitStrptr(groupName)},
		}
	}
	return c
}

// redshifttransitRequireSSL builds a DescribeClusterParameters page whose
// require_ssl parameter carries the given value.
func redshifttransitRequireSSL(value string) *redshift.DescribeClusterParametersOutput {
	return &redshift.DescribeClusterParametersOutput{
		Parameters: []redshifttypes.Parameter{
			{ParameterName: redshifttransitStrptr("require_ssl"), ParameterValue: redshifttransitStrptr(value)},
		},
	}
}

// redshifttransitAssetByID indexes the returned assets by ResourceID.
func redshifttransitAssetByID(assets []models.CryptoAsset) map[string]models.CryptoAsset {
	m := map[string]models.CryptoAsset{}
	for _, a := range assets {
		m[a.ResourceID] = a
	}
	return m
}

// TestRedshiftTransitScanPaginates verifies the DescribeClusters Marker loop: a
// fake that returns 2 pages (Marker on page 1) must yield BOTH pages' clusters
// as assets. Without the pagination restore, only the first page's cluster
// survives.
func TestRedshiftTransitScanPaginates(t *testing.T) {
	client := &fakeRedshiftTransitClient{
		pages: []*redshift.DescribeClustersOutput{
			{
				Clusters: []redshifttypes.Cluster{{ClusterIdentifier: redshifttransitStrptr("cluster-page1")}},
				Marker:   redshifttransitStrptr("marker-page2"),
			},
			{
				Clusters: []redshifttypes.Cluster{{ClusterIdentifier: redshifttransitStrptr("cluster-page2")}},
				// no Marker -> last page
			},
		},
	}
	resolver := newACMCertResolver(aws.Config{})
	assets, err := RedshiftTransitScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.calls; c != 2 {
		t.Errorf("expected DescribeClusters to be called 2 times (paginated), got %d", c)
	}
	got := redshifttransitAssetByID(assets)
	for _, want := range []string{"cluster-page1", "cluster-page2"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected cluster %q from a paginated page to appear as an asset; got=%v", want, keysOfRedshiftTransit(got))
		}
	}
}

func keysOfRedshiftTransit(m map[string]models.CryptoAsset) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestRedshiftTransitScanErrorPropagates verifies the owner's incompleteness
// decision: a DescribeClusters failure (denied/rate-limited) must make the scan
// VISIBLY incomplete by returning a non-nil error — NOT a silent empty success.
func TestRedshiftTransitScanErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform redshift:DescribeClusters")
	client := &fakeRedshiftTransitClient{err: sentinel}
	resolver := newACMCertResolver(aws.Config{})
	_, err := RedshiftTransitScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeClusters fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeClusters failure, got: %v", err)
	}
}

// TestRedshiftTransitRequireSSLTriState verifies the honesty tri-state derived
// from the require_ssl cluster parameter (which DEFAULTS to false — a default
// Redshift cluster accepts plaintext):
//   - require_ssl=true  -> non-pqc-classical (TLS enforced), observed
//   - require_ssl=false -> legacy-tls + note (TLS offered, plaintext accepted)
//   - unreadable group  -> unknown + note (never a fabricated all-clear)
//
// The scanner must NEVER stamp a definite "always encrypted classical" posture
// without reading require_ssl.
func TestRedshiftTransitRequireSSLTriState(t *testing.T) {
	client := &fakeRedshiftTransitClient{
		pages: []*redshift.DescribeClustersOutput{
			{Clusters: []redshifttypes.Cluster{
				redshifttransitCluster("enforced-cluster", "pg-enforced"),
				redshifttransitCluster("plaintext-cluster", "pg-default"),
			}},
		},
		paramsByGroup: map[string]*redshift.DescribeClusterParametersOutput{
			"pg-enforced": redshifttransitRequireSSL("true"),
			"pg-default":  redshifttransitRequireSSL("false"),
		},
	}
	resolver := newACMCertResolver(aws.Config{})
	assets, err := RedshiftTransitScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	got := redshifttransitAssetByID(assets)

	enf, ok := got["enforced-cluster"]
	if !ok {
		t.Fatalf("expected asset for enforced-cluster; got=%v", keysOfRedshiftTransit(got))
	}
	if p := enf.Properties["posture"]; p != string(models.PostureNonPQCClassical) {
		t.Errorf("require_ssl=true: expected posture %q (enforced classical TLS), got %q", models.PostureNonPQCClassical, p)
	}
	if e := enf.Properties["sslEnforcement"]; e != string(sslEnforced) {
		t.Errorf("require_ssl=true: expected sslEnforcement %q, got %q", sslEnforced, e)
	}

	pl, ok := got["plaintext-cluster"]
	if !ok {
		t.Fatalf("expected asset for plaintext-cluster; got=%v", keysOfRedshiftTransit(got))
	}
	if p := pl.Properties["posture"]; p != string(models.PostureLegacyTLS) {
		t.Errorf("require_ssl=false: expected posture %q (TLS offered but plaintext accepted — NOT a clean classical all-clear), got %q", models.PostureLegacyTLS, p)
	}
	if e := pl.Properties["sslEnforcement"]; e != string(sslNotEnforced) {
		t.Errorf("require_ssl=false: expected sslEnforcement %q, got %q", sslNotEnforced, e)
	}
	if note := pl.Properties["note"]; note == "" {
		t.Error("require_ssl=false: expected an explanatory note naming the unenforced require_ssl parameter, got none")
	}
}

// TestRedshiftTransitUnknownWhenUnreadable verifies the honesty fallback: when
// the cluster parameter group cannot be resolved (no group attached) or
// DescribeClusterParameters fails (denied/throttled), the scanner must emit
// PostureUnknown + a note naming what could not be read — NEVER a fabricated
// non-pqc-classical all-clear. The scanner also must NOT fabricate an observed
// TLS version — the version field stays blank since no Redshift API returns the
// negotiated TLS version.
func TestRedshiftTransitUnknownWhenUnreadable(t *testing.T) {
	t.Run("no parameter group", func(t *testing.T) {
		client := &fakeRedshiftTransitClient{
			pages: []*redshift.DescribeClustersOutput{
				{Clusters: []redshifttypes.Cluster{{ClusterIdentifier: redshifttransitStrptr("groupless-cluster")}}},
			},
		}
		resolver := newACMCertResolver(aws.Config{})
		assets, err := RedshiftTransitScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
		if err != nil {
			t.Fatalf("scan returned unexpected error: %v", err)
		}
		got := redshifttransitAssetByID(assets)
		a, ok := got["groupless-cluster"]
		if !ok {
			t.Fatalf("expected asset for groupless-cluster; got=%v", keysOfRedshiftTransit(got))
		}
		if p := a.Properties["posture"]; p != string(models.PostureUnknown) {
			t.Errorf("unresolvable require_ssl: expected posture %q (not a fabricated classical all-clear), got %q", models.PostureUnknown, p)
		}
		if note := a.Properties["note"]; note == "" {
			t.Error("unresolvable require_ssl: expected a note naming what could not be read, got none")
		}
		if a.ResourceType != "AWS::Redshift::Cluster" {
			t.Errorf("expected resourceType AWS::Redshift::Cluster, got %q", a.ResourceType)
		}
		// No fabricated TLS version: the scanner leaves the version blank because no
		// Redshift API returns the negotiated TLS version.
		if pp := a.CryptoProps.ProtocolProperties; pp != nil && pp.Version != "" {
			t.Errorf("expected blank TLS version (not fabricated), got %q", pp.Version)
		}
	})

	t.Run("DescribeClusterParameters denied", func(t *testing.T) {
		client := &fakeRedshiftTransitClient{
			pages: []*redshift.DescribeClustersOutput{
				{Clusters: []redshifttypes.Cluster{redshifttransitCluster("denied-cluster", "pg-denied")}},
			},
			paramsErr: errors.New("AccessDeniedException: not authorized to perform redshift:DescribeClusterParameters"),
		}
		resolver := newACMCertResolver(aws.Config{})
		assets, err := RedshiftTransitScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
		if err != nil {
			t.Fatalf("scan returned unexpected error: %v", err)
		}
		got := redshifttransitAssetByID(assets)
		a, ok := got["denied-cluster"]
		if !ok {
			t.Fatalf("expected asset for denied-cluster; got=%v", keysOfRedshiftTransit(got))
		}
		if p := a.Properties["posture"]; p != string(models.PostureUnknown) {
			t.Errorf("denied DescribeClusterParameters: expected posture %q, got %q", models.PostureUnknown, p)
		}
		if note := a.Properties["note"]; note == "" {
			t.Error("denied DescribeClusterParameters: expected a note naming what could not be read, got none")
		}
	})
}

// TestRedshiftTransitParamGroupCached verifies that many clusters sharing one
// parameter group cost a single DescribeClusterParameters call (memoised).
func TestRedshiftTransitParamGroupCached(t *testing.T) {
	client := &fakeRedshiftTransitClient{
		pages: []*redshift.DescribeClustersOutput{
			{Clusters: []redshifttypes.Cluster{
				redshifttransitCluster("shared-a", "pg-shared"),
				redshifttransitCluster("shared-b", "pg-shared"),
			}},
		},
		paramsByGroup: map[string]*redshift.DescribeClusterParametersOutput{
			"pg-shared": redshifttransitRequireSSL("true"),
		},
	}
	resolver := newACMCertResolver(aws.Config{})
	assets, err := RedshiftTransitScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.paramsCalls != 1 {
		t.Errorf("expected 1 DescribeClusterParameters call for a shared group (memoised), got %d", client.paramsCalls)
	}
	got := redshifttransitAssetByID(assets)
	for _, id := range []string{"shared-a", "shared-b"} {
		a, ok := got[id]
		if !ok {
			t.Fatalf("expected asset for %s; got=%v", id, keysOfRedshiftTransit(got))
		}
		if p := a.Properties["posture"]; p != string(models.PostureNonPQCClassical) {
			t.Errorf("%s: expected posture %q from the shared enforced group, got %q", id, models.PostureNonPQCClassical, p)
		}
	}
}

// TestRedshiftTransitScanCustomDomainCert verifies that a custom-domain cert ARN
// is recorded and the asset is stamped observed (the only server-cert datum
// Redshift exposes), while a cluster WITHOUT a custom domain carries no
// fabricated cert ARN.
func TestRedshiftTransitScanCustomDomainCert(t *testing.T) {
	client := &fakeRedshiftTransitClient{
		pages: []*redshift.DescribeClustersOutput{
			{Clusters: []redshifttypes.Cluster{
				{
					ClusterIdentifier:          redshifttransitStrptr("custom-domain-cluster"),
					CustomDomainName:           redshifttransitStrptr("redshift.example.com"),
					CustomDomainCertificateArn: redshifttransitStrptr("arn:aws:acm:us-east-1:111122223333:certificate/abc"),
				},
				{ClusterIdentifier: redshifttransitStrptr("no-domain-cluster")},
			}},
		},
	}
	resolver := newACMCertResolver(aws.Config{})
	assets, err := RedshiftTransitScanner{}.scan(context.Background(), client, resolver, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	got := redshifttransitAssetByID(assets)

	cd, ok := got["custom-domain-cluster"]
	if !ok {
		t.Fatalf("expected asset for custom-domain-cluster; got=%v", keysOfRedshiftTransit(got))
	}
	if cd.Properties["customDomainName"] != "redshift.example.com" {
		t.Errorf("expected customDomainName recorded, got %q", cd.Properties["customDomainName"])
	}
	if cd.Properties["customDomainCertificateArn"] != "arn:aws:acm:us-east-1:111122223333:certificate/abc" {
		t.Errorf("expected customDomainCertificateArn recorded, got %q", cd.Properties["customDomainCertificateArn"])
	}

	nd, ok := got["no-domain-cluster"]
	if !ok {
		t.Fatalf("expected asset for no-domain-cluster; got=%v", keysOfRedshiftTransit(got))
	}
	if _, present := nd.Properties["customDomainCertificateArn"]; present {
		t.Errorf("expected NO customDomainCertificateArn for a cluster without a custom domain (no fabrication), got %q", nd.Properties["customDomainCertificateArn"])
	}
}
