package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeRDSTransitClient is a hand-rolled rdsTransitAPI for unit-testing the
// scanner's pagination + error propagation + SSL-enforcement classification
// without a live AWS client. instancePages is returned page-by-page (each call
// consumes the next page) with Markers wired so the scanner loops through every
// page; paramsByGroup maps a parameter-group name to the parameters returned for
// it. The *Err fields force the respective API call to fail.
type fakeRDSTransitClient struct {
	instancePages []*rds.DescribeDBInstancesOutput
	instanceCalls int
	instancesErr  error

	paramsByGroup map[string][]rdstypes.Parameter
	paramCalls    int
	paramsErr     error
}

func (f *fakeRDSTransitClient) DescribeDBInstances(ctx context.Context, in *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	if f.instancesErr != nil {
		return nil, f.instancesErr
	}
	if f.instanceCalls >= len(f.instancePages) {
		return &rds.DescribeDBInstancesOutput{}, nil
	}
	out := f.instancePages[f.instanceCalls]
	f.instanceCalls++
	return out, nil
}

func (f *fakeRDSTransitClient) DescribeDBParameters(ctx context.Context, in *rds.DescribeDBParametersInput, optFns ...func(*rds.Options)) (*rds.DescribeDBParametersOutput, error) {
	f.paramCalls++
	if f.paramsErr != nil {
		return nil, f.paramsErr
	}
	name := ""
	if in.DBParameterGroupName != nil {
		name = *in.DBParameterGroupName
	}
	return &rds.DescribeDBParametersOutput{Parameters: f.paramsByGroup[name]}, nil
}

func rdstransitStrptr(s string) *string { return &s }

// rdstransitAssetByID returns the asset with the given ResourceID, or nil.
func rdstransitAssetByID(assets []models.CryptoAsset, id string) *models.CryptoAsset {
	for i := range assets {
		if assets[i].ResourceID == id {
			return &assets[i]
		}
	}
	return nil
}

// rdstransitPostureOf returns the posture property of an asset (empty if absent).
func rdstransitPostureOf(a *models.CryptoAsset) string {
	if a == nil || a.Properties == nil {
		return ""
	}
	return a.Properties["posture"]
}

// rdstransitParamGroup builds a DBParameterGroupStatus referencing a named group.
func rdstransitParamGroup(name string) rdstypes.DBParameterGroupStatus {
	return rdstypes.DBParameterGroupStatus{DBParameterGroupName: rdstransitStrptr(name)}
}

// rdstransitForceSSLParam builds the rds.force_ssl parameter with a given value.
func rdstransitForceSSLParam(val string) rdstypes.Parameter {
	return rdstypes.Parameter{
		ParameterName:  rdstransitStrptr("rds.force_ssl"),
		ParameterValue: rdstransitStrptr(val),
	}
}

// TestRDSTransitScanPaginatesInstances verifies the DescribeDBInstances Marker
// loop: a fake that returns 2 pages (Marker on page 1) must yield BOTH pages'
// instances as assets. Without the pagination restore only the first page's
// instance survives.
func TestRDSTransitScanPaginatesInstances(t *testing.T) {
	client := &fakeRDSTransitClient{
		instancePages: []*rds.DescribeDBInstancesOutput{
			{
				DBInstances: []rdstypes.DBInstance{{DBInstanceIdentifier: rdstransitStrptr("db-page1")}},
				Marker:      rdstransitStrptr("marker-page2"),
			},
			{
				DBInstances: []rdstypes.DBInstance{{DBInstanceIdentifier: rdstransitStrptr("db-page2")}},
				// no Marker -> last page
			},
		},
	}
	assets, err := RDSTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.instanceCalls != 2 {
		t.Errorf("expected DescribeDBInstances to be called 2 times (paginated), got %d", client.instanceCalls)
	}
	for _, want := range []string{"db-page1", "db-page2"} {
		if rdstransitAssetByID(assets, want) == nil {
			t.Errorf("expected instance %q from a paginated page to appear as an asset", want)
		}
	}
}

// TestRDSTransitScanInstancesErrorPropagates verifies the incompleteness
// contract: a DescribeDBInstances failure (denied/throttled) must make the scan
// VISIBLY incomplete by returning a non-nil error — NOT a silent empty success.
func TestRDSTransitScanInstancesErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform rds:DescribeDBInstances")
	client := &fakeRDSTransitClient{instancesErr: sentinel}
	_, err := RDSTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when DescribeDBInstances fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the DescribeDBInstances failure, got: %v", err)
	}
}

// TestRDSTransitScanEnforcedPosture verifies the honesty posture for an instance
// whose parameter group sets rds.force_ssl=1: plaintext is refused, so the
// asset is non-pqc-classical (a clean classical-TLS posture is legitimate ONLY
// when TLS is actually ENFORCED).
func TestRDSTransitScanEnforcedPosture(t *testing.T) {
	client := &fakeRDSTransitClient{
		instancePages: []*rds.DescribeDBInstancesOutput{
			{DBInstances: []rdstypes.DBInstance{{
				DBInstanceIdentifier: rdstransitStrptr("db-enforced"),
				DBParameterGroups:    []rdstypes.DBParameterGroupStatus{rdstransitParamGroup("pg-enforced")},
			}}},
		},
		paramsByGroup: map[string][]rdstypes.Parameter{
			"pg-enforced": {rdstransitForceSSLParam("1")},
		},
	}
	assets, err := RDSTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a := rdstransitAssetByID(assets, "db-enforced")
	if a == nil {
		t.Fatal("expected an asset for db-enforced")
	}
	if got := rdstransitPostureOf(a); got != string(models.PostureNonPQCClassical) {
		t.Errorf("enforced TLS instance: expected posture %q, got %q", models.PostureNonPQCClassical, got)
	}
	if a.Properties["sslEnforcement"] != string(sslEnforced) {
		t.Errorf("expected sslEnforcement=%q, got %q", sslEnforced, a.Properties["sslEnforcement"])
	}
}

// TestRDSTransitScanNotEnforcedNotClean verifies the central honesty rule: an
// instance that OFFERS TLS but does not enforce it (rds.force_ssl=0) accepts
// plaintext and MUST NOT be reported as a clean classical-TLS all-clear. It is
// downgraded to legacy-tls and carries a note.
func TestRDSTransitScanNotEnforcedNotClean(t *testing.T) {
	client := &fakeRDSTransitClient{
		instancePages: []*rds.DescribeDBInstancesOutput{
			{DBInstances: []rdstypes.DBInstance{{
				DBInstanceIdentifier: rdstransitStrptr("db-plaintext"),
				DBParameterGroups:    []rdstypes.DBParameterGroupStatus{rdstransitParamGroup("pg-off")},
			}}},
		},
		paramsByGroup: map[string][]rdstypes.Parameter{
			"pg-off": {rdstransitForceSSLParam("0")},
		},
	}
	assets, err := RDSTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a := rdstransitAssetByID(assets, "db-plaintext")
	if a == nil {
		t.Fatal("expected an asset for db-plaintext")
	}
	if got := rdstransitPostureOf(a); got == string(models.PostureNonPQCClassical) {
		t.Errorf("plaintext-accepting instance must NOT be a clean classical-TLS all-clear; got posture %q", got)
	}
	if got := rdstransitPostureOf(a); got != string(models.PostureLegacyTLS) {
		t.Errorf("not-enforced TLS instance: expected posture %q, got %q", models.PostureLegacyTLS, got)
	}
	if a.Properties["note"] == "" {
		t.Error("expected a note explaining that TLS is offered but not enforced")
	}
}

// TestRDSTransitScanUnknownWhenUnresolvable verifies that when enforcement
// cannot be determined (no parameter group resolvable), the posture is Unknown
// — never a fabricated all-clear nor a false alarm. A DescribeDBParameters
// failure is similarly non-fatal but yields Unknown (no silent clean success).
func TestRDSTransitScanUnknownWhenUnresolvable(t *testing.T) {
	t.Run("no-parameter-group", func(t *testing.T) {
		client := &fakeRDSTransitClient{
			instancePages: []*rds.DescribeDBInstancesOutput{
				{DBInstances: []rdstypes.DBInstance{{
					DBInstanceIdentifier: rdstransitStrptr("db-nogroup"),
					// no DBParameterGroups
				}}},
			},
		}
		assets, err := RDSTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		if err != nil {
			t.Fatalf("scan returned unexpected error: %v", err)
		}
		a := rdstransitAssetByID(assets, "db-nogroup")
		if a == nil {
			t.Fatal("expected an asset for db-nogroup")
		}
		if got := rdstransitPostureOf(a); got != string(models.PostureUnknown) {
			t.Errorf("unresolvable enforcement: expected posture %q, got %q", models.PostureUnknown, got)
		}
	})

	t.Run("describe-parameters-error", func(t *testing.T) {
		client := &fakeRDSTransitClient{
			instancePages: []*rds.DescribeDBInstancesOutput{
				{DBInstances: []rdstypes.DBInstance{{
					DBInstanceIdentifier: rdstransitStrptr("db-paramerr"),
					DBParameterGroups:    []rdstypes.DBParameterGroupStatus{rdstransitParamGroup("pg-err")},
				}}},
			},
			paramsErr: errors.New("AccessDeniedException: rds:DescribeDBParameters"),
		}
		assets, err := RDSTransitScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
		if err != nil {
			t.Fatalf("scan returned unexpected error (per-group param errors are non-fatal): %v", err)
		}
		a := rdstransitAssetByID(assets, "db-paramerr")
		if a == nil {
			t.Fatal("expected an asset for db-paramerr (instance must not be silently dropped on a param-read failure)")
		}
		if got := rdstransitPostureOf(a); got != string(models.PostureUnknown) {
			t.Errorf("param-read failure: expected posture %q (not a fabricated all-clear), got %q", models.PostureUnknown, got)
		}
	})
}

// TestRDSTransitScanParameterGroupCacheReused verifies that many instances
// sharing one parameter group cost a single DescribeDBParameters call (the
// pgCache memoisation), which both saves API calls and keeps results
// consistent.
func TestRDSTransitScanParameterGroupCacheReused(t *testing.T) {
	client := &fakeRDSTransitClient{
		instancePages: []*rds.DescribeDBInstancesOutput{
			{DBInstances: []rdstypes.DBInstance{
				{
					DBInstanceIdentifier: rdstransitStrptr("db-a"),
					DBParameterGroups:    []rdstypes.DBParameterGroupStatus{rdstransitParamGroup("pg-shared")},
				},
				{
					DBInstanceIdentifier: rdstransitStrptr("db-b"),
					DBParameterGroups:    []rdstypes.DBParameterGroupStatus{rdstransitParamGroup("pg-shared")},
				},
			}},
		},
		paramsByGroup: map[string][]rdstypes.Parameter{
			"pg-shared": {rdstransitForceSSLParam("1")},
		},
	}
	if _, err := (RDSTransitScanner{}).scan(context.Background(), client, "111122223333", "us-east-1"); err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.paramCalls != 1 {
		t.Errorf("expected DescribeDBParameters to be called once for a shared parameter group (cache), got %d", client.paramCalls)
	}
}
