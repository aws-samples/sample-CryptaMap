package transit

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/transfer"
	transfertypes "github.com/aws/aws-sdk-go-v2/service/transfer/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeTransferClient is a hand-rolled transferAPI for unit-testing the scanner's
// pagination + error propagation without a live AWS client. listPages is returned
// page-by-page (each ListServers call consumes the next page) with NextToken wired
// so the scanner loops through every page; listErr forces a ListServers failure.
// describeServers / describePolicies map a key (ServerId / policy name) to the
// canned output, and the *Err fields force a per-server failure to exercise the
// non-fatal fallback path.
type fakeTransferClient struct {
	listPages []*transfer.ListServersOutput
	listCalls int
	listErr   error

	describeServers map[string]*transfer.DescribeServerOutput
	describeSrvErr  error

	describePolicies map[string]*transfer.DescribeSecurityPolicyOutput
	describePolErr   error

	describePolicyCalls int
}

func (f *fakeTransferClient) ListServers(ctx context.Context, in *transfer.ListServersInput, optFns ...func(*transfer.Options)) (*transfer.ListServersOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listCalls >= len(f.listPages) {
		return &transfer.ListServersOutput{}, nil
	}
	out := f.listPages[f.listCalls]
	f.listCalls++
	return out, nil
}

func (f *fakeTransferClient) DescribeServer(ctx context.Context, in *transfer.DescribeServerInput, optFns ...func(*transfer.Options)) (*transfer.DescribeServerOutput, error) {
	if f.describeSrvErr != nil {
		return nil, f.describeSrvErr
	}
	if in.ServerId != nil {
		if out, ok := f.describeServers[*in.ServerId]; ok {
			return out, nil
		}
	}
	return &transfer.DescribeServerOutput{}, nil
}

func (f *fakeTransferClient) DescribeSecurityPolicy(ctx context.Context, in *transfer.DescribeSecurityPolicyInput, optFns ...func(*transfer.Options)) (*transfer.DescribeSecurityPolicyOutput, error) {
	f.describePolicyCalls++
	if f.describePolErr != nil {
		return nil, f.describePolErr
	}
	if in.SecurityPolicyName != nil {
		if out, ok := f.describePolicies[*in.SecurityPolicyName]; ok {
			return out, nil
		}
	}
	return &transfer.DescribeSecurityPolicyOutput{}, nil
}

func transferfamilyStrptr(s string) *string { return &s }

func transferfamilyBoolptr(b bool) *bool { return &b }

// transferfamilyServerWithPolicy builds a DescribeServerOutput whose security
// policy name is the given string.
func transferfamilyServerWithPolicy(serverID, policy string) *transfer.DescribeServerOutput {
	return &transfer.DescribeServerOutput{
		Server: &transfertypes.DescribedServer{
			ServerId:           transferfamilyStrptr(serverID),
			SecurityPolicyName: transferfamilyStrptr(policy),
		},
	}
}

// transferfamilyAssetByID returns the first asset with the given ResourceID.
func transferfamilyAssetByID(assets []models.CryptoAsset, id string) (models.CryptoAsset, bool) {
	for _, a := range assets {
		if a.ResourceID == id {
			return a, true
		}
	}
	return models.CryptoAsset{}, false
}

// transferfamilyPostureOf returns the posture property stamped on an asset.
func transferfamilyPostureOf(a models.CryptoAsset) string {
	return a.Properties["posture"]
}

// TestTransferFamilyScanPaginatesServers verifies the ListServers NextToken loop:
// a fake that returns 2 pages (NextToken on page 1) must yield BOTH pages' servers
// as assets. Without the pagination restore, only the first page survives.
func TestTransferFamilyScanPaginatesServers(t *testing.T) {
	client := &fakeTransferClient{
		listPages: []*transfer.ListServersOutput{
			{
				Servers:   []transfertypes.ListedServer{{ServerId: transferfamilyStrptr("s-page1")}},
				NextToken: transferfamilyStrptr("tok-page2"),
			},
			{
				Servers: []transfertypes.ListedServer{{ServerId: transferfamilyStrptr("s-page2")}},
				// no NextToken -> last page
			},
		},
	}
	assets, err := TransferFamilyScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.listCalls; c != 2 {
		t.Errorf("expected ListServers to be called 2 times (paginated), got %d", c)
	}
	for _, want := range []string{"s-page1", "s-page2"} {
		if _, ok := transferfamilyAssetByID(assets, want); !ok {
			t.Errorf("expected server %q from a paginated page to appear as an asset; assets=%+v", want, assets)
		}
	}
}

// TestTransferFamilyScanListErrorPropagates verifies the incompleteness contract:
// a ListServers failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success.
func TestTransferFamilyScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform transfer:ListServers")
	client := &fakeTransferClient{listErr: sentinel}
	_, err := TransferFamilyScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListServers fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListServers failure, got: %v", err)
	}
}

// TestTransferFamilyScanPerServerErrorNotDropped verifies that a per-server
// DescribeServer failure does NOT silently drop the server: the server still
// appears as an asset, but with the honest Unknown posture (we could not place
// its policy) rather than a false-safe classical default.
func TestTransferFamilyScanPerServerErrorNotDropped(t *testing.T) {
	client := &fakeTransferClient{
		listPages: []*transfer.ListServersOutput{
			{Servers: []transfertypes.ListedServer{{ServerId: transferfamilyStrptr("s-denied")}}},
		},
		describeSrvErr: errors.New("AccessDeniedException: transfer:DescribeServer"),
	}
	assets, err := TransferFamilyScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := transferfamilyAssetByID(assets, "s-denied")
	if !ok {
		t.Fatalf("server with a DescribeServer error was silently dropped; assets=%+v", assets)
	}
	if got := transferfamilyPostureOf(a); got != string(models.PostureUnknown) {
		t.Errorf("expected Unknown posture for an unreadable server (honest, not false-safe classical), got %q", got)
	}
}

// TestTransferFamilyScanKexDrivenPQC verifies the authoritative KEX-based posture:
// a 2025 policy whose SshKexs contain an ML-KEM hybrid group must classify as
// PQCHybrid (observed, not guessed from the name).
func TestTransferFamilyScanKexDrivenPQC(t *testing.T) {
	const policy = "TransferSecurityPolicy-2025-03"
	client := &fakeTransferClient{
		listPages: []*transfer.ListServersOutput{
			{Servers: []transfertypes.ListedServer{{ServerId: transferfamilyStrptr("s-pq")}}},
		},
		describeServers: map[string]*transfer.DescribeServerOutput{
			"s-pq": transferfamilyServerWithPolicy("s-pq", policy),
		},
		describePolicies: map[string]*transfer.DescribeSecurityPolicyOutput{
			policy: {
				SecurityPolicy: &transfertypes.DescribedSecurityPolicy{
					SecurityPolicyName: transferfamilyStrptr(policy),
					SshKexs:            []string{"mlkem768x25519-sha256", "ecdh-sha2-nistp256"},
					SshCiphers:         []string{"aes256-gcm@openssh.com"},
					Fips:               transferfamilyBoolptr(false),
				},
			},
		},
	}
	assets, err := TransferFamilyScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := transferfamilyAssetByID(assets, "s-pq")
	if !ok {
		t.Fatalf("expected server s-pq as an asset; assets=%+v", assets)
	}
	if got := transferfamilyPostureOf(a); got != string(models.PosturePQCHybrid) {
		t.Errorf("expected PQCHybrid posture from an ML-KEM KEX list, got %q", got)
	}
	if a.Properties["securityPolicy"] != policy {
		t.Errorf("expected securityPolicy property %q, got %q", policy, a.Properties["securityPolicy"])
	}
	if a.Properties["fips"] != "false" {
		t.Errorf("expected fips property %q, got %q", "false", a.Properties["fips"])
	}
}

// TestTransferFamilyScanClassicalPolicy verifies the honesty posture for the
// classical case: a recognized older dated policy whose KEX list has NO ML-KEM
// group must classify as NonPQCClassical — never as no-encryption (SSH/TLS is
// always encrypted, the only question is whether it is post-quantum).
func TestTransferFamilyScanClassicalPolicy(t *testing.T) {
	const policy = "TransferSecurityPolicy-2023-05"
	client := &fakeTransferClient{
		listPages: []*transfer.ListServersOutput{
			{Servers: []transfertypes.ListedServer{{ServerId: transferfamilyStrptr("s-classical")}}},
		},
		describeServers: map[string]*transfer.DescribeServerOutput{
			"s-classical": transferfamilyServerWithPolicy("s-classical", policy),
		},
		describePolicies: map[string]*transfer.DescribeSecurityPolicyOutput{
			policy: {
				SecurityPolicy: &transfertypes.DescribedSecurityPolicy{
					SecurityPolicyName: transferfamilyStrptr(policy),
					SshKexs:            []string{"ecdh-sha2-nistp384", "diffie-hellman-group14-sha256"},
				},
			},
		},
	}
	assets, err := TransferFamilyScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := transferfamilyAssetByID(assets, "s-classical")
	if !ok {
		t.Fatalf("expected server s-classical as an asset; assets=%+v", assets)
	}
	got := transferfamilyPostureOf(a)
	if got != string(models.PostureNonPQCClassical) {
		t.Errorf("expected NonPQCClassical posture from a classical KEX list, got %q", got)
	}
	if got == string(models.PostureNoEncryption) {
		t.Errorf("SSH transport must never be reported as no-encryption, got %q", got)
	}
}

// TestTransferFamilyScanPolicyNameFallbackUnknown verifies the false-safe fix:
// when DescribeSecurityPolicy fails (e.g. AccessDenied) AND the policy name is not
// a recognized dated/PQ name, the verdict is Unknown — NOT a guessed classical
// default that could mislabel a current PQ policy whose details we cannot read.
func TestTransferFamilyScanPolicyNameFallbackUnknown(t *testing.T) {
	const policy = "SomeUnrecognizedPolicyName"
	client := &fakeTransferClient{
		listPages: []*transfer.ListServersOutput{
			{Servers: []transfertypes.ListedServer{{ServerId: transferfamilyStrptr("s-fallback")}}},
		},
		describeServers: map[string]*transfer.DescribeServerOutput{
			"s-fallback": transferfamilyServerWithPolicy("s-fallback", policy),
		},
		// DescribeSecurityPolicy denied -> the authoritative KEX path cannot run,
		// so the scanner falls back to the policy-name-only classification.
		describePolErr: errors.New("AccessDeniedException: transfer:DescribeSecurityPolicy"),
	}
	assets, err := TransferFamilyScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a, ok := transferfamilyAssetByID(assets, "s-fallback")
	if !ok {
		t.Fatalf("expected server s-fallback as an asset; assets=%+v", assets)
	}
	if got := transferfamilyPostureOf(a); got != string(models.PostureUnknown) {
		t.Errorf("expected Unknown posture for an unplaceable policy name (no false-safe classical default), got %q", got)
	}
	if client.describePolicyCalls == 0 {
		t.Error("expected DescribeSecurityPolicy to be attempted for a server with a named policy")
	}
}
