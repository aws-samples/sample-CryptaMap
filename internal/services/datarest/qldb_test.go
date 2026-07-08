package datarest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/qldb"
	qldbtypes "github.com/aws/aws-sdk-go-v2/service/qldb/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// qldbCustodyFakeClient is a hand-rolled qldbAPI for unit-testing the scanner's
// pagination, error propagation, and key-custody classification without a live
// AWS client. pages is returned page-by-page; listErr forces a ListLedgers
// failure; descErrByName forces a per-ledger DescribeLedger failure; descByName
// maps a ledger name to its DescribeLedger output.
type qldbCustodyFakeClient struct {
	pages         []*qldb.ListLedgersOutput
	calls         int
	listErr       error
	descByName    map[string]*qldb.DescribeLedgerOutput
	descErrByName map[string]error
}

func (f *qldbCustodyFakeClient) ListLedgers(ctx context.Context, in *qldb.ListLedgersInput, optFns ...func(*qldb.Options)) (*qldb.ListLedgersOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.calls >= len(f.pages) {
		return &qldb.ListLedgersOutput{}, nil
	}
	out := f.pages[f.calls]
	f.calls++
	return out, nil
}

func (f *qldbCustodyFakeClient) DescribeLedger(ctx context.Context, in *qldb.DescribeLedgerInput, optFns ...func(*qldb.Options)) (*qldb.DescribeLedgerOutput, error) {
	name := ""
	if in.Name != nil {
		name = *in.Name
	}
	if err, ok := f.descErrByName[name]; ok {
		return nil, err
	}
	if out, ok := f.descByName[name]; ok {
		return out, nil
	}
	return &qldb.DescribeLedgerOutput{}, nil
}

func qldbStrptr(s string) *string { return &s }

// TestQLDBScanKeyCustodyHonesty verifies the key-custody classification against
// a fake: a ledger whose DescribeLedger returns a customer CMK records it
// verbatim; a ledger with no key info records the AWS-owned default; a ledger
// whose DescribeLedger FAILS must be recorded as kmsKeyId=UNDETERMINED with a
// note — NEVER the fabricated AWS_OWNED_KMS_KEY custody verdict (the ledger may
// use a CMK the scanner simply could not read). Posture stays SymmetricOnly in
// all cases (always-encrypted service), and pagination covers both pages.
func TestQLDBScanKeyCustodyHonesty(t *testing.T) {
	const cmkArn = "arn:aws:kms:us-east-1:111122223333:key/abc-123"
	client := &qldbCustodyFakeClient{
		pages: []*qldb.ListLedgersOutput{
			{
				Ledgers:   []qldbtypes.LedgerSummary{{Name: qldbStrptr("ledger-cmk")}, {Name: qldbStrptr("ledger-default")}},
				NextToken: qldbStrptr("tok-page2"),
			},
			{
				Ledgers: []qldbtypes.LedgerSummary{{Name: qldbStrptr("ledger-denied")}},
			},
		},
		descByName: map[string]*qldb.DescribeLedgerOutput{
			"ledger-cmk": {EncryptionDescription: &qldbtypes.LedgerEncryptionDescription{KmsKeyArn: qldbStrptr(cmkArn)}},
		},
		descErrByName: map[string]error{
			"ledger-denied": errors.New("AccessDeniedException: not authorized to perform qldb:DescribeLedger"),
		},
	}
	assets, err := QLDBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.calls != 2 {
		t.Errorf("expected ListLedgers to be called 2 times (paginated), got %d", client.calls)
	}
	byID := map[string]models.CryptoAsset{}
	for _, a := range assets {
		byID[a.ResourceID] = a
		if got := a.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
			t.Errorf("ledger %q posture = %q, want %q (always-encrypted)", a.ResourceID, got, models.PostureSymmetricOnly)
		}
	}
	if len(assets) != 3 {
		t.Fatalf("expected 3 assets (2 pages), got %d", len(assets))
	}
	if got := byID["ledger-cmk"].Properties["kmsKeyId"]; got != cmkArn {
		t.Errorf("ledger-cmk kmsKeyId = %q, want the observed CMK ARN %q", got, cmkArn)
	}
	if got := byID["ledger-default"].Properties["kmsKeyId"]; got != "AWS_OWNED_KMS_KEY" {
		t.Errorf("ledger-default kmsKeyId = %q, want AWS_OWNED_KMS_KEY", got)
	}
	// The honesty guardrail: a Describe failure must never fabricate the
	// AWS-owned-key custody claim.
	denied := byID["ledger-denied"]
	if got := denied.Properties["kmsKeyId"]; got != "UNDETERMINED" {
		t.Errorf("ledger-denied kmsKeyId = %q, want UNDETERMINED (never a fabricated AWS_OWNED_KMS_KEY)", got)
	}
	if note := denied.Properties["note"]; note == "" {
		t.Error("ledger-denied expected an explanatory note on the unreadable key custody")
	}
}

// TestQLDBScanListErrorPropagates verifies a genuine (non-DNS) ListLedgers
// failure returns a non-nil error — visibly incomplete, not a silent empty
// success.
func TestQLDBScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("ThrottlingException: Rate exceeded")
	client := &qldbCustodyFakeClient{listErr: sentinel}
	assets, err := QLDBScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListLedgers fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListLedgers failure, got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets on a hard list error, got %d", len(assets))
	}
}

// TestIsEndpointUnavailable verifies that QLDB endpoint-resolution / DNS
// failures (no such host) are detected as a graceful-skip signal, while
// genuine errors (throttling, AccessDenied, generic) are NOT — so they still
// surface as hard scanner errors.
func TestIsEndpointUnavailable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		// Endpoint/DNS failures -> skip.
		{"nil", nil, false},
		{"dns-not-found", &net.DNSError{Err: "no such host", Name: "qldb.us-east-1.amazonaws.com", IsNotFound: true}, true},
		{"wrapped-dns", fmt.Errorf("qldb ListLedgers: %w", &net.DNSError{Err: "no such host", IsNotFound: true}), true},
		{"no-such-host-string", errors.New(`Get "https://qldb.us-east-1.amazonaws.com/ledgers": dial tcp: lookup qldb.us-east-1.amazonaws.com: no such host`), true},

		// Transient resolver failures are NOT the retired-endpoint signal: a DNS
		// timeout/temporary blip during a compliance scan must stay a hard error,
		// never a clean-looking empty success.
		{"dns-timeout", &net.DNSError{Err: "i/o timeout", Name: "qldb.us-east-1.amazonaws.com", IsTimeout: true}, false},
		{"dns-temporary", &net.DNSError{Err: "server misbehaving", Name: "qldb.us-east-1.amazonaws.com", IsTemporary: true}, false},

		// Genuine errors -> do NOT skip (must still hard-fail).
		{"access-denied", errors.New("AccessDeniedException: not authorized to perform qldb:ListLedgers"), false},
		{"throttling", errors.New("ThrottlingException: Rate exceeded"), false},
		{"generic", errors.New("some other failure"), false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isEndpointUnavailable(c.err); got != c.want {
				t.Errorf("isEndpointUnavailable(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}
