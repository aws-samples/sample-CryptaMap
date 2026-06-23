package keymgmt

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/paymentcryptography"
	pctypes "github.com/aws/aws-sdk-go-v2/service/paymentcryptography/types"
	"github.com/aws/smithy-go"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// paymentsFakeClient is a hand-rolled paymentCryptographyAPI for unit-testing the
// scanner's pagination + error propagation + per-key classification without a
// live AWS client. listPages is returned page-by-page (each ListKeys call
// consumes the next page) with the NextToken wired so the scanner loops through
// every page; listErr forces a ListKeys failure; getKeys maps a KeyArn to a
// GetKey response and getErr (if set) forces every GetKey to fail.
type paymentsFakeClient struct {
	listPages []*paymentcryptography.ListKeysOutput
	listCalls int
	listErr   error

	getKeys map[string]*paymentcryptography.GetKeyOutput
	getErr  error
}

func (f *paymentsFakeClient) ListKeys(ctx context.Context, in *paymentcryptography.ListKeysInput, optFns ...func(*paymentcryptography.Options)) (*paymentcryptography.ListKeysOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listCalls >= len(f.listPages) {
		return &paymentcryptography.ListKeysOutput{}, nil
	}
	out := f.listPages[f.listCalls]
	f.listCalls++
	return out, nil
}

func (f *paymentsFakeClient) GetKey(ctx context.Context, in *paymentcryptography.GetKeyInput, optFns ...func(*paymentcryptography.Options)) (*paymentcryptography.GetKeyOutput, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	if in.KeyIdentifier != nil {
		if out, ok := f.getKeys[*in.KeyIdentifier]; ok {
			return out, nil
		}
	}
	return &paymentcryptography.GetKeyOutput{}, nil
}

// paymentsAPIErr is a smithy.APIError implementation so the test can drive the
// service-unavailable-in-region skip path (which inspects ErrorCode).
type paymentsAPIErr struct{ code string }

func (e paymentsAPIErr) Error() string        { return e.code + ": synthetic" }
func (e paymentsAPIErr) ErrorCode() string    { return e.code }
func (e paymentsAPIErr) ErrorMessage() string { return "synthetic" }
func (e paymentsAPIErr) ErrorFault() smithy.ErrorFault {
	return smithy.FaultClient
}

func paymentsStrptr(s string) *string { return &s }
func paymentsBoolptr(b bool) *bool    { return &b }

// paymentsKeySummary builds a ListKeys KeySummary with inline KeyAttributes.
func paymentsKeySummary(arn string, algo pctypes.KeyAlgorithm, class pctypes.KeyClass) pctypes.KeySummary {
	return pctypes.KeySummary{
		KeyArn:   paymentsStrptr(arn),
		Enabled:  paymentsBoolptr(true),
		KeyState: pctypes.KeyStateCreateComplete,
		KeyAttributes: &pctypes.KeyAttributes{
			KeyAlgorithm: algo,
			KeyClass:     class,
		},
	}
}

// paymentsAssetByID indexes scan output by ResourceID for assertions.
func paymentsAssetByID(assets []models.CryptoAsset) map[string]models.CryptoAsset {
	m := map[string]models.CryptoAsset{}
	for _, a := range assets {
		m[a.ResourceID] = a
	}
	return m
}

// paymentsPostureOf returns the posture property string for an asset.
func paymentsPostureOf(a models.CryptoAsset) string {
	return a.Properties["posture"]
}

// TestPaymentsScanPaginatesKeys verifies the ListKeys NextToken loop: a fake that
// returns 2 pages (NextToken on page 1) must yield BOTH pages' keys as assets.
// Without the pagination loop, only the first page's key would survive.
func TestPaymentsScanPaginatesKeys(t *testing.T) {
	client := &paymentsFakeClient{
		listPages: []*paymentcryptography.ListKeysOutput{
			{
				Keys:      []pctypes.KeySummary{paymentsKeySummary("arn:key-page1", pctypes.KeyAlgorithmAes256, pctypes.KeyClassSymmetricKey)},
				NextToken: paymentsStrptr("tok-page2"),
			},
			{
				Keys: []pctypes.KeySummary{paymentsKeySummary("arn:key-page2", pctypes.KeyAlgorithmRsa2048, pctypes.KeyClassAsymmetricKeyPair)},
				// no NextToken -> last page
			},
		},
	}
	assets, err := PaymentCryptographyScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.listCalls != 2 {
		t.Errorf("expected ListKeys to be called 2 times (paginated), got %d", client.listCalls)
	}
	got := paymentsAssetByID(assets)
	for _, want := range []string{"arn:key-page1", "arn:key-page2"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected key %q from a paginated page to appear as an asset; assets=%v", want, keysOfPayments(got))
		}
	}
}

func keysOfPayments(m map[string]models.CryptoAsset) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestPaymentsScanListKeysErrorPropagates verifies that a genuine ListKeys
// failure (e.g. throttling/validation that is NOT a "service-not-here" signal)
// makes the scan VISIBLY incomplete by returning a non-nil error — NOT a silent
// empty success.
func TestPaymentsScanListKeysErrorPropagates(t *testing.T) {
	sentinel := paymentsAPIErr{code: "ThrottlingException"}
	client := &paymentsFakeClient{listErr: sentinel}
	_, err := PaymentCryptographyScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListKeys throttles, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListKeys failure, got: %v", err)
	}
}

// TestPaymentsScanServiceUnavailableSkips verifies the graceful skip: a regional
// "service not available / not opted-in" signal (AccessDenied) yields zero assets
// and NO error, so the (account,region) shard is not flagged errored. This is the
// only acceptable empty-success path — distinct from a swallowed real failure.
func TestPaymentsScanServiceUnavailableSkips(t *testing.T) {
	client := &paymentsFakeClient{listErr: paymentsAPIErr{code: "AccessDeniedException"}}
	assets, err := PaymentCryptographyScanner{}.scan(context.Background(), client, "111122223333", "ap-south-1")
	if err != nil {
		t.Fatalf("expected nil error for service-not-available skip, got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected zero assets on graceful skip, got %d", len(assets))
	}
}

// TestPaymentsScanGetKeyFailureKeepsAsset verifies that a per-key GetKey failure
// drops only the enrichment (origin/createTimestamp), NEVER the asset — the key
// is still inventoried and classified from the inline ListKeys attributes.
func TestPaymentsScanGetKeyFailureKeepsAsset(t *testing.T) {
	client := &paymentsFakeClient{
		listPages: []*paymentcryptography.ListKeysOutput{
			{Keys: []pctypes.KeySummary{paymentsKeySummary("arn:key-getfail", pctypes.KeyAlgorithmAes256, pctypes.KeyClassSymmetricKey)}},
		},
		getErr: errors.New("AccessDeniedException: GetKey not permitted"),
	}
	assets, err := PaymentCryptographyScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	got := paymentsAssetByID(assets)
	a, ok := got["arn:key-getfail"]
	if !ok {
		t.Fatalf("expected key to survive a GetKey failure as an asset; assets=%v", keysOfPayments(got))
	}
	if v := paymentsPostureOf(a); v != string(models.PostureSymmetricOnly) {
		t.Errorf("expected AES key to remain classified SymmetricOnly even when GetKey fails, got %q", v)
	}
	if _, has := a.Properties["keyOrigin"]; has {
		t.Errorf("expected no keyOrigin enrichment when GetKey fails, got %q", a.Properties["keyOrigin"])
	}
}

// TestPaymentsScanClassificationHonesty asserts the per-algorithm posture
// contract for this key-management scanner:
//   - AES_*  -> SymmetricOnly (quantum-safe-grade symmetric, never NoEncryption)
//   - TDES_* -> SymmetricOnly (Grover-class, NOT a PQC migration target) AND
//     carries the weakCipher legacy-cipher annotation (so symmetric != AES-grade)
//   - RSA_*/ECC_* -> NonPQCClassical (asymmetric, quantum-vulnerable; never NoEncryption)
//   - unknown/future algorithm -> Unknown (never false-safe a new algorithm)
func TestPaymentsScanClassificationHonesty(t *testing.T) {
	client := &paymentsFakeClient{
		listPages: []*paymentcryptography.ListKeysOutput{
			{
				Keys: []pctypes.KeySummary{
					paymentsKeySummary("arn:aes", pctypes.KeyAlgorithmAes256, pctypes.KeyClassSymmetricKey),
					paymentsKeySummary("arn:tdes", pctypes.KeyAlgorithmTdes3key, pctypes.KeyClassSymmetricKey),
					paymentsKeySummary("arn:rsa", pctypes.KeyAlgorithmRsa3072, pctypes.KeyClassAsymmetricKeyPair),
					paymentsKeySummary("arn:ecc", pctypes.KeyAlgorithmEccNistP256, pctypes.KeyClassAsymmetricKeyPair),
					paymentsKeySummary("arn:unknown", pctypes.KeyAlgorithm("ML_KEM_768"), pctypes.KeyClassAsymmetricKeyPair),
				},
			},
		},
	}
	assets, err := PaymentCryptographyScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	got := paymentsAssetByID(assets)

	cases := []struct {
		id          string
		wantPosture models.CryptoPosture
	}{
		{"arn:aes", models.PostureSymmetricOnly},
		{"arn:tdes", models.PostureSymmetricOnly},
		{"arn:rsa", models.PostureNonPQCClassical},
		{"arn:ecc", models.PostureNonPQCClassical},
		{"arn:unknown", models.PostureUnknown},
	}
	for _, c := range cases {
		a, ok := got[c.id]
		if !ok {
			t.Errorf("%s: expected an asset, none found", c.id)
			continue
		}
		if v := paymentsPostureOf(a); v != string(c.wantPosture) {
			t.Errorf("%s: posture = %q, want %q", c.id, v, c.wantPosture)
		}
		// An always-present payment-HSM key must never be classified as having no
		// encryption — every key here is keyed material.
		if paymentsPostureOf(a) == string(models.PostureNoEncryption) {
			t.Errorf("%s: a payment key must never be classified NoEncryption", c.id)
		}
	}

	// TDES must carry the weak-cipher legacy annotation so "symmetric" is not
	// mistaken for AES-grade strength.
	if tdes, ok := got["arn:tdes"]; ok {
		if tdes.Properties["weakCipher"] == "" {
			t.Errorf("arn:tdes: expected a weakCipher annotation for legacy 3DES, got none")
		}
	}
}
