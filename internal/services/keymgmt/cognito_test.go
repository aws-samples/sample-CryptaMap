package keymgmt

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitotypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeCognitoClient is a hand-rolled cognitoUserPoolsAPI for unit-testing the
// scanner's pagination + error propagation without a live AWS client. listPages is
// returned page-by-page (each call consumes the next page) and the NextToken is
// wired so the scanner loops through every page; listErr forces a ListUserPools
// failure.
type fakeCognitoClient struct {
	cognitoListPages []*cognitoidentityprovider.ListUserPoolsOutput
	cognitoListCalls int
	cognitoListErr   error
}

func (f *fakeCognitoClient) ListUserPools(ctx context.Context, in *cognitoidentityprovider.ListUserPoolsInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUserPoolsOutput, error) {
	if f.cognitoListErr != nil {
		return nil, f.cognitoListErr
	}
	if f.cognitoListCalls >= len(f.cognitoListPages) {
		return &cognitoidentityprovider.ListUserPoolsOutput{}, nil
	}
	out := f.cognitoListPages[f.cognitoListCalls]
	f.cognitoListCalls++
	return out, nil
}

func cognitoStrptr(s string) *string { return &s }

// cognitoAssetByID returns the asset whose ResourceID matches id, or nil.
func cognitoAssetByID(assets []models.CryptoAsset, id string) *models.CryptoAsset {
	for i := range assets {
		if assets[i].ResourceID == id {
			return &assets[i]
		}
	}
	return nil
}

// TestCognitoScanPaginatesUserPools verifies the ListUserPools NextToken loop: a
// fake that returns 2 pages (NextToken on page 1) must yield BOTH pages' user
// pools as assets. Without the pagination loop, only the first page's pool
// survives — silently dropping pools in dense accounts.
func TestCognitoScanPaginatesUserPools(t *testing.T) {
	client := &fakeCognitoClient{
		cognitoListPages: []*cognitoidentityprovider.ListUserPoolsOutput{
			{
				UserPools: []cognitotypes.UserPoolDescriptionType{
					{Id: cognitoStrptr("pool-page1"), Name: cognitoStrptr("Pool1")},
				},
				NextToken: cognitoStrptr("tok-page2"),
			},
			{
				UserPools: []cognitotypes.UserPoolDescriptionType{
					{Id: cognitoStrptr("pool-page2"), Name: cognitoStrptr("Pool2")},
				},
				// no NextToken -> last page
			},
		},
	}
	assets, err := CognitoScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.cognitoListCalls; c != 2 {
		t.Errorf("expected ListUserPools to be called 2 times (paginated), got %d", c)
	}
	for _, want := range []string{"pool-page1", "pool-page2"} {
		if cognitoAssetByID(assets, want) == nil {
			t.Errorf("expected user pool %q from a paginated page to appear as an asset", want)
		}
	}
}

// TestCognitoScanListErrorPropagates verifies the incompleteness decision: a
// ListUserPools failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success that would
// look like "this account has no user pools".
func TestCognitoScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform cognito-idp:ListUserPools")
	client := &fakeCognitoClient{cognitoListErr: sentinel}
	assets, err := CognitoScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListUserPools fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListUserPools failure, got: %v", err)
	}
	if len(assets) != 0 {
		t.Errorf("expected no assets on error, got %d", len(assets))
	}
}

// TestCognitoScanHonestyPosture asserts the always-on classical-signature posture:
// every Cognito user pool signs tokens with RS256 (RSA-2048), a classical
// quantum-vulnerable signature. The asset MUST be NonPQCClassical (never reported
// as safe and never as a "no encryption" finding — Cognito always signs), carry
// the RS256 signature algorithm with NIST quantum level 0, and surface the
// migration-target note.
func TestCognitoScanHonestyPosture(t *testing.T) {
	client := &fakeCognitoClient{
		cognitoListPages: []*cognitoidentityprovider.ListUserPoolsOutput{
			{
				UserPools: []cognitotypes.UserPoolDescriptionType{
					{Id: cognitoStrptr("pool-1"), Name: cognitoStrptr("MyPool")},
				},
			},
		},
	}
	assets, err := CognitoScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	a := cognitoAssetByID(assets, "pool-1")
	if a == nil {
		t.Fatal("expected an asset for pool-1")
	}

	// Posture must be NonPQCClassical — never safe, never NoEncryption. Cognito
	// always signs tokens, so a "no encryption" posture would be a false finding.
	if got := a.Properties["posture"]; got != string(models.PostureNonPQCClassical) {
		t.Errorf("expected NonPQCClassical posture for RS256 token signing, got %q", got)
	}
	if a.Properties["posture"] == string(models.PostureNoEncryption) {
		t.Errorf("Cognito always signs tokens; posture must not be NoEncryption")
	}

	if a.Properties == nil || a.Properties["tokenSigningAlgorithm"] != "RS256" {
		t.Errorf("expected tokenSigningAlgorithm=RS256, got properties=%v", a.Properties)
	}
	if a.Properties["userPoolName"] != "MyPool" {
		t.Errorf("expected userPoolName=MyPool, got %v", a.Properties["userPoolName"])
	}
	if a.Properties["note"] == "" {
		t.Error("expected a non-empty migration-target note explaining the classical RS256 signature")
	}

	ap := a.CryptoProps.AlgorithmProperties
	if ap == nil {
		t.Fatal("expected AlgorithmProperties to be populated for the RS256 signature")
	}
	if ap.Primitive != models.PrimitiveSignature {
		t.Errorf("expected signature primitive, got %v", ap.Primitive)
	}
	if ap.KeySizeBits != 2048 {
		t.Errorf("expected RSA-2048 key size, got %d", ap.KeySizeBits)
	}
	if ap.NistQuantumSecurityLevel != 0 {
		t.Errorf("expected NIST quantum security level 0 (quantum-vulnerable), got %d", ap.NistQuantumSecurityLevel)
	}
}
