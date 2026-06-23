package certmgmt

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/signer"
	signertypes "github.com/aws/aws-sdk-go-v2/service/signer/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeSignerClient is a hand-rolled signerAPI for unit-testing the scanner's
// pagination + error propagation + classification without a live AWS client.
// listPages is returned page-by-page (each call consumes the next page) with the
// NextToken wired so the scanner loops through every page; listErr forces a
// ListSigningProfiles failure; getOverrides supplies per-profile
// GetSigningProfile EncryptionAlgorithm by profile name (absent name => no
// overrides, simulating a profile whose algorithm cannot be observed); getErr
// forces a GetSigningProfile failure for ALL profiles.
type fakeSignerClient struct {
	listPages    []*signer.ListSigningProfilesOutput
	listCalls    int
	listErr      error
	getOverrides map[string]signertypes.EncryptionAlgorithm
	getErr       error
}

func (f *fakeSignerClient) ListSigningProfiles(ctx context.Context, in *signer.ListSigningProfilesInput, optFns ...func(*signer.Options)) (*signer.ListSigningProfilesOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listCalls >= len(f.listPages) {
		return &signer.ListSigningProfilesOutput{}, nil
	}
	out := f.listPages[f.listCalls]
	f.listCalls++
	return out, nil
}

func (f *fakeSignerClient) GetSigningProfile(ctx context.Context, in *signer.GetSigningProfileInput, optFns ...func(*signer.Options)) (*signer.GetSigningProfileOutput, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	name := ""
	if in.ProfileName != nil {
		name = *in.ProfileName
	}
	algo, ok := f.getOverrides[name]
	if !ok {
		// No overrides recorded for this profile -> algorithm is unobservable.
		return &signer.GetSigningProfileOutput{}, nil
	}
	return &signer.GetSigningProfileOutput{
		Overrides: &signertypes.SigningPlatformOverrides{
			SigningConfiguration: &signertypes.SigningConfigurationOverrides{
				EncryptionAlgorithm: algo,
				HashAlgorithm:       signertypes.HashAlgorithmSha256,
			},
		},
	}, nil
}

func signerStrptr(s string) *string { return &s }

// signerAssetByID indexes assets by ResourceID for assertion convenience.
func signerAssetByID(assets []models.CryptoAsset) map[string]models.CryptoAsset {
	m := map[string]models.CryptoAsset{}
	for _, a := range assets {
		m[a.ResourceID] = a
	}
	return m
}

// signerPostureOf returns the posture property stamped on an asset (empty if none).
func signerPostureOf(a models.CryptoAsset) models.CryptoPosture {
	if a.Properties == nil {
		return ""
	}
	return models.CryptoPosture(a.Properties["posture"])
}

// TestSignerScanPaginatesProfiles verifies the ListSigningProfiles NextToken loop:
// a fake returning 2 pages (NextToken on page 1) must yield BOTH pages' profiles as
// assets. Without the pagination loop, only the first page's profile survives.
func TestSignerScanPaginatesProfiles(t *testing.T) {
	client := &fakeSignerClient{
		listPages: []*signer.ListSigningProfilesOutput{
			{
				Profiles: []signertypes.SigningProfile{
					{ProfileName: signerStrptr("prof-page1"), Arn: signerStrptr("arn:aws:signer:us-east-1:111122223333:/signing-profiles/prof-page1")},
				},
				NextToken: signerStrptr("tok-page2"),
			},
			{
				Profiles: []signertypes.SigningProfile{
					{ProfileName: signerStrptr("prof-page2"), Arn: signerStrptr("arn:aws:signer:us-east-1:111122223333:/signing-profiles/prof-page2")},
				},
				// no NextToken -> last page
			},
		},
		getOverrides: map[string]signertypes.EncryptionAlgorithm{
			"prof-page1": signertypes.EncryptionAlgorithmRsa,
			"prof-page2": signertypes.EncryptionAlgorithmEcdsa,
		},
	}
	assets, err := SignerScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if c := client.listCalls; c != 2 {
		t.Errorf("expected ListSigningProfiles to be called 2 times (paginated), got %d", c)
	}
	byID := signerAssetByID(assets)
	for _, want := range []string{
		"arn:aws:signer:us-east-1:111122223333:/signing-profiles/prof-page1",
		"arn:aws:signer:us-east-1:111122223333:/signing-profiles/prof-page2",
	} {
		if _, ok := byID[want]; !ok {
			t.Errorf("expected profile %q from a paginated page to appear as an asset; got %d assets", want, len(assets))
		}
	}
}

// TestSignerScanListErrorPropagates verifies the incompleteness decision: a
// ListSigningProfiles failure (denied/rate-limited) must make the scan VISIBLY
// incomplete by returning a non-nil error — NOT a silent empty success.
func TestSignerScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform signer:ListSigningProfiles")
	client := &fakeSignerClient{listErr: sentinel}
	assets, err := SignerScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err == nil {
		t.Fatalf("expected scan to return a non-nil error when ListSigningProfiles fails, got nil with %d assets", len(assets))
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListSigningProfiles failure, got: %v", err)
	}
}

// TestSignerScanClassifiesClassicalSignatures asserts the honesty posture for this
// cert-domain scanner: an observed RSA/ECDSA signing profile maps to RSA/ECDSA and
// is stamped NonPQCClassical (a quantum-migration target) — NEVER a "no encryption"
// or "clean" finding. The signature primitive and the classical-only note must be
// present so the asset reads as quantum-vulnerable, not as encryption-off.
func TestSignerScanClassifiesClassicalSignatures(t *testing.T) {
	client := &fakeSignerClient{
		listPages: []*signer.ListSigningProfilesOutput{
			{
				Profiles: []signertypes.SigningProfile{
					{ProfileName: signerStrptr("rsa-prof"), Arn: signerStrptr("arn:rsa")},
					{ProfileName: signerStrptr("ecdsa-prof"), Arn: signerStrptr("arn:ecdsa")},
				},
			},
		},
		getOverrides: map[string]signertypes.EncryptionAlgorithm{
			"rsa-prof":   signertypes.EncryptionAlgorithmRsa,
			"ecdsa-prof": signertypes.EncryptionAlgorithmEcdsa,
		},
	}
	assets, err := SignerScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	byID := signerAssetByID(assets)

	for _, tc := range []struct {
		id      string
		wantSig string
	}{
		{"arn:rsa", "RSA"},
		{"arn:ecdsa", "ECDSA"},
	} {
		a, ok := byID[tc.id]
		if !ok {
			t.Fatalf("expected asset %q to be present", tc.id)
		}
		if p := signerPostureOf(a); p != models.PostureNonPQCClassical {
			t.Errorf("%s: expected posture NonPQCClassical, got %q", tc.id, p)
		}
		if p := signerPostureOf(a); p == models.PostureNoEncryption {
			t.Errorf("%s: signing profile must NEVER be classified NoEncryption", tc.id)
		}
		if a.Properties == nil || a.Properties["note"] == "" {
			t.Errorf("%s: expected classical-only quantum-vulnerable note", tc.id)
		}
		if a.Properties["signatureAlgorithm"] == "" {
			t.Errorf("%s: expected signatureAlgorithm property to record observed algorithm", tc.id)
		}
		if a.CryptoProps.AlgorithmProperties == nil {
			t.Fatalf("%s: expected AlgorithmProperties to be set", tc.id)
		}
		if a.CryptoProps.AlgorithmProperties.Primitive != models.PrimitiveSignature {
			t.Errorf("%s: expected Primitive=signature, got %q", tc.id, a.CryptoProps.AlgorithmProperties.Primitive)
		}
		if a.CryptoProps.AlgorithmProperties.AlgorithmName != tc.wantSig {
			t.Errorf("%s: expected AlgorithmName %q, got %q", tc.id, tc.wantSig, a.CryptoProps.AlgorithmProperties.AlgorithmName)
		}
		if a.CryptoProps.AlgorithmProperties.NistQuantumSecurityLevel != 0 {
			t.Errorf("%s: classical signature must be NIST quantum level 0, got %d", tc.id, a.CryptoProps.AlgorithmProperties.NistQuantumSecurityLevel)
		}
	}
}

// TestSignerScanUnreadableAlgoStaysClassical asserts the no-silent-downgrade
// posture: when GetSigningProfile reveals no overrides (algorithm unobservable),
// the profile is STILL emitted as a NonPQCClassical asset (the platform implies a
// classical algorithm) — it is not dropped and not turned into a clean/no-encryption
// finding. The signature label falls back to a generic classical signature.
func TestSignerScanUnreadableAlgoStaysClassical(t *testing.T) {
	client := &fakeSignerClient{
		listPages: []*signer.ListSigningProfilesOutput{
			{
				Profiles: []signertypes.SigningProfile{
					{ProfileName: signerStrptr("opaque-prof"), Arn: signerStrptr("arn:opaque")},
				},
			},
		},
		// no getOverrides entry -> GetSigningProfile returns empty overrides
	}
	assets, err := SignerScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	byID := signerAssetByID(assets)
	a, ok := byID["arn:opaque"]
	if !ok {
		t.Fatalf("expected profile with unobservable algorithm to STILL be emitted (not dropped); got %d assets", len(assets))
	}
	if p := signerPostureOf(a); p != models.PostureNonPQCClassical {
		t.Errorf("unobservable-algo profile must remain NonPQCClassical, got %q", p)
	}
	if a.CryptoProps.AlgorithmProperties == nil || a.CryptoProps.AlgorithmProperties.AlgorithmName != "classical signature" {
		t.Errorf("expected fallback AlgorithmName \"classical signature\", got %+v", a.CryptoProps.AlgorithmProperties)
	}
	// Unobservable algorithm must not be stamped as observed.
	if a.Properties["signatureAlgorithm"] != "" {
		t.Errorf("expected no signatureAlgorithm property when algorithm is unobservable, got %q", a.Properties["signatureAlgorithm"])
	}
}

// TestSignerScanGetProfileErrorDoesNotDrop asserts no silent drop on the
// per-resource path: if GetSigningProfile fails for a profile, the profile is still
// emitted (as classical) rather than dropped — a List-visible profile must not
// disappear because a follow-up describe was denied.
func TestSignerScanGetProfileErrorDoesNotDrop(t *testing.T) {
	client := &fakeSignerClient{
		listPages: []*signer.ListSigningProfilesOutput{
			{
				Profiles: []signertypes.SigningProfile{
					{ProfileName: signerStrptr("denied-prof"), Arn: signerStrptr("arn:denied")},
				},
			},
		},
		getErr: errors.New("AccessDeniedException: signer:GetSigningProfile"),
	}
	assets, err := SignerScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	byID := signerAssetByID(assets)
	a, ok := byID["arn:denied"]
	if !ok {
		t.Fatalf("expected profile to be emitted even when GetSigningProfile is denied; got %d assets", len(assets))
	}
	if p := signerPostureOf(a); p != models.PostureNonPQCClassical {
		t.Errorf("describe-denied profile must remain NonPQCClassical, got %q", p)
	}
}
