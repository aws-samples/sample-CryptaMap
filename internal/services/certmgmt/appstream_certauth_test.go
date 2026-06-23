package certmgmt

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	asTypes "github.com/aws/aws-sdk-go-v2/service/appstream/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestClassifyAppStreamCertAuth is the regulator-honesty guardrail for the
// AppStream certificate-based-authentication trust surface. It drives the pure
// classify helper through every status branch and asserts the EXACT posture
// constant and Property keys/values Scan emits.
//
// The contract these cases lock down:
//   - ENABLED / ENABLED_NO_DIRECTORY_LOGIN_FALLBACK -> NonPQCClassical (classical
//     X.509 client-cert trust), with passwordFallbackAllowed recorded correctly
//     (true with AD fallback, false for cert-only) and the CA ARN passed through.
//   - DISABLED -> STILL NonPQCClassical informational inventory, NEVER
//     PostureNoEncryption. This is auth/cert custody, not at-rest encryption, so
//     a disabled config must not be reported as "encryption off".
//   - cba == nil -> skip (ok=false), never a crash and never a fabricated asset.
func TestClassifyAppStreamCertAuth(t *testing.T) {
	const (
		acct    = "111122223333"
		region  = "us-east-1"
		dirName = "corp.example.com"
		caArn   = "arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/abc-123"
	)

	cases := []struct {
		name string
		cba  *asTypes.CertificateBasedAuthProperties

		wantOK              bool
		wantPosture         models.CryptoPosture
		wantStatus          string
		wantFallback        string
		wantCAArn           string // "" means the certificateAuthorityArn key must be ABSENT
		wantNoteContains    string
		wantNoteNotContains string // must NOT appear (honesty: never "encryption off")
	}{
		{
			name: "enabled_with_customer_ca_and_password_fallback",
			cba: &asTypes.CertificateBasedAuthProperties{
				Status:                  asTypes.CertificateBasedAuthStatusEnabled,
				CertificateAuthorityArn: aws.String(caArn),
			},
			wantOK:              true,
			wantPosture:         models.PostureNonPQCClassical,
			wantStatus:          string(asTypes.CertificateBasedAuthStatusEnabled),
			wantFallback:        "true",
			wantCAArn:           caArn,
			wantNoteContains:    "AD-password fallback is allowed",
			wantNoteNotContains: "encryption",
		},
		{
			name: "enabled_cert_only_no_fallback",
			cba: &asTypes.CertificateBasedAuthProperties{
				Status:                  asTypes.CertificateBasedAuthStatusEnabledNoDirectoryLoginFallback,
				CertificateAuthorityArn: aws.String(caArn),
			},
			wantOK:              true,
			wantPosture:         models.PostureNonPQCClassical,
			wantStatus:          string(asTypes.CertificateBasedAuthStatusEnabledNoDirectoryLoginFallback),
			wantFallback:        "false",
			wantCAArn:           caArn,
			wantNoteContains:    "cert-only, no AD-password fallback",
			wantNoteNotContains: "encryption",
		},
		{
			name: "disabled_is_informational_never_no_encryption",
			cba: &asTypes.CertificateBasedAuthProperties{
				Status: asTypes.CertificateBasedAuthStatusDisabled,
			},
			wantOK:           true,
			wantPosture:      models.PostureNonPQCClassical, // honesty: NOT PostureNoEncryption
			wantStatus:       string(asTypes.CertificateBasedAuthStatusDisabled),
			wantFallback:     "true",
			wantCAArn:        "", // no CA configured when disabled -> key absent
			wantNoteContains: "not currently enforced",
		},
		{
			name: "enabled_without_ca_arn_omits_key",
			cba: &asTypes.CertificateBasedAuthProperties{
				Status: asTypes.CertificateBasedAuthStatusEnabled,
			},
			wantOK:           true,
			wantPosture:      models.PostureNonPQCClassical,
			wantStatus:       string(asTypes.CertificateBasedAuthStatusEnabled),
			wantFallback:     "true",
			wantCAArn:        "", // CA ARN nil -> key must be absent, not empty string
			wantNoteContains: "ENABLED",
		},
		{
			name:   "nil_block_skips_never_crashes",
			cba:    nil,
			wantOK: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, ok := classifyAppStreamCertAuth(acct, region, dirName, c.cba)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if !c.wantOK {
				// Skip case: nothing further to assert; must not have crashed.
				return
			}

			// Posture (the load-bearing honesty assertion).
			if got := a.Properties["posture"]; got != string(c.wantPosture) {
				t.Errorf("posture = %q, want %q", got, c.wantPosture)
			}
			if a.Properties["posture"] == string(models.PostureNoEncryption) {
				t.Errorf("AppStream cert-auth must NEVER report no-encryption (auth/cert custody, not at-rest encryption)")
			}

			// Category + resource shape.
			if a.Category != models.CategoryCertificate {
				t.Errorf("Category = %v, want %v", a.Category, models.CategoryCertificate)
			}
			if a.ResourceType != "AWS::AppStream::DirectoryConfig" {
				t.Errorf("ResourceType = %q, want AWS::AppStream::DirectoryConfig", a.ResourceType)
			}
			if a.CryptoProps.AssetType != models.AssetTypeCertificate {
				t.Errorf("AssetType = %v, want %v", a.CryptoProps.AssetType, models.AssetTypeCertificate)
			}

			// Status + fallback Property values.
			if got := a.Properties["certBasedAuthStatus"]; got != c.wantStatus {
				t.Errorf("certBasedAuthStatus = %q, want %q", got, c.wantStatus)
			}
			if got := a.Properties["passwordFallbackAllowed"]; got != c.wantFallback {
				t.Errorf("passwordFallbackAllowed = %q, want %q", got, c.wantFallback)
			}

			// CA ARN: present-and-equal, or absent (never an empty-string key).
			got, present := a.Properties["certificateAuthorityArn"]
			if c.wantCAArn == "" {
				if present {
					t.Errorf("certificateAuthorityArn present = %q, want absent", got)
				}
			} else {
				if got != c.wantCAArn {
					t.Errorf("certificateAuthorityArn = %q, want %q", got, c.wantCAArn)
				}
			}

			// Note evidence.
			note := a.Properties["note"]
			if note == "" {
				t.Errorf("note must be set for every classified directory config")
			}
			if c.wantNoteContains != "" && !contains(note, c.wantNoteContains) {
				t.Errorf("note = %q, want it to contain %q", note, c.wantNoteContains)
			}
			if c.wantNoteNotContains != "" && contains(note, c.wantNoteNotContains) {
				t.Errorf("note = %q must NOT contain %q (no fabricated encryption framing)", note, c.wantNoteNotContains)
			}
		})
	}
}

// contains is a tiny substring helper to keep the table assertions readable.
func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
