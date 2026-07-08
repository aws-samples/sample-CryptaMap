package datarest

import (
	"testing"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestClassifyBedrockKeyTier is the regulator-honesty guardrail for the Bedrock
// at-rest classifier. Bedrock ALWAYS encrypts its stored resources at rest with
// AES-256 and there is no toggle to disable it, so the posture must be
// UNCONDITIONALLY SymmetricOnly across every resource family and every input —
// the only thing that varies is the KEY TIER (customer CMK vs AWS-owned/managed
// default). This test fails loudly if anyone later:
//   - makes an absent CMK collapse to PostureNoEncryption (false alarm on an
//     always-encrypted service), or
//   - makes the AWS-managed default look like a clean all-clear (drops the
//     "no customer key custody" honesty note / fabricates a CMK ARN).
func TestClassifyBedrockKeyTier(t *testing.T) {
	const cmkARN = "arn:aws:kms:us-east-1:123456789012:key/abcd-1234-ef56"

	cases := []struct {
		name        string
		cmkArn      string
		getErr      bool
		noCMKField  bool
		defaultNote string
		wantPosture models.CryptoPosture
		wantKeyID   string
		wantTier    string
		wantNote    string // "" means assert the note key is ABSENT
	}{
		{
			// Customer CMK present -> customer-managed tier, real ARN, no default note.
			name:        "customer CMK present",
			cmkArn:      cmkARN,
			wantPosture: models.PostureSymmetricOnly,
			wantKeyID:   cmkARN,
			wantTier:    "customer-managed",
			wantNote:    "",
		},
		{
			// CMK absent (custom model / agent / guardrail with no GetX CMK) ->
			// STILL SymmetricOnly (always-encrypted), AWS-owned sentinel, honest note.
			name:        "CMK absent uses AWS-owned default with custody note",
			cmkArn:      "",
			wantPosture: models.PostureSymmetricOnly,
			wantKeyID:   awsOwnedKey,
			wantTier:    "aws-managed-default",
			wantNote:    awsManagedDefaultNote,
		},
		{
			// Get FAILED: key custody could not be read. STILL SymmetricOnly
			// (Bedrock always encrypts), but custody is honestly undetermined — we must
			// NOT fabricate the aws-managed-default verdict, and never a CMK ARN.
			name:        "Get failure yields honest unknown custody, never aws-managed-default",
			cmkArn:      "",
			getErr:      true,
			wantPosture: models.PostureSymmetricOnly,
			wantKeyID:   "UNRESOLVED",
			wantTier:    "unknown",
			wantNote:    keyCustodyUnknownNote,
		},
		{
			// Knowledge base: the SDK exposes NO per-KB CMK field (noCMKField). An
			// empty CMK here is NOT an observed AWS-managed default (the downstream
			// store may be CMK-encrypted), so custody MUST be honestly undetermined —
			// keyTier=unknown, kmsKeyId=UNRESOLVED, never the aws-managed-default
			// verdict and never a fabricated CMK ARN — with the KB-specific note.
			// DISCRIMINATING: if the classifier reverts to the aws-managed-default
			// verdict for a no-CMK-field input, wantKeyID/wantTier below fail.
			name:        "knowledge base no-CMK-field yields honest unknown custody",
			cmkArn:      "",
			noCMKField:  true,
			defaultNote: kbNoCMKFieldNote,
			wantPosture: models.PostureSymmetricOnly,
			wantKeyID:   "UNRESOLVED",
			wantTier:    "unknown",
			wantNote:    kbNoCMKFieldNote,
		},
		{
			// noCMKField with no explicit note falls back to the KB-specific note
			// (not the shared aws-managed-default note), still UNRESOLVED/unknown.
			name:        "no-CMK-field default note falls back to KB note",
			cmkArn:      "",
			noCMKField:  true,
			wantPosture: models.PostureSymmetricOnly,
			wantKeyID:   "UNRESOLVED",
			wantTier:    "unknown",
			wantNote:    kbNoCMKFieldNote,
		},
		{
			// A family-specific note must NOT override a real customer CMK, even with
			// noCMKField set: a present CMK is still customer-managed with the ARN and
			// no default note attached.
			name:        "customer CMK present ignores defaultNote and noCMKField",
			cmkArn:      cmkARN,
			noCMKField:  true,
			defaultNote: kbNoCMKFieldNote,
			wantPosture: models.PostureSymmetricOnly,
			wantKeyID:   cmkARN,
			wantTier:    "customer-managed",
			wantNote:    "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotPosture, props := classifyBedrockKeyTier(c.cmkArn, c.getErr, c.noCMKField, c.defaultNote)

			// HONESTY: posture is ALWAYS SymmetricOnly, NEVER no-encryption.
			if gotPosture != c.wantPosture {
				t.Errorf("posture = %q, want %q", gotPosture, c.wantPosture)
			}
			if gotPosture == models.PostureNoEncryption {
				t.Fatalf("posture is PostureNoEncryption for an always-encrypted service — false alarm")
			}

			if got := props["kmsKeyId"]; got != c.wantKeyID {
				t.Errorf("kmsKeyId = %q, want %q", got, c.wantKeyID)
			}
			if got := props["keyTier"]; got != c.wantTier {
				t.Errorf("keyTier = %q, want %q", got, c.wantTier)
			}

			gotNote, hasNote := props["note"]
			if c.wantNote == "" {
				if hasNote {
					t.Errorf("expected NO note for a customer-managed key, got %q", gotNote)
				}
			} else {
				if !hasNote {
					t.Fatalf("expected an honesty note for the AWS-managed default, got none — an AWS-managed default must NOT read as a clean all-clear")
				}
				if gotNote != c.wantNote {
					t.Errorf("note = %q, want %q", gotNote, c.wantNote)
				}
			}

			// HONESTY: never fabricate a CMK ARN when none was supplied — the only
			// allowed no-CMK key IDs are the AWS-owned sentinel (default tier) or the
			// UNRESOLVED sentinel (read failed / custody undetermined).
			if c.cmkArn == "" && props["kmsKeyId"] != awsOwnedKey && props["kmsKeyId"] != "UNRESOLVED" {
				t.Errorf("fabricated kmsKeyId %q with no CMK input; want %q or %q", props["kmsKeyId"], awsOwnedKey, "UNRESOLVED")
			}
		})
	}
}

// TestNewBedrockAsset_AssemblesClassification verifies the Scan-path assembler
// stamps the SymmetricOnly posture and the key-tier evidence from the pure
// classifier onto a real asset, so the helper truly is the single source of truth.
func TestNewBedrockAsset_AssemblesClassification(t *testing.T) {
	// Knowledge base (noCMKField) branch: honest UNRESOLVED/unknown custody, never
	// the fabricated aws-managed-default verdict, KB-specific note retained.
	a := newBedrockAsset("123456789012", "us-east-1", "kb-1", "AWS::Bedrock::KnowledgeBase", "", false, true, kbNoCMKFieldNote)
	if a.Properties["posture"] != string(models.PostureSymmetricOnly) {
		t.Errorf("posture property = %q, want %q", a.Properties["posture"], models.PostureSymmetricOnly)
	}
	if a.Properties["kmsKeyId"] != "UNRESOLVED" {
		t.Errorf("kmsKeyId = %q, want UNRESOLVED (no-CMK-field custody undetermined, never aws-managed-default)", a.Properties["kmsKeyId"])
	}
	if a.Properties["keyTier"] != "unknown" {
		t.Errorf("keyTier = %q, want unknown", a.Properties["keyTier"])
	}
	if a.Properties["note"] != kbNoCMKFieldNote {
		t.Errorf("note = %q, want KB note", a.Properties["note"])
	}
	if a.CryptoProps.AlgorithmProperties == nil || a.CryptoProps.AlgorithmProperties.AlgorithmName != "AES-256" {
		t.Errorf("at-rest algorithm = %+v, want AES-256", a.CryptoProps.AlgorithmProperties)
	}

	// AWS-managed default branch: no CMK, not a no-CMK-field family (e.g. a custom
	// model whose GetCustomModel succeeded with no ModelKmsKeyArn) -> observed
	// AWS-owned default with the shared custody note.
	d := newBedrockAsset("123456789012", "us-east-1", "model-0", "AWS::Bedrock::CustomModel", "", false, false, "")
	if d.Properties["kmsKeyId"] != awsOwnedKey {
		t.Errorf("kmsKeyId = %q, want %q (observed AWS-managed default)", d.Properties["kmsKeyId"], awsOwnedKey)
	}
	if d.Properties["keyTier"] != "aws-managed-default" {
		t.Errorf("keyTier = %q, want aws-managed-default", d.Properties["keyTier"])
	}
	if d.Properties["note"] != awsManagedDefaultNote {
		t.Errorf("note = %q, want shared aws-managed-default note", d.Properties["note"])
	}

	// Customer-managed branch (real CMK ARN).
	const cmkARN = "arn:aws:kms:us-east-1:123456789012:key/abcd"
	b := newBedrockAsset("123456789012", "us-east-1", "model-1", "AWS::Bedrock::CustomModel", cmkARN, false, false, "")
	if b.Properties["kmsKeyId"] != cmkARN {
		t.Errorf("kmsKeyId = %q, want %q", b.Properties["kmsKeyId"], cmkARN)
	}
	if b.Properties["keyTier"] != "customer-managed" {
		t.Errorf("keyTier = %q, want customer-managed", b.Properties["keyTier"])
	}
	if _, has := b.Properties["note"]; has {
		t.Errorf("customer-managed asset should carry no default note, got %q", b.Properties["note"])
	}
}
