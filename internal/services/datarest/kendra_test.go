package datarest

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	kentypes "github.com/aws/aws-sdk-go-v2/service/kendra/types"
)

// TestKendraKeyTier is the regulator-honesty guardrail for the Amazon Kendra
// at-rest scanner. Kendra is an ALWAYS-ENCRYPTED (Type-C) service: every index is
// AES-256 at rest with no disable toggle, so the posture is unconditionally
// SymmetricOnly (asserted in Scan) and kendraKeyTier only selects the key TIER.
//
// The test pins the EXACT kmsKeyId value the scanner records so that nobody can
// later (a) make an absent/nil key look like a clean all-clear by changing the
// AWS-owned sentinel, or (b) — at the Scan layer — flip an always-encrypted RAG/KYC
// corpus to a no-encryption finding. The honesty contract here is: a customer CMK
// surfaces the real ARN (customer key custody), while EVERY non-customer-key state
// (nil config, nil id, empty id) degrades to the AWS-owned default sentinel —
// never a crash, never an empty/blank all-clear, never no-encryption.
func TestKendraKeyTier(t *testing.T) {
	const customerCMK = "arn:aws:kms:ap-south-1:111122223333:key/abcd1234-ab12-cd34-ef56-abcdef123456"

	cases := []struct {
		name string
		sse  *kentypes.ServerSideEncryptionConfiguration
		want string
	}{
		{
			// Customer CMK present -> the real ARN is recorded (customer key custody).
			name: "customer_cmk_present",
			sse:  &kentypes.ServerSideEncryptionConfiguration{KmsKeyId: aws.String(customerCMK)},
			want: customerCMK,
		},
		{
			// AWS-owned default (no config returned by DescribeIndex). Still AES-256 /
			// SymmetricOnly, but NO customer key custody: must be the AWS-owned
			// sentinel, NOT a blank/clean all-clear and NOT no-encryption.
			name: "nil_config_aws_owned_default",
			sse:  nil,
			want: kendraOwnedKeySentinel,
		},
		{
			// Config present but KmsKeyId nil -> degrades to AWS-owned default, no crash.
			name: "config_with_nil_keyid",
			sse:  &kentypes.ServerSideEncryptionConfiguration{KmsKeyId: nil},
			want: kendraOwnedKeySentinel,
		},
		{
			// Config present but KmsKeyId empty string -> degrades to AWS-owned default.
			name: "config_with_empty_keyid",
			sse:  &kentypes.ServerSideEncryptionConfiguration{KmsKeyId: aws.String("")},
			want: kendraOwnedKeySentinel,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := kendraKeyTier(c.sse)
			if got != c.want {
				t.Errorf("kendraKeyTier() = %q, want %q", got, c.want)
			}
			// Honesty contract: the AWS-owned default must NEVER degrade to an empty
			// kmsKeyId (an empty value would render as a blank/clean all-clear in the
			// dashboard, hiding the lack of customer key custody).
			if got == "" {
				t.Errorf("kendraKeyTier() returned empty kmsKeyId for %s; an always-encrypted index must record the AWS-owned sentinel, never a blank all-clear", c.name)
			}
		})
	}

	// Pin the sentinel value itself: the AWS-owned default tier must be a clearly
	// non-customer marker, never an empty string.
	if kendraOwnedKeySentinel == "" {
		t.Fatal("kendraOwnedKeySentinel must be a non-empty AWS-owned marker")
	}
}
