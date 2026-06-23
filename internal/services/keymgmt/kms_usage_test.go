package keymgmt

import "testing"

// TestIsAWSManagedAlias locks the discriminator behind the AWS-managed-key
// symmetric-only guarantee: only the reserved, literal-lowercase "alias/aws/"
// prefix is AWS-managed. KMS alias names are CASE SENSITIVE and the reserved
// prefix customers cannot create is exactly "alias/aws/", so a mixed-case alias
// like "alias/AWS/Redshift" is a legitimate CUSTOMER alias and must NOT be
// treated as AWS-managed — doing so would wrongly assert a symmetric-only
// guarantee over a key whose real spec we never resolved (a false-safe over a
// possibly-asymmetric customer key).
func TestIsAWSManagedAlias(t *testing.T) {
	cases := []struct {
		alias string
		want  bool
	}{
		{"alias/aws/rds", true},
		{"alias/aws/s3", true},
		{"alias/aws/ssm", true},
		{"alias/AWS/Redshift", false}, // case-sensitive: mixed-case is a customer alias
		{"alias/my-app-key", false},
		{"alias/aws-team-key", false}, // "aws" without the reserved "aws/" path segment
		{"alias/team/aws/key", false}, // reserved prefix is an anchor, not a substring
		{"", false},
	}
	for _, c := range cases {
		if got := isAWSManagedAlias(c.alias); got != c.want {
			t.Errorf("isAWSManagedAlias(%q) = %v, want %v", c.alias, got, c.want)
		}
	}
}

// TestKMSSpecPostureAWSManagedConsistency proves that when an AWS-managed key
// DOES resolve via DescribeKey, kmsSpecPosture already classifies its
// SYMMETRIC_DEFAULT spec as symmetric-only — i.e. the unresolved alias/aws/*
// guarantee (SymmetricOnly) is CONSISTENT with the resolved path, not a
// divergent special case.
func TestKMSSpecPostureAWSManagedConsistency(t *testing.T) {
	if got := kmsSpecPosture("SYMMETRIC_DEFAULT"); got != "symmetric-only" {
		t.Errorf("kmsSpecPosture(SYMMETRIC_DEFAULT) = %q, want symmetric-only "+
			"(resolved AWS-managed key must match the unresolved-alias guarantee)", got)
	}
}
