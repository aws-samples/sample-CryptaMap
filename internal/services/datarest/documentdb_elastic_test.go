package datarest

import (
	"testing"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestClassifyDocumentDBElasticCluster verifies the kmsKeyId fallback and the
// invariant that posture is ALWAYS SymmetricOnly. DocumentDB Elastic clusters
// are unconditionally KMS-encrypted at rest with no opt-out, so the only thing
// that varies is WHICH key is recorded — never the posture. In particular, an
// empty kmsKeyId (GetCluster returned no key, or the describe failed entirely)
// falls back to the AWS-owned default key WITHOUT downgrading posture; a
// describe failure must never be reported as no-encryption.
func TestClassifyDocumentDBElasticCluster(t *testing.T) {
	const (
		acct = "111122223333"
		reg  = "us-east-1"
		arn  = "arn:aws:docdb-elastic:us-east-1:111122223333:cluster/my-cluster"
		name = "my-cluster"
	)

	t.Run("non-empty KmsKeyId is recorded verbatim", func(t *testing.T) {
		key := "arn:aws:kms:us-east-1:111122223333:key/abcd-1234"
		a := classifyDocumentDBElasticCluster(acct, reg, arn, name, key, false)
		if got := a.Properties["kmsKeyId"]; got != key {
			t.Errorf("kmsKeyId = %q, want %q (customer key recorded as-is)", got, key)
		}
		if got := a.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
			t.Errorf("posture = %q, want %q", got, models.PostureSymmetricOnly)
		}
		if got := a.Properties["clusterName"]; got != name {
			t.Errorf("clusterName = %q, want %q", got, name)
		}
	})

	t.Run("empty KmsKeyId from a successful describe falls back to AWS-owned key, posture unchanged", func(t *testing.T) {
		a := classifyDocumentDBElasticCluster(acct, reg, arn, name, "", false)
		if got := a.Properties["kmsKeyId"]; got != "AWS_OWNED_KMS_KEY" {
			t.Errorf("kmsKeyId = %q, want AWS_OWNED_KMS_KEY (empty key on a successful describe)", got)
		}
		// The crux: a missing key must NOT downgrade posture.
		if got := a.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
			t.Errorf("posture = %q, want %q (missing key must NOT downgrade)", got, models.PostureSymmetricOnly)
		}
	})

	t.Run("GetCluster failure yields honest unknown custody, never AWS-owned", func(t *testing.T) {
		// A describe FAILURE proves nothing about custody: the cluster may use a
		// customer CMK the scanner role cannot read. Asserting AWS_OWNED_KMS_KEY
		// would fabricate a "no customer CMK" verdict, so custody must be
		// recorded as undetermined — with posture still SymmetricOnly (no opt-out).
		a := classifyDocumentDBElasticCluster(acct, reg, arn, name, "", true)
		if got := a.Properties["kmsKeyId"]; got != "UNRESOLVED" {
			t.Errorf("kmsKeyId = %q, want UNRESOLVED (describe failed; custody never observed)", got)
		}
		if got := a.Properties["keyTier"]; got != "unknown" {
			t.Errorf("keyTier = %q, want unknown", got)
		}
		if a.Properties["note"] == "" {
			t.Error("expected an honesty note on the describe-failure path, got empty")
		}
		if got := a.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
			t.Errorf("posture = %q, want %q (describe failure must NOT downgrade)", got, models.PostureSymmetricOnly)
		}
	})

	t.Run("AES at-rest / SymmetricOnly posture is always stamped", func(t *testing.T) {
		// Both the key-present and key-absent paths must carry the same
		// AES-256 at-rest crypto props and SymmetricOnly posture.
		for _, key := range []string{"arn:aws:kms:us-east-1:111122223333:key/abcd-1234", ""} {
			a := classifyDocumentDBElasticCluster(acct, reg, arn, name, key, false)
			if got := a.Properties["posture"]; got != string(models.PostureSymmetricOnly) {
				t.Errorf("kmsKeyId=%q: posture = %q, want %q", key, got, models.PostureSymmetricOnly)
			}
			ap := a.CryptoProps.AlgorithmProperties
			if ap == nil {
				t.Fatalf("kmsKeyId=%q: AlgorithmProperties = nil, want AES-256 at-rest", key)
			}
			if ap.AlgorithmName != "AES-256" {
				t.Errorf("kmsKeyId=%q: AlgorithmName = %q, want AES-256", key, ap.AlgorithmName)
			}
			if ap.NistQuantumSecurityLevel != 5 {
				t.Errorf("kmsKeyId=%q: NistQuantumSecurityLevel = %d, want 5 (AES-256 anchors NIST Category 5)", key, ap.NistQuantumSecurityLevel)
			}
		}
	})

	t.Run("empty clusterName is omitted", func(t *testing.T) {
		a := classifyDocumentDBElasticCluster(acct, reg, arn, "", "", false)
		if _, ok := a.Properties["clusterName"]; ok {
			t.Errorf("clusterName property present for empty name, want omitted")
		}
	})
}
