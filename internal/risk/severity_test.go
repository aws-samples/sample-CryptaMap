package risk

import (
	"testing"

	"github.com/aws-samples/cryptamap/pkg/models"
)

func TestIsQuantumResistantPosture(t *testing.T) {
	cases := []struct {
		posture models.CryptoPosture
		want    bool
	}{
		{models.PostureSymmetricOnly, true},
		{models.PosturePQCHybrid, true},
		{models.PosturePQCReady, true},
		{models.PostureNoEncryption, false},
		{models.PostureLegacyTLS, false},
		{models.PostureNonPQCClassical, false},
		{models.PostureUnknown, false},
	}
	for _, tc := range cases {
		if got := IsQuantumResistantPosture(tc.posture); got != tc.want {
			t.Errorf("IsQuantumResistantPosture(%s) = %v, want %v", tc.posture, got, tc.want)
		}
	}
}

// TestPostureUnknownFailsSafe locks the B1 fail-safe contract: an undetermined
// posture ("needs investigation") must map to a non-clean severity (MEDIUM) and
// must NEVER be treated as INFORMATIONAL/clean or as quantum-resistant. This is
// an explicit case in SeverityFromPosture (not a silent default fall-through) so
// it cannot regress into a clean verdict by accident.
func TestPostureUnknownFailsSafe(t *testing.T) {
	if got := SeverityFromPosture(models.PostureUnknown); got != models.SeverityMedium {
		t.Errorf("SeverityFromPosture(unknown) = %s, want MEDIUM (needs investigation, never clean)", got)
	}
	if got := SeverityFromPosture(models.PostureUnknown); got == models.SeverityInformational {
		t.Error("unknown posture must NEVER be INFORMATIONAL/clean")
	}
	if IsQuantumResistantPosture(models.PostureUnknown) {
		t.Error("unknown posture must NEVER be classified quantum-resistant")
	}
}
