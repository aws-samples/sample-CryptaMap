package risk

import (
	"testing"

	"github.com/aws-samples/cryptamap/pkg/models"
)

func TestIsQuantumSafePosture(t *testing.T) {
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
		if got := IsQuantumSafePosture(tc.posture); got != tc.want {
			t.Errorf("IsQuantumSafePosture(%s) = %v, want %v", tc.posture, got, tc.want)
		}
	}
}
