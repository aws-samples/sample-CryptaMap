package risk

import (
	"fmt"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// Calculate runs Mosca's Theorem (Score = X + Y - Z) and returns a MoscaScore.
// A positive score means the asset will outlive the quantum threat horizon
// while still in service — i.e. HNDL exposure is active.
func Calculate(p MoscaParams) models.MoscaScore {
	score := p.X + p.Y - p.Z
	notes := fmt.Sprintf("X=%d (data shelf-life), Y=%d (migration time), Z=%d (CRQC threat horizon); Score=X+Y-Z=%d",
		p.X, p.Y, p.Z, score)
	return models.MoscaScore{
		X:     p.X,
		Y:     p.Y,
		Z:     p.Z,
		Score: score,
		Notes: notes,
	}
}

// CalculateForService returns Mosca for a given service identifier, applying overrides.
func CalculateForService(service string, overrides map[string]MoscaParams) models.MoscaScore {
	p := DefaultParams(service)
	if o, ok := overrides[service]; ok {
		p = o
	}
	return Calculate(p)
}
