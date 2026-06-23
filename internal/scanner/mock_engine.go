package scanner

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/aws-samples/cryptamap/internal/compliance"
	"github.com/aws-samples/cryptamap/internal/mock"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// RunMock generates a synthetic ScanResult bypassing all AWS API calls.
// Used by --mock for end-to-end pipeline validation.
func RunMock(ctx context.Context, accountID, region string, scale int, comp *compliance.Registry, e *Engine) models.ScanResult {
	g := mock.Generator{
		AccountID: accountID,
		Region:    region,
		Scale:     scale,
		Seed:      time.Now().UnixNano(),
	}
	assets := g.GenerateAssets()
	startedAt := time.Now().UTC().Add(-time.Second)
	completedAt := time.Now().UTC()

	if e == nil {
		e = NewEngine(NewRegistry(), comp, EngineOptions{ToolVersion: "1.0.0"})
	}
	if e.Compliance == nil {
		e.Compliance = comp
	}

	findings := e.buildFindings(assets)
	summary := e.buildSummary(assets, findings, len(mock.Templates()))

	return models.ScanResult{
		ScanID:      uuid.NewString(),
		AccountID:   accountID,
		Region:      region,
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		Mode:        "mock",
		Summary:     summary,
		Assets:      assets,
		Findings:    findings,
		ToolVersion: e.Opts.ToolVersion,
	}
}
