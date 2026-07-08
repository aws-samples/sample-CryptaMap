package models

import "time"

// ScanSummary aggregates counts for one ScanResult.
type ScanSummary struct {
	TotalAssets   int `json:"totalAssets"`
	TotalFindings int `json:"totalFindings"`
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Informational int `json:"informational"`
	// InventoryOnly counts assets that are recorded for inventory completeness
	// but are deliberately NOT emitted as Findings: quantum-resistant-at-rest
	// (symmetric AES-256, PostureSymmetricOnly) is not a PQC-migration item, so it
	// stays in the CBOM as a line item and is counted here, but never inflates the
	// finding/severity buckets or the headline number. Without this count, the
	// symmetric-only assets removed from the finding stream would vanish silently.
	InventoryOnly int `json:"inventoryOnly"`
	ServiceCount  int `json:"serviceCount"`
}

// ServiceScanReport captures per-service stats for observability.
type ServiceScanReport struct {
	Service    string   `json:"service"`
	AssetCount int      `json:"assetCount"`
	Errors     []string `json:"errors,omitempty"`
	DurationMS int64    `json:"durationMs"`
}

// ScanResult is the top-level output of a scan, prior to format conversion.
type ScanResult struct {
	ScanID       string              `json:"scanId"`
	AccountID    string              `json:"accountId"`
	Region       string              `json:"region"`
	StartedAt    time.Time           `json:"startedAt"`
	CompletedAt  time.Time           `json:"completedAt"`
	Mode         string              `json:"mode"` // live | mock
	Summary      ScanSummary         `json:"summary"`
	Assets       []CryptoAsset       `json:"assets"`
	Findings     []Finding           `json:"findings"`
	ServiceStats []ServiceScanReport `json:"serviceStats,omitempty"`
	ToolVersion  string              `json:"toolVersion"`
	// Coverage, when non-nil, carries org-merge completion state so the emitted
	// CBOM/roadmap can stamp it into their metadata. Absent (nil) for a single
	// live scan, whose coverage question is trivially "just this shard"; the CBOM
	// writer only emits the incompleteness properties when this is set.
	Coverage *MergeCoverage `json:"coverage,omitempty"`
}

// MergeCoverage records the org-merge completion barrier so a consumer handed
// only the merged CBOM (not the side-car summary JSON) can distinguish a
// partial-coverage org scan from a clean one. It mirrors the loud-incomplete
// fields of the merge summary; the CBOM writer stamps these into
// metadata.properties as cryptamap:incomplete / expectedShards / observedShards
// / missingShards / failedShardCount.
type MergeCoverage struct {
	Complete       bool `json:"complete"`
	Incomplete     bool `json:"incomplete"`
	ExpectedShards int  `json:"expectedShards"`
	ObservedShards int  `json:"observedShards"`
	MissingShards  int  `json:"missingShards"`
	FailedShards   int  `json:"failedShards"`
}

// MultiScanResult bundles per-account/region results produced by an org scan.
type MultiScanResult struct {
	OrchestratorAccountID string       `json:"orchestratorAccountId"`
	StartedAt             time.Time    `json:"startedAt"`
	CompletedAt           time.Time    `json:"completedAt"`
	Scans                 []ScanResult `json:"scans"`
	TotalAccounts         int          `json:"totalAccounts"`
	TotalRegions          int          `json:"totalRegions"`
}
