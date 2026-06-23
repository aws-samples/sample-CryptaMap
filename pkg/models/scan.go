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
