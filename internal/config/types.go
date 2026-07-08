// Package config loads CryptaMap YAML configuration.
package config

// Config is the root config struct.
type Config struct {
	Version    string           `yaml:"version"`
	Scan       ScanConfig       `yaml:"scan"`
	Output     OutputConfig     `yaml:"output"`
	Risk       RiskConfig       `yaml:"risk"`
	Compliance ComplianceConfig `yaml:"compliance"`
	Mock       MockConfig       `yaml:"mock"`
	Dashboard  DashboardConfig  `yaml:"dashboard"`
	Owner      OwnerInfo        `yaml:"owner"`
}

type OwnerInfo struct {
	Name      string `yaml:"name"`
	Email     string `yaml:"email"`
	Phone     string `yaml:"phone"`
	OrgUnit   string `yaml:"org_unit"`
	VendorPOC string `yaml:"vendor_poc"`
}

// ScanConfig holds CLI scan settings. NOTE: org-wide cross-account scanning is
// NOT configured here — the deployed Step Functions fan-out passes the scanner
// role/externalId in the Lambda event, and the CLI scan path is single-account.
type ScanConfig struct {
	Mode         string       `yaml:"mode"`
	Regions      []string     `yaml:"regions"`
	Accounts     []string     `yaml:"accounts"`
	Concurrency  Concurrency  `yaml:"concurrency"`
	RateLimiting RateLimiting `yaml:"rate_limiting"`
	Profile      string       `yaml:"profile"`
}

type Concurrency struct {
	MaxGoroutines int `yaml:"max_goroutines"`
}

// RateLimiting tunes the engine's transient-error retry backoff. Jitter is
// always applied by the engine and is not configurable.
type RateLimiting struct {
	MaxRetries  int `yaml:"max_retries"`
	BaseDelayMs int `yaml:"base_delay_ms"`
	MaxDelayMs  int `yaml:"max_delay_ms"`
}

// OutputConfig holds local artifact output settings. NOTE: the S3/DynamoDB
// evidence-store writers (Lambda fan-out path) are configured via the
// RESULTS_BUCKET / SCANS_TABLE / RETENTION_DAYS environment variables set by
// the CDK, not via this YAML config.
type OutputConfig struct {
	SecurityHub SecurityHubOutput `yaml:"security_hub"`
	Formats     OutputFormats     `yaml:"formats"`
	LocalDir    string            `yaml:"local_dir"`
}

// SecurityHubOutput holds the Security Hub ASFF product ARN stamped into the
// locally-written ASFF JSON findings. There is no live BatchImportFindings push
// path; ProductARN is consumed only by the local WriteASFF output.
type SecurityHubOutput struct {
	ProductARN string `yaml:"product_arn"`
}

type OutputFormats struct {
	CycloneDX bool `yaml:"cyclonedx"`
	PQCCExcel bool `yaml:"pqcc_excel"`
	PDF       bool `yaml:"pdf"`
	ASFF      bool `yaml:"asff"`
	Roadmap   bool `yaml:"roadmap"` // PQC migration roadmap (roadmap.json + roadmap.md)
	HTML      bool `yaml:"html"`    // self-contained offline single-file HTML evidence report
}

type RiskConfig struct {
	Mosca           MoscaConfig       `yaml:"mosca"`
	SeverityMapping map[string]string `yaml:"severity_mapping"`
}

type MoscaConfig struct {
	Defaults  MoscaDefaults            `yaml:"defaults"`
	Overrides map[string]MoscaDefaults `yaml:"overrides"`
}

type MoscaDefaults struct {
	DataShelfLifeYears  int `yaml:"data_shelf_life_years"`
	MigrationTimeYears  int `yaml:"migration_time_years"`
	ThreatTimelineYears int `yaml:"threat_timeline_years"`
}

type ComplianceConfig struct {
	Frameworks []string `yaml:"frameworks"`
}

type MockConfig struct {
	Enabled bool      `yaml:"enabled"`
	Scale   MockScale `yaml:"scale"`
}

type MockScale struct {
	Accounts            int `yaml:"accounts"`
	RegionsPerAccount   int `yaml:"regions_per_account"`
	ResourcesPerService int `yaml:"resources_per_service"`
}

type DashboardConfig struct {
	Auth DashboardAuth `yaml:"auth"`
}

type DashboardAuth struct {
	CognitoEnabled bool   `yaml:"cognito_enabled"`
	UserPoolID     string `yaml:"user_pool_id"`
	ClientID       string `yaml:"client_id"`
}
