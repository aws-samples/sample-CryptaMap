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

type ScanConfig struct {
	Mode         string       `yaml:"mode"`
	Regions      []string     `yaml:"regions"`
	Accounts     []string     `yaml:"accounts"`
	OrgScanning  OrgScanning  `yaml:"org_scanning"`
	Concurrency  Concurrency  `yaml:"concurrency"`
	RateLimiting RateLimiting `yaml:"rate_limiting"`
	Profile      string       `yaml:"profile"`
}

type OrgScanning struct {
	Enabled             bool   `yaml:"enabled"`
	RoleName            string `yaml:"role_name"`
	ManagementAccountID string `yaml:"management_account_id"`
	ExternalID          string `yaml:"external_id"`
}

type Concurrency struct {
	MaxGoroutines int `yaml:"max_goroutines"`
}

type RateLimiting struct {
	MaxRetries  int  `yaml:"max_retries"`
	BaseDelayMs int  `yaml:"base_delay_ms"`
	MaxDelayMs  int  `yaml:"max_delay_ms"`
	Jitter      bool `yaml:"jitter"`
}

type OutputConfig struct {
	S3          S3Output          `yaml:"s3"`
	DynamoDB    DynamoDBOutput    `yaml:"dynamodb"`
	SecurityHub SecurityHubOutput `yaml:"security_hub"`
	Formats     OutputFormats     `yaml:"formats"`
	LocalDir    string            `yaml:"local_dir"`
}

type S3Output struct {
	Enabled    bool   `yaml:"enabled"`
	BucketName string `yaml:"bucket_name"`
	Prefix     string `yaml:"prefix"`
}

type DynamoDBOutput struct {
	Enabled        bool   `yaml:"enabled"`
	TableName      string `yaml:"table_name"`
	RetentionScans int    `yaml:"retention_scans"`
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
