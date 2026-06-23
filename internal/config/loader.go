package config

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

var envVarRE = regexp.MustCompile(`\$\{([A-Z0-9_]+)\}`)

// Default returns sensible defaults aligned with the spec.
func Default() *Config {
	return &Config{
		Version: "1.0",
		Scan: ScanConfig{
			Mode:    "on-demand",
			Regions: []string{},
			Concurrency: Concurrency{
				MaxGoroutines: 50,
			},
			RateLimiting: RateLimiting{
				MaxRetries:  5,
				BaseDelayMs: 100,
				MaxDelayMs:  30000,
				Jitter:      true,
			},
		},
		Output: OutputConfig{
			S3: S3Output{
				Enabled:    true,
				BucketName: "cryptamap-results-${AWS_ACCOUNT_ID}",
				Prefix:     "scans/",
			},
			DynamoDB: DynamoDBOutput{
				Enabled:        true,
				TableName:      "CryptaMapScans",
				RetentionScans: 30,
			},
			SecurityHub: SecurityHubOutput{
				ProductARN: "arn:aws:securityhub:${REGION}:${ACCOUNT}:product/${ACCOUNT}/default",
			},
			Formats: OutputFormats{
				CycloneDX: true,
				PQCCExcel: true,
				ASFF:      true,
				Roadmap:   true,
				HTML:      true,
			},
			LocalDir: "./dist/scan-output",
		},
		Risk: RiskConfig{
			Mosca: MoscaConfig{
				Defaults: MoscaDefaults{
					DataShelfLifeYears:  7,
					MigrationTimeYears:  2,
					ThreatTimelineYears: 3,
				},
				Overrides: map[string]MoscaDefaults{},
			},
			SeverityMapping: map[string]string{
				"no_encryption":     "CRITICAL",
				"legacy_tls":        "HIGH",
				"non_pqc_classical": "MEDIUM",
				"pqc_ready":         "INFORMATIONAL",
			},
		},
		Compliance: ComplianceConfig{
			Frameworks: []string{
				"SEBI_CSCRF", "RBI_BANK_IN", "IRDAI_ICSG",
				"CISA_M2302", "MITRE_PQCC", "CNSA_2_0", "EU_NIS2_DORA",
				"CANADA_PQC", "EUROPOL_QSFF",
			},
		},
		Mock: MockConfig{
			Enabled: false,
			Scale: MockScale{
				Accounts:            3,
				RegionsPerAccount:   4,
				ResourcesPerService: 20,
			},
		},
		Dashboard: DashboardConfig{
			Auth: DashboardAuth{
				CognitoEnabled: true,
			},
		},
	}
}

// Load reads a YAML config file. If the path is empty, returns Default().
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	expanded := expandEnv(string(data))
	if err := yaml.Unmarshal([]byte(expanded), cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}

// expandEnv expands ${VAR} references in YAML content.
func expandEnv(s string) string {
	return envVarRE.ReplaceAllStringFunc(s, func(m string) string {
		name := m[2 : len(m)-1]
		if v, ok := os.LookupEnv(name); ok {
			return v
		}
		return m
	})
}

// ApplyOverrides applies CLI overrides onto the loaded config.
type CLIOverrides struct {
	Regions     []string
	Accounts    []string
	OrgScanning *bool
	Mock        *bool
	MockScale   *int
	OutputDir   string
	Profile     string
	Verbose     *bool
}

func (c *Config) Apply(o CLIOverrides) {
	if len(o.Regions) > 0 {
		c.Scan.Regions = o.Regions
	}
	if len(o.Accounts) > 0 {
		c.Scan.Accounts = o.Accounts
	}
	if o.OrgScanning != nil {
		c.Scan.OrgScanning.Enabled = *o.OrgScanning
	}
	if o.Mock != nil {
		c.Mock.Enabled = *o.Mock
	}
	if o.MockScale != nil {
		c.Mock.Scale.ResourcesPerService = *o.MockScale
	}
	if o.OutputDir != "" {
		c.Output.LocalDir = o.OutputDir
	}
	if o.Profile != "" {
		c.Scan.Profile = o.Profile
	}
}
