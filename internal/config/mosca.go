package config

import "github.com/aws-samples/cryptamap/internal/risk"

// MoscaOverrideParams converts the YAML-facing risk.mosca.overrides map into
// the per-service risk.MoscaParams map consumed by the scanner engine
// (scanner.EngineOptions.MoscaOverrides -> BuildFindings ->
// risk.CalculateForService). Field mapping:
//
//	data_shelf_life_years  -> MoscaParams.X (data shelf-life)
//	migration_time_years   -> MoscaParams.Y (migration time)
//	threat_timeline_years  -> MoscaParams.Z (CRQC threat horizon)
//
// Zero-value rule (documented contract):
//   - A fully-zero override entry (all three fields absent or 0) is meaningless
//     — it would zero out the service's Mosca score — so it is SKIPPED and the
//     built-in per-service defaults apply unchanged.
//   - A partially-set entry overrides ONLY the fields the operator set (> 0);
//     each unset/non-positive field falls back to that service's built-in
//     default (risk.DefaultParams), so overriding just data_shelf_life_years
//     does not silently clobber Y and Z to zero.
//
// Returns nil when there is nothing to override, so callers can pass the
// result straight into EngineOptions.MoscaOverrides (nil == use defaults).
func (c *Config) MoscaOverrideParams() map[string]risk.MoscaParams {
	src := c.Risk.Mosca.Overrides
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]risk.MoscaParams, len(src))
	for service, o := range src {
		if o == (MoscaDefaults{}) {
			// Fully-zero override: meaningless, keep built-in defaults.
			continue
		}
		p := risk.DefaultParams(service)
		if o.DataShelfLifeYears > 0 {
			p.X = o.DataShelfLifeYears
		}
		if o.MigrationTimeYears > 0 {
			p.Y = o.MigrationTimeYears
		}
		if o.ThreatTimelineYears > 0 {
			p.Z = o.ThreatTimelineYears
		}
		out[service] = p
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
