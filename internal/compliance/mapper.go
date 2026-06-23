// Package compliance maps cryptographic findings to regulatory frameworks:
// SEBI CSCRF, RBI (.bank.in + Q-SAFE), IRDAI ICSG, CISA M-23-02, MITRE PQCC,
// CNSA 2.0, EU NIS2/DORA, Canada PQC Roadmap, Europol QSFF.
//
// The Indian-regulator mappers (SEBI/RBI/IRDAI) emit ControlID values that are
// CryptaMap's OWN mapping labels (prefixed "CryptaMap→"), never official
// regulator control codes — those regulators do not publish "CSCRF-*"/"RBI-*"/
// "IRDAI-CTRL-*" identifiers. Post-quantum framing for India is national
// (CERT-In CIWP-2025-0002), not a per-regulator mandate. See the per-mapper
// docs.
package compliance

import (
	"github.com/aws-samples/cryptamap/pkg/models"
)

// Framework identifiers (mirror config string IDs).
const (
	SEBI    = "SEBI_CSCRF"
	RBI     = "RBI_BANK_IN"
	IRDAI   = "IRDAI_ICSG"
	CISA    = "CISA_M2302"
	MITRE   = "MITRE_PQCC"
	CNSA    = "CNSA_2_0"
	NIS2    = "EU_NIS2_DORA"
	CANADA  = "CANADA_PQC"
	EUROPOL = "EUROPOL_QSFF"
)

// Mapper produces ComplianceMapping entries for one (asset, posture) pair.
type Mapper interface {
	ID() string
	Map(asset models.CryptoAsset, posture models.CryptoPosture) []models.ComplianceMapping
}

// Registry holds all enabled mappers.
type Registry struct {
	mappers []Mapper
}

// NewRegistry returns a Registry with all 9 default frameworks enabled.
func NewRegistry(enabled []string) *Registry {
	all := []Mapper{
		&SEBIMapper{},
		&RBIMapper{},
		&IRDAIMapper{},
		&CISAMapper{},
		&MITREMapper{},
		&CNSAMapper{},
		&NIS2DORAMapper{},
		&CanadaMapper{},
		&EuropolMapper{},
	}
	if len(enabled) == 0 {
		return &Registry{mappers: all}
	}
	want := map[string]bool{}
	for _, e := range enabled {
		want[e] = true
	}
	out := []Mapper{}
	for _, m := range all {
		if want[m.ID()] {
			out = append(out, m)
		}
	}
	return &Registry{mappers: out}
}

// MapAll returns all framework mappings for an asset.
func (r *Registry) MapAll(asset models.CryptoAsset, posture models.CryptoPosture) []models.ComplianceMapping {
	out := []models.ComplianceMapping{}
	for _, m := range r.mappers {
		out = append(out, m.Map(asset, posture)...)
	}
	return out
}

// statusFromPosture is the default compliance-status mapping for a posture. Use
// this ONLY for frameworks that publish an actual cryptographic/PQC obligation an
// asset can be "compliant" WITH (CISA M-23-02, NSA CNSA 2.0, EU NIS2/DORA, CCCS,
// Europol QSFF). For the Indian regulators (RBI/SEBI/IRDAI), which have NO PQC
// mandate today, use readinessFromPosture instead — asserting "compliant" there
// over-claims regulatory compliance with an obligation that does not yet exist.
func statusFromPosture(p models.CryptoPosture) string {
	switch p {
	case models.PostureNoEncryption, models.PostureLegacyTLS:
		return "non-compliant"
	case models.PostureNonPQCClassical:
		return "partial"
	case models.PosturePQCHybrid, models.PosturePQCReady, models.PostureSymmetricOnly:
		return "compliant"
	default:
		return "informational"
	}
}

// readinessFromPosture maps a posture to a non-regulatory PQC-READINESS status,
// for frameworks that do NOT (yet) impose a PQC obligation (RBI/SEBI/IRDAI). It
// deliberately avoids the words "compliant"/"non-compliant" — there is no mandate
// to be compliant with — and instead reports the asset's quantum-readiness as an
// evidence signal: "quantum-safe", "quantum-vulnerable", "partial", or
// "informational". This keeps the regulator-facing output honest (CryptaMap is an
// evidence tool, not a compliance certification).
func readinessFromPosture(p models.CryptoPosture) string {
	switch p {
	case models.PostureNoEncryption, models.PostureLegacyTLS:
		return "quantum-vulnerable"
	case models.PostureNonPQCClassical:
		return "partial"
	case models.PosturePQCHybrid, models.PosturePQCReady, models.PostureSymmetricOnly:
		return "quantum-safe"
	default:
		return "informational"
	}
}
