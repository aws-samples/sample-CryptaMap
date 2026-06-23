package output

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/xuri/excelize/v2"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// PQCCSheetBaselineInventory is the worksheet name carrying the per-asset
// inventory rows that ValidatePQCCWorkbook checks against the canonical contract.
const PQCCSheetBaselineInventory = "Baseline Inventory"

// PQCCHeaders is the canonical MITRE/PQCC Inventory Workbook column set, VERBATIM
// and IN ORDER from the official template (pqcc.org/pqc-inventory-workbook,
// "Example Inventory" header row). It is the SINGLE SOURCE OF TRUTH shared by the
// writer (WritePQCCExcel) and the validator (ValidatePQCCWorkbook): the writer
// emits exactly these columns in this order, and the validator asserts the
// emitted header row matches names + order + count. Do not reorder/rename without
// re-verifying against the authoritative workbook.
var PQCCHeaders = []string{
	"Entry ID", "Asset/System Short Name/ID", "Asset/System Type",
	"POC Name (Internal)", "POC Email", "POC Phone", "POC Org/Sub-Org(s)",
	"External Vendor Org", "External Vendor POC Name", "Vendor POC Email",
	"Asset PQC Needs", "PQC Status Notes", "Planned Disposition",
	"Disposition Date", "Asset Priority", "Asset Priority Notes",
	"Additional Notes", "Last Updated (Date)",
}

// pqccColAssetPQCNeeds / pqccColAssetPriority are the zero-based column indices
// (into PQCCHeaders) of the two dropdown-constrained columns, so the validator
// and writer agree on WHICH columns are controlled-vocabulary.
const (
	pqccColAssetPQCNeeds = 10 // "Asset PQC Needs"
	pqccColAssetPriority = 14 // "Asset Priority"
)

// PQCCAssetPQCNeedsValues is the controlled vocabulary for the "Asset PQC Needs"
// column, VERBATIM from the workbook's Spreadsheet Customizations sheet. Shared
// by pqccNeedsForSeverity (writer) and ValidatePQCCWorkbook (validator).
var PQCCAssetPQCNeedsValues = []string{
	"Needs Attention",
	"Unknown / May Need Attention",
	"Resolved / Doesn't Need Attention",
}

// PQCCAssetPriorityValues is the controlled vocabulary for the "Asset Priority"
// column (high / medium / low). Shared by pqccPriorityForSeverity (writer) and
// ValidatePQCCWorkbook (validator).
var PQCCAssetPriorityValues = []string{"High", "Medium", "Low"}

// PQCCOptions are user-supplied fields used by the MITRE PQCC Inventory Workbook.
type PQCCOptions struct {
	OwnerName    string
	OwnerEmail   string
	OwnerPhone   string
	OwnerOrgUnit string
	VendorOrg    string
	VendorPOC    string
	VendorEmail  string
}

// pqccDeadline maps a Mosca score to a planned disposition target date string.
// These are CryptaMap's own urgency-tiered planning targets (higher Mosca score
// → nearer target), NOT regulator-published deadlines: >= 7 → 2027, 4-6 → 2028,
// 1-3 → 2029, <= 0 → 2033.
func pqccDeadline(score int) string {
	switch {
	case score >= 7:
		return "2027-12-31"
	case score >= 4:
		return "2028-12-31"
	case score >= 1:
		return "2029-12-31"
	default:
		return "2033-12-31"
	}
}

// pqccNeedsForSeverity maps severity to the official MITRE/PQCC "Asset PQC Needs"
// controlled-vocabulary dropdown values (verbatim from the workbook's
// Spreadsheet Customizations sheet): "Needs Attention" /
// "Unknown / May Need Attention" / "Resolved / Doesn't Need Attention".
func pqccNeedsForSeverity(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return PQCCAssetPQCNeedsValues[0] // "Needs Attention"
	case models.SeverityMedium:
		return PQCCAssetPQCNeedsValues[1] // "Unknown / May Need Attention"
	case models.SeverityInformational:
		return PQCCAssetPQCNeedsValues[2] // "Resolved / Doesn't Need Attention"
	}
	return PQCCAssetPQCNeedsValues[1] // "Unknown / May Need Attention"
}

func pqccPriorityForSeverity(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return PQCCAssetPriorityValues[0] // "High"
	case models.SeverityMedium:
		return PQCCAssetPriorityValues[1] // "Medium"
	}
	return PQCCAssetPriorityValues[2] // "Low"
}

// WritePQCCExcel writes a MITRE PQCC Inventory Workbook to w.
func WritePQCCExcel(w io.Writer, scan models.ScanResult, opts PQCCOptions) error {
	f := excelize.NewFile()
	defer f.Close()

	// Default sheet -> Overview
	if err := f.SetSheetName("Sheet1", "Overview"); err != nil {
		return err
	}
	overview := [][]interface{}{
		{"MITRE PQCC Inventory Workbook (CryptaMap export)"},
		{"Generated", time.Now().UTC().Format(time.RFC3339)},
		{"CryptaMap version", scan.ToolVersion},
		{"Account", scan.AccountID},
		{"Region", scan.Region},
		{"Mode", scan.Mode},
		{"Total assets", scan.Summary.TotalAssets},
		{"Total findings", scan.Summary.TotalFindings},
		{"Critical", scan.Summary.Critical},
		{"High", scan.Summary.High},
		{"Medium", scan.Summary.Medium},
		{"Informational", scan.Summary.Informational},
	}
	for i, row := range overview {
		cell, _ := excelize.CoordinatesToCellName(1, i+1)
		f.SetSheetRow("Overview", cell, &row)
	}

	// Baseline Inventory sheet
	const sheet = PQCCSheetBaselineInventory
	idx, err := f.NewSheet(sheet)
	if err != nil {
		return err
	}
	f.SetActiveSheet(idx)

	// Header row is the canonical PQCCHeaders contract (VERBATIM from the official
	// MITRE/PQCC Inventory Workbook). PQCCHeaders is the single source of truth
	// shared with ValidatePQCCWorkbook; emit it verbatim so the validator and the
	// writer can never silently drift apart.
	header := make([]interface{}, len(PQCCHeaders))
	for i, h := range PQCCHeaders {
		header[i] = h
	}
	f.SetSheetRow(sheet, "A1", &header)

	scanTime := scan.CompletedAt.UTC().Format("2006-01-02")
	for i, finding := range scan.Findings {
		row := i + 2
		cell, _ := excelize.CoordinatesToCellName(1, row)
		fwSet := map[string]bool{}
		for _, c := range finding.Compliance {
			fwSet[c.Framework] = true
		}
		fwList := ""
		for fw := range fwSet {
			if fwList != "" {
				fwList += ", "
			}
			fwList += fw
		}
		vals := []interface{}{
			strconv.Itoa(i + 1),
			sanitizeCell(finding.ResourceID),
			"Cloud",
			sanitizeCell(opts.OwnerName),
			sanitizeCell(opts.OwnerEmail),
			sanitizeCell(opts.OwnerPhone),
			sanitizeCell(opts.OwnerOrgUnit),
			sanitizeCell(coalesce(opts.VendorOrg, "Amazon Web Services")),
			sanitizeCell(coalesce(opts.VendorPOC, "AWS Support")),
			sanitizeCell(opts.VendorEmail),
			pqccNeedsForSeverity(finding.Severity),
			sanitizeCell(fmt.Sprintf("%s — %s", finding.Title, finding.Description)),
			"Asset/system refresh",
			pqccDeadline(finding.Mosca.Score),
			pqccPriorityForSeverity(finding.Severity),
			sanitizeCell(finding.Mosca.Notes),
			sanitizeCell(fwList),
			scanTime,
		}
		f.SetSheetRow(sheet, cell, &vals)
	}

	// Glossary sheet — minimal PQCC algorithm vulnerability table.
	gIdx, err := f.NewSheet("Glossary")
	if err != nil {
		return err
	}
	_ = gIdx
	glossary := [][]interface{}{
		{"Algorithm", "Type", "Quantum Vulnerable", "PQC Replacement"},
		{"RSA", "Signature/KEM", "Yes", "ML-DSA / ML-KEM"},
		{"ECDSA", "Signature", "Yes", "ML-DSA"},
		{"ECDH / X25519", "Key Agreement", "Yes", "ML-KEM"},
		{"Ed25519", "Signature", "Yes", "ML-DSA"},
		{"DH", "Key Agreement", "Yes", "ML-KEM"},
		{"AES-128/192/256", "Symmetric (AE)", "No (Grover halves)", "AES-256 + KDF agility"},
		{"SHA-2 / SHA-3", "Hash", "No (Grover halves)", "Same family, longer output"},
		{"ML-DSA", "Signature", "No", "(target)"},
		{"ML-KEM", "Key Encapsulation", "No", "(target)"},
		{"SLH-DSA", "Signature", "No", "(target, hash-based)"},
	}
	for i, row := range glossary {
		cell, _ := excelize.CoordinatesToCellName(1, i+1)
		f.SetSheetRow("Glossary", cell, &row)
	}

	if _, err := f.WriteTo(w); err != nil {
		return err
	}
	return nil
}

func coalesce(s, def string) string {
	if s != "" {
		return s
	}
	return def
}

// sanitizeCell neutralizes CSV/Excel formula injection (OWASP) by prefixing a
// single quote when a scan-derived string begins with a formula-trigger rune
// (= + - @ TAB CR). Spreadsheet apps then treat the value as literal text
// instead of evaluating it as a formula. Applied to every untrusted string
// written into a cell; numeric/typed cells are left untouched.
func sanitizeCell(s string) string {
	if s == "" {
		return s
	}
	first := []rune(s)[0]
	if strings.ContainsRune("=+-@\t\r", first) {
		return "'" + s
	}
	return s
}
