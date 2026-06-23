package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// validASFFLabels is the closed enum BatchImportFindings accepts for
// Severity.Label (AWS Security Hub API Reference, Severity data type).
var validASFFLabels = map[string]bool{
	"INFORMATIONAL": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true,
}

func sampleASFFScan() models.ScanResult { //nolint:unused
	now := time.Date(2026, 6, 12, 0, 0, 0, 0, time.UTC)
	return models.ScanResult{
		AccountID: "111122223333",
		Region:    "ap-south-1",
		Findings: []models.Finding{
			{
				ID:           "abc-123",
				AccountID:    "111122223333",
				Region:       "ap-south-1",
				ResourceID:   "my-bucket",
				ResourceARN:  "arn:aws:s3:::my-bucket",
				ResourceType: "AwsS3Bucket",
				Title:        "S3 bucket uses RSA-2048 key wrapping",
				Description:  "The bucket default encryption uses an RSA-2048 KMS key, which is quantum-vulnerable.",
				Severity:     models.SeverityHigh,
				CreatedAt:    now,
				UpdatedAt:    now,
				Compliance: []models.ComplianceMapping{
					{Framework: "SEBI-CSCRF", ControlID: "BOX-ITEM-7", Status: "non-compliant"},
				},
			},
		},
	}
}

// TestASFFProductArnSubstitution proves the ${ACCOUNT}/${REGION} placeholders in
// the default ProductArn template are replaced with the finding's real
// account/region — the prior bug emitted the literal placeholders, which
// BatchImportFindings rejects (the account segment must equal AwsAccountId).
func TestASFFProductArnSubstitution(t *testing.T) {
	tmpl := "arn:aws:securityhub:${REGION}:${ACCOUNT}:product/${ACCOUNT}/default"
	findings := BuildASFFFindings(sampleASFFScan(), tmpl)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	got := findings[0].ProductARN
	want := "arn:aws:securityhub:ap-south-1:111122223333:product/111122223333/default"
	if got != want {
		t.Fatalf("ProductArn not expanded:\n got %q\nwant %q", got, want)
	}
	if strings.Contains(got, "${") {
		t.Fatalf("ProductArn still contains a placeholder: %q", got)
	}
	// The account segment must equal AwsAccountId (BatchImportFindings rule).
	if !strings.Contains(got, findings[0].AwsAccountID) {
		t.Fatalf("ProductArn account segment %q != AwsAccountId %q", got, findings[0].AwsAccountID)
	}
}

// TestASFFFieldLimits verifies every emitted finding respects the documented
// Security Hub BatchImportFindings field-length limits and enum constraints,
// including for pathologically long inputs (which must be clamped, not rejected).
func TestASFFFieldLimits(t *testing.T) {
	scan := sampleASFFScan()
	// Inject pathological lengths to exercise the truncation guards.
	scan.Findings[0].Title = strings.Repeat("T", 5000)
	scan.Findings[0].Description = strings.Repeat("D", 9000)
	scan.Findings[0].ResourceID = strings.Repeat("r", 1200)
	scan.Findings[0].ID = strings.Repeat("i", 2000)

	findings := BuildASFFFindings(scan, "arn:aws:securityhub:ap-south-1:111122223333:product/111122223333/default")
	f := findings[0]

	if n := len([]rune(f.Title)); n > asffMaxTitle {
		t.Errorf("Title len %d exceeds %d", n, asffMaxTitle)
	}
	if n := len([]rune(f.Description)); n > asffMaxDescription {
		t.Errorf("Description len %d exceeds %d", n, asffMaxDescription)
	}
	if n := len(f.ID); n > asffMaxID {
		t.Errorf("Id len %d exceeds %d", n, asffMaxID)
	}
	if len(f.Types) > asffMaxTypes {
		t.Errorf("Types len %d exceeds %d", len(f.Types), asffMaxTypes)
	}
	if !validASFFLabels[f.Severity.Label] {
		t.Errorf("Severity.Label %q not a valid ASFF enum value", f.Severity.Label)
	}
	if f.Severity.Normalized < 0 || f.Severity.Normalized > 100 {
		t.Errorf("Severity.Normalized %d out of 0-100 range", f.Severity.Normalized)
	}
}

// TestASFFTruncateIDUniqueness ensures two long ids sharing a prefix still map to
// distinct truncated ids (head slice + FNV hash suffix).
func TestASFFTruncateIDUniqueness(t *testing.T) {
	base := strings.Repeat("x", asffMaxID)
	a := asffTruncateID(base + "-alpha")
	b := asffTruncateID(base + "-bravo")
	if a == b {
		t.Fatalf("distinct long ids collided after truncation: %q == %q", a, b)
	}
	if len(a) > asffMaxID || len(b) > asffMaxID {
		t.Fatalf("truncated ids exceed limit: %d / %d", len(a), len(b))
	}
}

// TestASFFRequiredFields confirms every required top-level attribute is present
// TestASFFComplianceStatusMapping asserts every internal compliance status maps
// to the correct ASFF Compliance.Status enum value, with FAILED > WARNING >
// PASSED > NOT_AVAILABLE precedence. Regression guard for the bug where "partial"
// and "informational" silently collapsed to NOT_AVAILABLE.
func TestASFFComplianceStatusMapping(t *testing.T) {
	cases := []struct {
		name     string
		statuses []string
		want     string
	}{
		{"compliant->PASSED", []string{"compliant"}, "PASSED"},
		{"non-compliant->FAILED", []string{"non-compliant"}, "FAILED"},
		{"partial->WARNING", []string{"partial"}, "WARNING"},
		{"informational->NOT_AVAILABLE", []string{"informational"}, "NOT_AVAILABLE"},
		// India-framework readiness vocabulary must map too (else silent NOT_AVAILABLE).
		{"quantum-safe->PASSED", []string{"quantum-safe"}, "PASSED"},
		{"quantum-vulnerable->FAILED", []string{"quantum-vulnerable"}, "FAILED"},
		{"mixed readiness+mandate: vulnerable wins", []string{"quantum-safe", "quantum-vulnerable"}, "FAILED"},
		{"precedence: non-compliant beats partial+compliant", []string{"compliant", "partial", "non-compliant"}, "FAILED"},
		{"precedence: partial beats compliant", []string{"compliant", "partial"}, "WARNING"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := models.Finding{ResourceID: "r", Title: "t", Description: "d"}
			for _, s := range tc.statuses {
				f.Compliance = append(f.Compliance, models.ComplianceMapping{Framework: "RBI", ControlID: "X", Status: s})
			}
			got := BuildASFFFinding(f, "arn:aws:securityhub:ap-south-1:111122223333:product/111122223333/default")
			if got.Compliance.Status != tc.want {
				t.Errorf("statuses %v -> Compliance.Status %q, want %q", tc.statuses, got.Compliance.Status, tc.want)
			}
		})
	}
}

// and non-empty, and Compliance.Status maps to a valid enum.
func TestASFFRequiredFields(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteASFF(&buf, sampleASFFScan(), "arn:aws:securityhub:ap-south-1:111122223333:product/111122223333/default"); err != nil {
		t.Fatalf("WriteASFF: %v", err)
	}
	var findings []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &findings); err != nil {
		t.Fatalf("emitted ASFF is not valid JSON: %v", err)
	}
	required := []string{
		"SchemaVersion", "Id", "ProductArn", "GeneratorId", "AwsAccountId",
		"Types", "CreatedAt", "UpdatedAt", "Severity", "Title", "Description", "Resources",
	}
	for _, f := range findings {
		for _, k := range required {
			v, ok := f[k]
			if !ok || v == nil || v == "" {
				t.Errorf("required field %q missing/empty", k)
			}
		}
		if sv, _ := f["SchemaVersion"].(string); sv != "2018-10-08" {
			t.Errorf("SchemaVersion = %q, want 2018-10-08", sv)
		}
		if comp, ok := f["Compliance"].(map[string]any); ok {
			st, _ := comp["Status"].(string)
			switch st {
			case "PASSED", "WARNING", "FAILED", "NOT_AVAILABLE":
			default:
				t.Errorf("Compliance.Status %q not a valid enum", st)
			}
		}
	}
}
