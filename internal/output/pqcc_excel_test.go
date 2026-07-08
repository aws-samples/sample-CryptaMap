package output

import (
	"bytes"
	"testing"

	"github.com/xuri/excelize/v2"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestPQCCFrameworkListDeterministic asserts the "Additional Notes" framework
// list is emitted in sorted order regardless of map iteration order — this
// evidence workbook must be byte-deterministic so two scans of the same state
// diff cleanly (a stated project invariant). Repeated iterations make a
// map-order-dependent implementation fail with overwhelming probability.
func TestPQCCFrameworkListDeterministic(t *testing.T) {
	scan := models.ScanResult{
		Findings: []models.Finding{{
			ResourceID:  "my-bucket",
			Title:       "t",
			Description: "d",
			Severity:    models.SeverityHigh,
			Compliance: []models.ComplianceMapping{
				{Framework: "SEBI-CSCRF", ControlID: "A", Status: "non-compliant"},
				{Framework: "RBI", ControlID: "B", Status: "non-compliant"},
				{Framework: "IRDAI", ControlID: "C", Status: "non-compliant"},
			},
		}},
	}
	const want = "IRDAI, RBI, SEBI-CSCRF"
	for i := 0; i < 8; i++ {
		var buf bytes.Buffer
		if err := WritePQCCExcel(&buf, scan, PQCCOptions{}); err != nil {
			t.Fatalf("WritePQCCExcel: %v", err)
		}
		f, err := excelize.OpenReader(bytes.NewReader(buf.Bytes()))
		if err != nil {
			t.Fatalf("open workbook: %v", err)
		}
		// "Additional Notes" is column 17 (Q) per PQCCHeaders; data starts row 2.
		got, err := f.GetCellValue(PQCCSheetBaselineInventory, "Q2")
		f.Close()
		if err != nil {
			t.Fatalf("GetCellValue Q2: %v", err)
		}
		if got != want {
			t.Fatalf("iteration %d: framework list %q, want sorted %q", i, got, want)
		}
	}
}

func TestSanitizeCell(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"hyperlink formula", "=HYPERLINK(\"http://evil\",\"click\")", "'=HYPERLINK(\"http://evil\",\"click\")"},
		{"plus", "+1+1", "'+1+1"},
		{"minus", "-2+3", "'-2+3"},
		{"at", "@SUM(A1)", "'@SUM(A1)"},
		{"tab", "\tfoo", "'\tfoo"},
		{"carriage return", "\rfoo", "'\rfoo"},
		{"benign resource id", "arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeCell(tc.in); got != tc.want {
				t.Errorf("sanitizeCell(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
