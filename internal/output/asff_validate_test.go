package output

import (
	"bytes"
	"strings"
	"testing"
)

// TestValidateRealEmittedASFF feeds the REAL emitted ASFF (via WriteASFF over a
// representative scan) through ValidateASFFBytes and asserts zero violations.
// This is the contract-conformance gate analogous to ValidateCBOMBytes: if the
// emitter ever produces an ASFF that BatchImportFindings would reject, this fails.
func TestValidateRealEmittedASFF(t *testing.T) {
	var buf bytes.Buffer
	const tmpl = "arn:aws:securityhub:${REGION}:${ACCOUNT}:product/${ACCOUNT}/default"
	if err := WriteASFF(&buf, sampleASFFScan(), tmpl); err != nil {
		t.Fatalf("WriteASFF: %v", err)
	}
	if err := ValidateASFFBytes(buf.Bytes()); err != nil {
		t.Fatalf("real emitted ASFF violates the Security Hub contract:\n%v", err)
	}
}

// TestValidateRealEmittedASFFPathological proves the emitter's clamps keep the
// output contract-valid even for pathologically long / multi-region inputs — the
// validator must STILL pass, proving the clamps actually defend the contract.
func TestValidateRealEmittedASFFPathological(t *testing.T) {
	scan := sampleASFFScan()
	scan.Findings[0].Title = strings.Repeat("T", 5000)
	scan.Findings[0].Description = strings.Repeat("D", 9000)
	scan.Findings[0].ResourceID = strings.Repeat("r", 1200)
	scan.Findings[0].ResourceARN = ""
	scan.Findings[0].ID = strings.Repeat("i", 2000)

	var buf bytes.Buffer
	const tmpl = "arn:aws:securityhub:${REGION}:${ACCOUNT}:product/${ACCOUNT}/default"
	if err := WriteASFF(&buf, scan, tmpl); err != nil {
		t.Fatalf("WriteASFF: %v", err)
	}
	if err := ValidateASFFBytes(buf.Bytes()); err != nil {
		t.Fatalf("pathological emitted ASFF violates the contract (clamps failed):\n%v", err)
	}
}

// validASFFFinding returns a minimal contract-valid finding the negative tests
// mutate one field at a time, proving each rule has teeth in isolation.
func validASFFFinding() ASFFFinding {
	return ASFFFinding{
		SchemaVersion: "2018-10-08",
		ID:            "cryptamap/111122223333/ap-south-1/my-bucket/abc-123",
		ProductARN:    "arn:aws:securityhub:ap-south-1:111122223333:product/111122223333/default",
		GeneratorID:   "cryptamap-scanner-v1",
		AwsAccountID:  "111122223333",
		Types:         []string{"Software and Configuration Checks/Crypto/PostQuantumReadiness"},
		CreatedAt:     "2026-06-12T00:00:00Z",
		UpdatedAt:     "2026-06-12T00:00:00Z",
		Severity:      ASFFSeverity{Label: "HIGH", Normalized: 70},
		Title:         "S3 bucket uses RSA-2048 key wrapping",
		Description:   "quantum-vulnerable key wrapping",
		Resources:     []ASFFResource{{Type: "AwsS3Bucket", ID: "arn:aws:s3:::my-bucket"}},
		Compliance:    &ASFFCompliance{Status: "FAILED"},
		RecordState:   "ACTIVE",
	}
}

// TestValidateASFFFinding_Baseline confirms the hand-built valid finding passes,
// so the negative tests below isolate the mutated rule (not a latent defect).
func TestValidateASFFFinding_Baseline(t *testing.T) {
	if err := ValidateASFFFinding(validASFFFinding()); err != nil {
		t.Fatalf("baseline valid finding should pass, got: %v", err)
	}
}

// TestValidateASFFFinding_RejectsViolations proves the validator REJECTS each
// violation class — i.e. it has teeth. Each case mutates one field of an
// otherwise-valid finding and asserts a violation mentioning the right path.
func TestValidateASFFFinding_RejectsViolations(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*ASFFFinding)
		wantInErr string
	}{
		{"bad SchemaVersion", func(f *ASFFFinding) { f.SchemaVersion = "1999-01-01" }, "SchemaVersion"},
		{"missing Id", func(f *ASFFFinding) { f.ID = "" }, "Id"},
		{"oversize Id", func(f *ASFFFinding) { f.ID = strings.Repeat("x", asffMaxID+1) }, "Id"},
		{"missing ProductArn", func(f *ASFFFinding) { f.ProductARN = "" }, "ProductArn"},
		{"placeholder ProductArn", func(f *ASFFFinding) {
			f.ProductARN = "arn:aws:securityhub:${REGION}:${ACCOUNT}:product/${ACCOUNT}/default"
		}, "placeholder"},
		{"ProductArn account mismatch", func(f *ASFFFinding) {
			f.ProductARN = "arn:aws:securityhub:ap-south-1:999988887777:product/999988887777/default"
		}, "account segment"},
		{"missing GeneratorId", func(f *ASFFFinding) { f.GeneratorID = "" }, "GeneratorId"},
		{"bad AwsAccountId", func(f *ASFFFinding) { f.AwsAccountID = "12345" }, "AwsAccountId"},
		{"empty Types", func(f *ASFFFinding) { f.Types = nil }, "Types"},
		{"too-many Types segments", func(f *ASFFFinding) { f.Types = []string{"a/b/c/d"} }, "segments"},
		{"empty Types segment", func(f *ASFFFinding) { f.Types = []string{"a//c"} }, "segments"},
		{"missing CreatedAt", func(f *ASFFFinding) { f.CreatedAt = "" }, "CreatedAt"},
		{"bad CreatedAt format", func(f *ASFFFinding) { f.CreatedAt = "June 12 2026" }, "CreatedAt"},
		{"no-timezone timestamp", func(f *ASFFFinding) { f.UpdatedAt = "2026-06-12T00:00:00" }, "UpdatedAt"},
		{"bad Severity.Label", func(f *ASFFFinding) { f.Severity.Label = "SEVERE" }, "Severity.Label"},
		{"empty Severity.Label", func(f *ASFFFinding) { f.Severity.Label = "" }, "Severity.Label"},
		{"Severity.Normalized out of range", func(f *ASFFFinding) { f.Severity.Normalized = 500 }, "Severity.Normalized"},
		{"missing Title", func(f *ASFFFinding) { f.Title = "" }, "Title"},
		{"oversize Title", func(f *ASFFFinding) { f.Title = strings.Repeat("T", asffMaxTitle+1) }, "Title"},
		{"missing Description", func(f *ASFFFinding) { f.Description = "" }, "Description"},
		{"oversize Description", func(f *ASFFFinding) { f.Description = strings.Repeat("D", asffMaxDescription+1) }, "Description"},
		{"no Resources", func(f *ASFFFinding) { f.Resources = nil }, "Resources"},
		{"Resource missing Type", func(f *ASFFFinding) { f.Resources[0].Type = "" }, "Resources[0].Type"},
		{"Resource missing Id", func(f *ASFFFinding) { f.Resources[0].ID = "" }, "Resources[0].Id"},
		{"bad Compliance.Status", func(f *ASFFFinding) { f.Compliance.Status = "MAYBE" }, "Compliance.Status"},
		{"bad RecordState", func(f *ASFFFinding) { f.RecordState = "DELETED" }, "RecordState"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := validASFFFinding()
			tc.mutate(&f)
			err := ValidateASFFFinding(f)
			if err == nil {
				t.Fatalf("validator did NOT reject violation %q (no teeth)", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Fatalf("violation %q: error does not mention %q\n got: %v", tc.name, tc.wantInErr, err)
			}
		})
	}
}

// TestValidateASFFBytes_RejectsWireOnlyEnums proves the bytes-level validator
// catches invalid Workflow.Status / VerificationState that the typed emit struct
// does not carry — should they ever appear on the wire.
func TestValidateASFFBytes_RejectsWireOnlyEnums(t *testing.T) {
	cases := []struct {
		name      string
		json      string
		wantInErr string
	}{
		{
			"bad Workflow.Status",
			`{"SchemaVersion":"2018-10-08","Id":"x","ProductArn":"arn:aws:securityhub:ap-south-1:111122223333:product/111122223333/default","GeneratorId":"g","AwsAccountId":"111122223333","Types":["A/B"],"CreatedAt":"2026-06-12T00:00:00Z","UpdatedAt":"2026-06-12T00:00:00Z","Severity":{"Label":"HIGH","Normalized":70},"Title":"t","Description":"d","Resources":[{"Type":"AwsS3Bucket","Id":"arn:aws:s3:::b"}],"Workflow":{"Status":"BOGUS"}}`,
			"Workflow.Status",
		},
		{
			"bad VerificationState",
			`{"SchemaVersion":"2018-10-08","Id":"x","ProductArn":"arn:aws:securityhub:ap-south-1:111122223333:product/111122223333/default","GeneratorId":"g","AwsAccountId":"111122223333","Types":["A/B"],"CreatedAt":"2026-06-12T00:00:00Z","UpdatedAt":"2026-06-12T00:00:00Z","Severity":{"Label":"HIGH","Normalized":70},"Title":"t","Description":"d","Resources":[{"Type":"AwsS3Bucket","Id":"arn:aws:s3:::b"}],"VerificationState":"NOPE"}`,
			"VerificationState",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateASFFBytes([]byte(tc.json))
			if err == nil {
				t.Fatalf("validator did NOT reject %q", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Fatalf("%q: error does not mention %q\n got: %v", tc.name, tc.wantInErr, err)
			}
		})
	}
}
