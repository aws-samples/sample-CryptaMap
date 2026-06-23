package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/xuri/excelize/v2"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestValidatePQCCWorkbook_RealEmittedWorkbookConforms is the positive teeth:
// it generates the REAL workbook from a representative deterministic scan (the
// same e2e mock pipeline every other output test drives) via WritePQCCExcel, then
// runs ValidatePQCCWorkbook over the emitted bytes and requires ZERO violations.
// If the writer ever drifts from the canonical PQCCHeaders / controlled-vocab
// contract, this fails — the programmatic replacement for the prior manual header
// check.
func TestValidatePQCCWorkbook_RealEmittedWorkbookConforms(t *testing.T) {
	scan := e2eScanResult(t)

	// Inject the same formula-injection probe the e2e test uses, so we prove the
	// quote-prefixed sanitized free-text cells do NOT trip the contract validator
	// (sanitization is the writer's job; validation must tolerate the result).
	scan.Findings = append(scan.Findings, models.Finding{
		ID:          "probe",
		Title:       "synthetic formula-injection probe",
		Description: "regression probe",
		Severity:    models.SeverityHigh,
		Posture:     models.PostureNonPQCClassical,
		AccountID:   scan.AccountID,
		Region:      scan.Region,
		Service:     "s3",
		ResourceID:  `=HYPERLINK("http://evil","click")`,
		Mosca:       models.MoscaScore{Score: 5},
		CreatedAt:   scan.CompletedAt,
		UpdatedAt:   scan.CompletedAt,
	})

	var buf bytes.Buffer
	if err := WritePQCCExcel(&buf, scan, PQCCOptions{OwnerName: "Test Owner"}); err != nil {
		t.Fatalf("WritePQCCExcel: %v", err)
	}

	if err := ValidatePQCCWorkbook(buf.Bytes()); err != nil {
		t.Fatalf("real emitted PQCC workbook FAILED canonical-contract validation: %v", err)
	}
}

// makeWorkbook builds a minimal Baseline Inventory workbook from explicit rows so
// the negative tests can author precise violations. rows[0] should be the header.
func makeWorkbook(t *testing.T, rows [][]interface{}) []byte {
	t.Helper()
	f := excelize.NewFile()
	defer f.Close()
	if err := f.SetSheetName("Sheet1", PQCCSheetBaselineInventory); err != nil {
		t.Fatalf("SetSheetName: %v", err)
	}
	for i, row := range rows {
		cell, _ := excelize.CoordinatesToCellName(1, i+1)
		r := row // copy for &
		if err := f.SetSheetRow(PQCCSheetBaselineInventory, cell, &r); err != nil {
			t.Fatalf("SetSheetRow: %v", err)
		}
	}
	var buf bytes.Buffer
	if _, err := f.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	return buf.Bytes()
}

// canonicalHeaderRow returns the exact canonical header as an interface row.
func canonicalHeaderRow() []interface{} {
	h := make([]interface{}, len(PQCCHeaders))
	for i, s := range PQCCHeaders {
		h[i] = s
	}
	return h
}

// validDataRow returns a full-width data row with in-vocab controlled values.
func validDataRow() []interface{} {
	row := make([]interface{}, len(PQCCHeaders))
	for i := range row {
		row[i] = "x"
	}
	row[pqccColAssetPQCNeeds] = PQCCAssetPQCNeedsValues[0]
	row[pqccColAssetPriority] = PQCCAssetPriorityValues[0]
	return row
}

// TestValidatePQCCWorkbook_RejectsBadHeader proves the validator has teeth on the
// header contract: a renamed column is rejected.
func TestValidatePQCCWorkbook_RejectsBadHeader(t *testing.T) {
	hdr := canonicalHeaderRow()
	hdr[0] = "Entry Identifier" // renamed first column
	raw := makeWorkbook(t, [][]interface{}{hdr, validDataRow()})

	err := ValidatePQCCWorkbook(raw)
	if err == nil {
		t.Fatal("expected rejection of a workbook with a renamed header column, got nil")
	}
	if !strings.Contains(err.Error(), "header column 1") {
		t.Errorf("error should name the offending header column; got: %v", err)
	}
}

// TestValidatePQCCWorkbook_RejectsMissingHeader proves a dropped column (wrong
// column COUNT) is rejected.
func TestValidatePQCCWorkbook_RejectsMissingHeader(t *testing.T) {
	full := canonicalHeaderRow()
	short := full[:len(full)-1] // drop the last header column
	raw := makeWorkbook(t, [][]interface{}{short})

	err := ValidatePQCCWorkbook(raw)
	if err == nil {
		t.Fatal("expected rejection of a workbook missing a header column, got nil")
	}
	if !strings.Contains(err.Error(), "columns, want") {
		t.Errorf("error should report the column-count mismatch; got: %v", err)
	}
}

// TestValidatePQCCWorkbook_RejectsWrongCellCount proves a data row with MORE cells
// than the header set (overflow columns / misalignment) is rejected.
func TestValidatePQCCWorkbook_RejectsWrongCellCount(t *testing.T) {
	over := validDataRow()
	over = append(over, "overflow-extra-cell") // one column past the header set
	raw := makeWorkbook(t, [][]interface{}{canonicalHeaderRow(), over})

	err := ValidatePQCCWorkbook(raw)
	if err == nil {
		t.Fatal("expected rejection of a data row with too many cells, got nil")
	}
	if !strings.Contains(err.Error(), "cells, want") {
		t.Errorf("error should report the cell-count mismatch; got: %v", err)
	}
}

// TestValidatePQCCWorkbook_RejectsShortRowDroppingControlledColumn proves a row
// truncated before a controlled-vocab column (leaving that column unaligned/empty)
// is rejected — excelize drops trailing empties, so this guards that path.
func TestValidatePQCCWorkbook_RejectsShortRowDroppingControlledColumn(t *testing.T) {
	// Only fill up to (but not including) the Asset PQC Needs column.
	short := make([]interface{}, pqccColAssetPQCNeeds)
	for i := range short {
		short[i] = "x"
	}
	raw := makeWorkbook(t, [][]interface{}{canonicalHeaderRow(), short})

	err := ValidatePQCCWorkbook(raw)
	if err == nil {
		t.Fatal("expected rejection of a short row missing a controlled column, got nil")
	}
	if !strings.Contains(err.Error(), "controlled-vocabulary column is missing") {
		t.Errorf("error should flag the missing controlled column; got: %v", err)
	}
}

// TestValidatePQCCWorkbook_RejectsOutOfVocabNeeds proves an out-of-vocabulary
// value in the "Asset PQC Needs" dropdown column is rejected.
func TestValidatePQCCWorkbook_RejectsOutOfVocabNeeds(t *testing.T) {
	bad := validDataRow()
	bad[pqccColAssetPQCNeeds] = "Probably Fine" // not in the controlled set
	raw := makeWorkbook(t, [][]interface{}{canonicalHeaderRow(), bad})

	err := ValidatePQCCWorkbook(raw)
	if err == nil {
		t.Fatal("expected rejection of an out-of-vocab Asset PQC Needs value, got nil")
	}
	if !strings.Contains(err.Error(), "Probably Fine") || !strings.Contains(err.Error(), "Asset PQC Needs") {
		t.Errorf("error should name the bad value and column; got: %v", err)
	}
}

// TestValidatePQCCWorkbook_RejectsOutOfVocabPriority proves an out-of-vocabulary
// value in the "Asset Priority" dropdown column is rejected.
func TestValidatePQCCWorkbook_RejectsOutOfVocabPriority(t *testing.T) {
	bad := validDataRow()
	bad[pqccColAssetPriority] = "Urgent" // not High/Medium/Low
	raw := makeWorkbook(t, [][]interface{}{canonicalHeaderRow(), bad})

	err := ValidatePQCCWorkbook(raw)
	if err == nil {
		t.Fatal("expected rejection of an out-of-vocab Asset Priority value, got nil")
	}
	if !strings.Contains(err.Error(), "Urgent") || !strings.Contains(err.Error(), "Asset Priority") {
		t.Errorf("error should name the bad value and column; got: %v", err)
	}
}

// TestValidatePQCCWorkbook_RejectsMissingSheet proves a workbook without the
// Baseline Inventory sheet is rejected.
func TestValidatePQCCWorkbook_RejectsMissingSheet(t *testing.T) {
	f := excelize.NewFile()
	defer f.Close()
	var buf bytes.Buffer
	if _, err := f.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	err := ValidatePQCCWorkbook(buf.Bytes())
	if err == nil {
		t.Fatal("expected rejection of a workbook missing the Baseline Inventory sheet, got nil")
	}
	if !strings.Contains(err.Error(), PQCCSheetBaselineInventory) {
		t.Errorf("error should name the missing sheet; got: %v", err)
	}
}
