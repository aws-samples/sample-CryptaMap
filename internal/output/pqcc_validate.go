package output

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/xuri/excelize/v2"
)

// ValidatePQCCWorkbook parses the raw bytes of a CryptaMap-emitted MITRE PQCC
// Inventory Workbook (.xlsx) and asserts the "Baseline Inventory" sheet conforms
// to the canonical PQCC contract that consumers (and MITRE) expect:
//
//   - the header row matches PQCCHeaders EXACTLY — same names, same order, same
//     count (no extra/missing/reordered/renamed columns);
//   - every data row has exactly len(PQCCHeaders) cells aligned to the headers
//     (no short rows leaving a controlled column unaligned, no overflow columns);
//   - the two dropdown-constrained columns only carry values from their
//     controlled vocabularies (PQCCAssetPQCNeedsValues / PQCCAssetPriorityValues).
//
// It is the programmatic replacement for the prior one-time MANUAL header check,
// so the emitted workbook cannot silently drift from the documented format. It
// uses the SAME excel library as the writer (github.com/xuri/excelize/v2) and the
// SAME canonical vars the writer emits, so the writer and validator can never
// disagree about what "correct" is.
//
// Returned errors enumerate ALL violations found (one per line) so a caller/CI
// sees the complete picture in a single run rather than fixing-then-rediscovering.
//
// Formula-injection neutralization is the writer's responsibility (sanitizeCell)
// and is intentionally NOT re-checked here: the workbook stores quote-prefixed
// literals, which are valid controlled-vocab/free-text values from this layer's
// perspective.
func ValidatePQCCWorkbook(raw []byte) error {
	f, err := excelize.OpenReader(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("pqcc workbook is not an openable .xlsx: %w", err)
	}
	defer f.Close()

	if !sheetExists(f, PQCCSheetBaselineInventory) {
		return fmt.Errorf("pqcc workbook is missing the required %q sheet", PQCCSheetBaselineInventory)
	}

	rows, err := f.GetRows(PQCCSheetBaselineInventory)
	if err != nil {
		return fmt.Errorf("reading %q sheet: %w", PQCCSheetBaselineInventory, err)
	}
	if len(rows) == 0 {
		return fmt.Errorf("%q sheet is empty (no header row)", PQCCSheetBaselineInventory)
	}

	var violations []string

	// 1. Header row: exact names + order + count.
	header := rows[0]
	if len(header) != len(PQCCHeaders) {
		violations = append(violations, fmt.Sprintf(
			"header has %d columns, want %d (%v)", len(header), len(PQCCHeaders), PQCCHeaders))
	}
	for i, want := range PQCCHeaders {
		var got string
		if i < len(header) {
			got = header[i]
		}
		if got != want {
			violations = append(violations, fmt.Sprintf(
				"header column %d (%s) = %q, want %q",
				i+1, colLetter(i), got, want))
		}
	}

	// If the header is structurally wrong, the column-index assumptions for the
	// controlled-vocab checks below are unreliable; report header violations and
	// stop rather than emit a cascade of misaligned false positives.
	if len(violations) > 0 {
		return fmt.Errorf("pqcc workbook fails canonical contract:\n  - %s",
			strings.Join(violations, "\n  - "))
	}

	pqcNeeds := vocabSet(PQCCAssetPQCNeedsValues)
	priority := vocabSet(PQCCAssetPriorityValues)

	// 2 + 3. Per data row: cell count aligned to headers, controlled-vocab values.
	for r := 1; r < len(rows); r++ {
		row := rows[r]
		excelRow := r + 1 // 1-based row number in the sheet

		// excelize.GetRows drops trailing empty cells, so a row with len < headers
		// is only acceptable if the missing tail is genuinely empty. Conversely a
		// row with len > headers has overflow columns and is always a violation.
		// We canonicalize to a full-width slice so cell-count and per-column checks
		// are unambiguous, and separately flag true short/over rows.
		switch {
		case len(row) > len(PQCCHeaders):
			violations = append(violations, fmt.Sprintf(
				"row %d has %d cells, want %d (overflow columns beyond the header set)",
				excelRow, len(row), len(PQCCHeaders)))
			continue
		case len(row) < len(PQCCHeaders):
			// Short row: the dropped tail must be empty cells only. A controlled
			// column inside the dropped tail would be an unaligned/missing cell.
			if missesControlledColumn(len(row)) {
				violations = append(violations, fmt.Sprintf(
					"row %d has only %d cells, want %d — a controlled-vocabulary column is missing/unaligned",
					excelRow, len(row), len(PQCCHeaders)))
				continue
			}
		}

		needs := cellAt(row, pqccColAssetPQCNeeds)
		if !pqcNeeds[needs] {
			violations = append(violations, fmt.Sprintf(
				"row %d col %d (%s, %q) = %q, not in allowed set %v",
				excelRow, pqccColAssetPQCNeeds+1, colLetter(pqccColAssetPQCNeeds),
				PQCCHeaders[pqccColAssetPQCNeeds], needs, PQCCAssetPQCNeedsValues))
		}
		prio := cellAt(row, pqccColAssetPriority)
		if !priority[prio] {
			violations = append(violations, fmt.Sprintf(
				"row %d col %d (%s, %q) = %q, not in allowed set %v",
				excelRow, pqccColAssetPriority+1, colLetter(pqccColAssetPriority),
				PQCCHeaders[pqccColAssetPriority], prio, PQCCAssetPriorityValues))
		}
	}

	if len(violations) > 0 {
		return fmt.Errorf("pqcc workbook fails canonical contract (%d violation(s)):\n  - %s",
			len(violations), strings.Join(violations, "\n  - "))
	}
	return nil
}

// missesControlledColumn reports whether a row of the given length (cells present
// after excelize dropped trailing empties) is missing one of the controlled-vocab
// columns. Both controlled columns sit before the final header, so any short row
// that doesn't reach the later controlled column has an unaligned controlled cell.
func missesControlledColumn(rowLen int) bool {
	highest := pqccColAssetPQCNeeds
	if pqccColAssetPriority > highest {
		highest = pqccColAssetPriority
	}
	return rowLen <= highest
}

// cellAt returns the cell value at zero-based column i, or "" if the row is short
// (excelize drops trailing empties).
func cellAt(row []string, i int) string {
	if i < len(row) {
		return row[i]
	}
	return ""
}

func vocabSet(vals []string) map[string]bool {
	m := make(map[string]bool, len(vals))
	for _, v := range vals {
		m[v] = true
	}
	return m
}

func sheetExists(f *excelize.File, name string) bool {
	for _, s := range f.GetSheetList() {
		if s == name {
			return true
		}
	}
	return false
}

// colLetter renders a zero-based column index as its Excel column letter (0 -> A)
// for human-readable violation messages; falls back to the numeric index if the
// excelize helper errors.
func colLetter(i int) string {
	name, err := excelize.ColumnNumberToName(i + 1)
	if err != nil {
		return fmt.Sprintf("col#%d", i+1)
	}
	return name
}
