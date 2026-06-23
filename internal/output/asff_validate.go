package output

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// This file provides a REUSABLE AWS Security Finding Format (ASFF) validator so
// that any package's tests can validate the ASFF their real scan() output
// produces against the documented Security Hub BatchImportFindings contract —
// the same machine-validation-against-an-external-contract that
// cdx_schema_validate.go already gives the CBOM. Without it, an emitted ASFF
// finding could silently violate the contract (a missing required field, an
// invalid enum, an over-length text field, a leftover ${...} placeholder ARN),
// be rejected by BatchImportFindings at import time, and never be caught by the
// hand-asserted field tests.
//
// The rules below are hand-coded against the documented constraints rather than
// a vendored JSON schema, for determinism and zero network dependency. Sources:
//   - Required top-level attributes:
//     https://docs.aws.amazon.com/securityhub/latest/userguide/asff-required-attributes.html
//   - ASFF syntax / enum members & field caps (AwsSecurityFinding, Severity,
//     Compliance, Workflow, Resource data types in the API Reference):
//     https://docs.aws.amazon.com/securityhub/latest/userguide/asff-syntax.html
//     https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_AwsSecurityFinding.html
//
// Documented constraints encoded here:
//   - REQUIRED non-empty: SchemaVersion(=="2018-10-08"), Id, ProductArn,
//     GeneratorId, AwsAccountId, Types(>=1), CreatedAt, UpdatedAt, Severity,
//     Title, Description, Resources(>=1, each Type+Id non-empty).
//   - ENUMs: Severity.Label, Compliance.Status, RecordState,
//     Workflow.Status (if present), VerificationState (if present).
//   - FORMAT/LENGTH: Id<=512, Title<=256, Description<=1024, GeneratorId<=512,
//     ProductArn<=512, Resources[].Id<=2048, Resources[].Type<=256;
//     CreatedAt/UpdatedAt ISO-8601/RFC3339 with timezone; AwsAccountId 12 digits;
//     ProductArn matches the private-product ARN pattern with no ${...}
//     placeholders; Types entries are 1-3 non-empty namespace/category/classifier
//     segments.

// ASFF documented field-length maxima (AWS Security Hub API Reference).
const (
	asffMaxGeneratorID  = 512  // GeneratorId
	asffMaxProductArn   = 512  // ProductArn
	asffMaxResourceID   = 2048 // Resources[].Id
	asffMaxResourceType = 256  // Resources[].Type
)

// Closed enum sets accepted by BatchImportFindings. Anything outside these is
// rejected. (asff-syntax.html + API Reference data types.)
var (
	asffSeverityLabels = map[string]bool{
		"INFORMATIONAL": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true,
	}
	asffComplianceStatuses = map[string]bool{
		"PASSED": true, "WARNING": true, "FAILED": true, "NOT_AVAILABLE": true,
	}
	asffRecordStates = map[string]bool{
		"ACTIVE": true, "ARCHIVED": true,
	}
	asffWorkflowStatuses = map[string]bool{
		"NEW": true, "NOTIFIED": true, "RESOLVED": true, "SUPPRESSED": true,
	}
	asffVerificationStates = map[string]bool{
		"UNKNOWN": true, "TRUE_POSITIVE": true, "FALSE_POSITIVE": true, "BENIGN_POSITIVE": true,
	}
)

// asffProductArnRe matches the private-product ProductArn shape
// arn:{partition}:securityhub:{region}:{accountId}:product/{companyId}/{productId}
// (asff-required-attributes.html -> ProductArn). The account/company segments are
// validated for cross-field consistency separately. The pattern intentionally
// excludes "{" and "}" so any leftover ${ACCOUNT}/${REGION} placeholder fails.
var asffProductArnRe = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):securityhub:[a-z0-9-]+:[0-9]*:product/[^/{}]+/[^/{}]+$`)

// asffAccountRe is the 12-digit AWS account id format used by AwsAccountId.
var asffAccountRe = regexp.MustCompile(`^[0-9]{12}$`)

// validateASFFTimestamp checks an ASFF timestamp is ISO-8601/RFC3339 with an
// explicit timezone (Z or numeric offset), as BatchImportFindings requires. We
// accept both the no-fraction RFC3339 form and the fractional-second form.
func validateASFFTimestamp(s string) bool {
	if _, err := time.Parse(time.RFC3339, s); err == nil {
		return true
	}
	if _, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return true
	}
	return false
}

// ValidateASFFFinding checks one ASFFFinding against the documented Security Hub
// contract and returns a single descriptive error enumerating EVERY violation
// (one per line, each as "path: rule (value=...)"), or nil when fully valid.
// Reusable as the single ASFF-conformance entry point for any package's tests.
func ValidateASFFFinding(f ASFFFinding) error {
	var v []string
	add := func(path, rule string, value interface{}) {
		v = append(v, fmt.Sprintf("%s: %s (value=%q)", path, rule, fmt.Sprintf("%v", value)))
	}

	// --- Required non-empty + SchemaVersion fixed value ---
	if f.SchemaVersion == "" {
		add("SchemaVersion", "required, must be non-empty", f.SchemaVersion)
	} else if f.SchemaVersion != "2018-10-08" {
		add("SchemaVersion", `must equal "2018-10-08"`, f.SchemaVersion)
	}
	if f.ID == "" {
		add("Id", "required, must be non-empty", f.ID)
	} else if n := len(f.ID); n > asffMaxID {
		add("Id", fmt.Sprintf("must be <= %d chars (got %d)", asffMaxID, n), f.ID)
	}
	if f.GeneratorID == "" {
		add("GeneratorId", "required, must be non-empty", f.GeneratorID)
	} else if n := len(f.GeneratorID); n > asffMaxGeneratorID {
		add("GeneratorId", fmt.Sprintf("must be <= %d chars (got %d)", asffMaxGeneratorID, n), f.GeneratorID)
	}

	// --- AwsAccountId: 12 digits ---
	if f.AwsAccountID == "" {
		add("AwsAccountId", "required, must be non-empty", f.AwsAccountID)
	} else if !asffAccountRe.MatchString(f.AwsAccountID) {
		add("AwsAccountId", "must be a 12-digit AWS account id", f.AwsAccountID)
	}

	// --- ProductArn: pattern + no placeholders + account-segment consistency ---
	if f.ProductARN == "" {
		add("ProductArn", "required, must be non-empty", f.ProductARN)
	} else {
		if strings.Contains(f.ProductARN, "${") {
			add("ProductArn", "contains an unexpanded ${...} placeholder", f.ProductARN)
		}
		if n := len(f.ProductARN); n > asffMaxProductArn {
			add("ProductArn", fmt.Sprintf("must be <= %d chars (got %d)", asffMaxProductArn, n), f.ProductARN)
		}
		if !asffProductArnRe.MatchString(f.ProductARN) {
			add("ProductArn", "must match arn:<partition>:securityhub:<region>:<accountId>:product/<companyId>/<productId>", f.ProductARN)
		} else if f.AwsAccountID != "" {
			// Private-product rule: the account-id segment of the ARN must equal
			// AwsAccountId, else BatchImportFindings rejects the finding.
			parts := strings.Split(f.ProductARN, ":")
			if len(parts) >= 5 && parts[4] != "" && parts[4] != f.AwsAccountID {
				add("ProductArn", fmt.Sprintf("account segment %q must equal AwsAccountId %q", parts[4], f.AwsAccountID), f.ProductARN)
			}
		}
	}

	// --- Types: >=1, each 1-3 non-empty segments ---
	if len(f.Types) == 0 {
		add("Types", "required, must contain at least one entry", f.Types)
	} else if len(f.Types) > asffMaxTypes {
		add("Types", fmt.Sprintf("must contain <= %d entries (got %d)", asffMaxTypes, len(f.Types)), len(f.Types))
	}
	for i, t := range f.Types {
		if t == "" {
			add(fmt.Sprintf("Types[%d]", i), "must be non-empty", t)
			continue
		}
		segs := strings.Split(t, "/")
		if len(segs) > 3 {
			add(fmt.Sprintf("Types[%d]", i), "must have at most 3 segments (namespace/category/classifier)", t)
		}
		for j, s := range segs {
			if strings.TrimSpace(s) == "" {
				add(fmt.Sprintf("Types[%d] segment %d", i, j), "namespace/category/classifier segments must be non-empty", t)
			}
		}
	}

	// --- Timestamps: required + ISO-8601/RFC3339 with timezone ---
	if f.CreatedAt == "" {
		add("CreatedAt", "required, must be non-empty", f.CreatedAt)
	} else if !validateASFFTimestamp(f.CreatedAt) {
		add("CreatedAt", "must be ISO-8601/RFC3339 with timezone", f.CreatedAt)
	}
	if f.UpdatedAt == "" {
		add("UpdatedAt", "required, must be non-empty", f.UpdatedAt)
	} else if !validateASFFTimestamp(f.UpdatedAt) {
		add("UpdatedAt", "must be ISO-8601/RFC3339 with timezone", f.UpdatedAt)
	}

	// --- Severity (required object) + Label enum + Normalized range ---
	if f.Severity.Label == "" {
		add("Severity.Label", "required, must be non-empty", f.Severity.Label)
	} else if !asffSeverityLabels[f.Severity.Label] {
		add("Severity.Label", "must be one of INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL", f.Severity.Label)
	}
	if f.Severity.Normalized < 0 || f.Severity.Normalized > 100 {
		add("Severity.Normalized", "must be in 0-100", f.Severity.Normalized)
	}

	// --- Title / Description: required + length caps ---
	if f.Title == "" {
		add("Title", "required, must be non-empty", f.Title)
	} else if n := len([]rune(f.Title)); n > asffMaxTitle {
		add("Title", fmt.Sprintf("must be <= %d chars (got %d)", asffMaxTitle, n), n)
	}
	if f.Description == "" {
		add("Description", "required, must be non-empty", f.Description)
	} else if n := len([]rune(f.Description)); n > asffMaxDescription {
		add("Description", fmt.Sprintf("must be <= %d chars (got %d)", asffMaxDescription, n), n)
	}

	// --- Resources: >=1, each Type+Id non-empty + length caps ---
	if len(f.Resources) == 0 {
		add("Resources", "required, must contain at least one resource", f.Resources)
	}
	for i, r := range f.Resources {
		if r.Type == "" {
			add(fmt.Sprintf("Resources[%d].Type", i), "required, must be non-empty", r.Type)
		} else if n := len(r.Type); n > asffMaxResourceType {
			add(fmt.Sprintf("Resources[%d].Type", i), fmt.Sprintf("must be <= %d chars (got %d)", asffMaxResourceType, n), n)
		}
		if r.ID == "" {
			add(fmt.Sprintf("Resources[%d].Id", i), "required, must be non-empty", r.ID)
		} else if n := len(r.ID); n > asffMaxResourceID {
			add(fmt.Sprintf("Resources[%d].Id", i), fmt.Sprintf("must be <= %d chars (got %d)", asffMaxResourceID, n), n)
		}
	}

	// --- Optional enum-bearing fields: validate only when present ---
	if f.Compliance != nil && f.Compliance.Status != "" && !asffComplianceStatuses[f.Compliance.Status] {
		add("Compliance.Status", "must be one of PASSED|WARNING|FAILED|NOT_AVAILABLE", f.Compliance.Status)
	}
	if f.RecordState != "" && !asffRecordStates[f.RecordState] {
		add("RecordState", "must be one of ACTIVE|ARCHIVED", f.RecordState)
	}

	if len(v) == 0 {
		return nil
	}
	sort.Strings(v)
	return fmt.Errorf("ASFF finding %q violates the Security Hub contract:\n  %s", f.ID, strings.Join(v, "\n  "))
}

// rawASFFFinding mirrors ASFFFinding plus the optional enum-bearing fields that
// the emit-time struct does not populate today (Workflow.Status,
// VerificationState). Validating from the wire JSON lets ValidateASFFBytes catch
// a bad value in those fields too, should they ever be emitted.
type rawASFFFinding struct {
	ASFFFinding
	Workflow *struct {
		Status string `json:"Status"`
	} `json:"Workflow,omitempty"`
	VerificationState string `json:"VerificationState,omitempty"`
}

// ValidateASFFBytes validates raw ASFF JSON (either a single finding object or a
// JSON array of findings, as WriteASFF emits) against the documented Security Hub
// contract. Returns nil when every finding is valid; a descriptive error listing
// each finding's violations otherwise. Reusable from any package's tests as the
// single ASFF-conformance entry point — the analog of ValidateCBOMBytes.
func ValidateASFFBytes(raw []byte) error {
	trimmed := strings.TrimSpace(string(raw))
	var findings []rawASFFFinding
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(raw, &findings); err != nil {
			return fmt.Errorf("unmarshal ASFF array: %w", err)
		}
	} else {
		var one rawASFFFinding
		if err := json.Unmarshal(raw, &one); err != nil {
			return fmt.Errorf("unmarshal ASFF finding: %w", err)
		}
		findings = []rawASFFFinding{one}
	}
	if len(findings) == 0 {
		return fmt.Errorf("ASFF payload contains no findings")
	}
	var errs []string
	for i, rf := range findings {
		if err := ValidateASFFFinding(rf.ASFFFinding); err != nil {
			errs = append(errs, fmt.Sprintf("findings[%d]: %v", i, err))
		}
		// Optional enum fields present only on the wire are checked here so they
		// can't slip an invalid member past the typed validator.
		if rf.Workflow != nil && rf.Workflow.Status != "" && !asffWorkflowStatuses[rf.Workflow.Status] {
			errs = append(errs, fmt.Sprintf("findings[%d]: Workflow.Status: must be one of NEW|NOTIFIED|RESOLVED|SUPPRESSED (value=%q)", i, rf.Workflow.Status))
		}
		if rf.VerificationState != "" && !asffVerificationStates[rf.VerificationState] {
			errs = append(errs, fmt.Sprintf("findings[%d]: VerificationState: must be one of UNKNOWN|TRUE_POSITIVE|FALSE_POSITIVE|BENIGN_POSITIVE (value=%q)", i, rf.VerificationState))
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("ASFF payload has %d invalid finding(s):\n%s", len(errs), strings.Join(errs, "\n"))
}
