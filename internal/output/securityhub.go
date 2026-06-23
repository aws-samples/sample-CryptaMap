package output

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"strings"
	"time"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// Security Hub BatchImportFindings field-length limits (AWS Security Hub API
// Reference, AwsSecurityFinding / Resource data types). A finding that exceeds
// any of these is rejected by BatchImportFindings, so we clamp variable-length
// fields at emit time. These match the documented maxima exactly.
const (
	asffMaxID          = 512  // Id
	asffMaxTitle       = 256  // Title
	asffMaxDescription = 1024 // Description
	asffMaxTypes       = 50   // Types array entries
)

// asffTruncate clamps a free-text field (Title/Description) to max runes,
// appending a single-rune ellipsis so truncation is visible rather than silent.
func asffTruncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	// Operate on runes so we never split a multi-byte UTF-8 sequence.
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}

// asffTruncateID clamps the finding Id while preserving uniqueness: if the id is
// over the limit we keep a head slice and append a deterministic 8-hex FNV hash
// of the full id, so two long ids that share a prefix still map to distinct ids.
func asffTruncateID(id string) string {
	if len(id) <= asffMaxID {
		return id
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	suffix := fmt.Sprintf("~%08x", h.Sum32()) // 9 chars
	return id[:asffMaxID-len(suffix)] + suffix
}

// PartitionForRegion returns the AWS partition that owns a region, derived from
// the region's prefix. ARNs are partition-scoped — arn:aws: (commercial),
// arn:aws-us-gov: (GovCloud), arn:aws-cn: (China) — and a finding emitted with
// the wrong partition is rejected, so every partition-bearing ARN we emit must
// follow the finding's region rather than a hardcoded "aws". GovCloud regions
// are us-gov-west-1 / us-gov-east-1 and China regions are cn-north-1 /
// cn-northwest-1; everything else (incl. ap-south-1 / us-east-1) is commercial.
func PartitionForRegion(region string) string {
	switch {
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	default:
		return "aws"
	}
}

// expandProductArn substitutes the ${ACCOUNT}/${REGION} placeholders carried in
// the default ProductArn template with this finding's real account/region. The
// AWS-required private-product ARN shape is
// arn:aws:securityhub:<region>:<account>:product/<account>/default and the
// account segment MUST equal the finding's AwsAccountId, so we source both from
// the finding itself. If the template has no placeholders this is a no-op, and
// if account/region are unknown the placeholder is left intact (visible) rather
// than emitting a half-formed ARN.
//
// The partition prefix is also corrected to follow the finding's region: the
// default template hardcodes "arn:aws:", which is wrong in GovCloud/China, so a
// leading "arn:aws:" is rewritten to "arn:<partition>:" when the region maps to
// a non-commercial partition. Commercial regions leave "arn:aws:" untouched, so
// existing commercial output is byte-for-byte identical.
func expandProductArn(productArn, account, region string) string {
	if account != "" {
		productArn = strings.ReplaceAll(productArn, "${ACCOUNT}", account)
	}
	if region != "" {
		productArn = strings.ReplaceAll(productArn, "${REGION}", region)
		if part := PartitionForRegion(region); part != "aws" {
			productArn = strings.Replace(productArn, "arn:aws:", "arn:"+part+":", 1)
		}
	}
	return productArn
}

// ASFFFinding mirrors the AWS Security Finding Format (ASFF) v2018-10-08.
// We hand-roll a minimal struct rather than rely on the SDK type so we can
// emit JSON identical to the spec example.
type ASFFFinding struct {
	SchemaVersion     string            `json:"SchemaVersion"`
	ID                string            `json:"Id"`
	ProductARN        string            `json:"ProductArn"`
	GeneratorID       string            `json:"GeneratorId"`
	AwsAccountID      string            `json:"AwsAccountId"`
	Types             []string          `json:"Types"`
	CreatedAt         string            `json:"CreatedAt"`
	UpdatedAt         string            `json:"UpdatedAt"`
	Severity          ASFFSeverity      `json:"Severity"`
	Title             string            `json:"Title"`
	Description       string            `json:"Description"`
	Remediation       ASFFRemediation   `json:"Remediation"`
	Resources         []ASFFResource    `json:"Resources"`
	Compliance        *ASFFCompliance   `json:"Compliance,omitempty"`
	ProductFields     map[string]string `json:"ProductFields,omitempty"`
	UserDefinedFields map[string]string `json:"UserDefinedFields,omitempty"`
	RecordState       string            `json:"RecordState"`
	WorkflowState     string            `json:"WorkflowState"`
}

type ASFFSeverity struct {
	Label      string `json:"Label"`
	Normalized int    `json:"Normalized"`
}

type ASFFRemediation struct {
	Recommendation ASFFRecommendation `json:"Recommendation"`
}

type ASFFRecommendation struct {
	Text string `json:"Text"`
	URL  string `json:"Url,omitempty"`
}

type ASFFResource struct {
	Type      string                 `json:"Type"`
	ID        string                 `json:"Id"`
	Region    string                 `json:"Region,omitempty"`
	Partition string                 `json:"Partition,omitempty"`
	Details   map[string]interface{} `json:"Details,omitempty"`
}

type ASFFCompliance struct {
	Status              string   `json:"Status"`
	RelatedRequirements []string `json:"RelatedRequirements,omitempty"`
}

// BuildASFFFindings returns ASFF objects for all findings in scan.
func BuildASFFFindings(scan models.ScanResult, productArn string) []ASFFFinding {
	out := make([]ASFFFinding, 0, len(scan.Findings))
	for _, f := range scan.Findings {
		out = append(out, BuildASFFFinding(f, productArn))
	}
	return out
}

// BuildASFFFinding returns one ASFF object for a Finding.
func BuildASFFFinding(f models.Finding, productArn string) ASFFFinding {
	relReq := []string{}
	// ASFF Compliance.Status is a CLOSED enum: PASSED | WARNING | FAILED |
	// NOT_AVAILABLE (Security Hub rejects anything else). Map the internal
	// compliance statuses onto it. Two internal vocabularies feed in:
	//   - mandate frameworks (compliance/mapper.go statusFromPosture): compliant |
	//     non-compliant | partial | informational
	//   - India readiness frameworks (readinessFromPosture, no PQC mandate):
	//     quantum-safe | quantum-vulnerable | partial | informational
	// Both must map, or a status would silently fall to NOT_AVAILABLE (the prior
	// fidelity bug). quantum-vulnerable≡non-compliant→FAILED; quantum-safe≡
	// compliant→PASSED; "partial"→WARNING; "informational" carries no pass/fail
	// verdict→NOT_AVAILABLE. Precedence: FAILED > WARNING > PASSED > NOT_AVAILABLE.
	cstatus := "NOT_AVAILABLE"
	hasNonCompliant := false
	hasPartial := false
	hasCompliant := false
	for _, c := range f.Compliance {
		relReq = append(relReq, fmt.Sprintf("%s/%s", c.Framework, c.ControlID))
		switch c.Status {
		case "non-compliant", "quantum-vulnerable":
			hasNonCompliant = true
		case "partial":
			hasPartial = true
		case "compliant", "quantum-safe":
			hasCompliant = true
		}
	}
	switch {
	case hasNonCompliant:
		cstatus = "FAILED"
	case hasPartial:
		cstatus = "WARNING"
	case hasCompliant:
		cstatus = "PASSED"
	}
	resID := f.ResourceARN
	if resID == "" {
		resID = f.ResourceID
	}
	return ASFFFinding{
		SchemaVersion: "2018-10-08",
		// Clamp to the documented 512-char Id limit, preserving uniqueness.
		ID: asffTruncateID(fmt.Sprintf("cryptamap/%s/%s/%s/%s", f.AccountID, f.Region, f.ResourceID, f.ID)),
		// Substitute the ${ACCOUNT}/${REGION} placeholders from the default
		// ProductArn template with this finding's real account/region — the
		// account segment must equal AwsAccountId for BatchImportFindings.
		ProductARN:   expandProductArn(productArn, f.AccountID, f.Region),
		GeneratorID:  "cryptamap-scanner-v1",
		AwsAccountID: f.AccountID,
		Types:        []string{"Software and Configuration Checks/Crypto/PostQuantumReadiness"},
		CreatedAt:    f.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt:    f.UpdatedAt.UTC().Format(time.RFC3339),
		Severity: ASFFSeverity{
			Label:      string(f.Severity),
			Normalized: models.NormalizedSeverity(f.Severity),
		},
		// Clamp Title/Description to the documented maxima (256 / 1024).
		Title:       asffTruncate(f.Title, asffMaxTitle),
		Description: asffTruncate(f.Description, asffMaxDescription),
		Remediation: ASFFRemediation{
			Recommendation: ASFFRecommendation{
				Text: f.Recommendation,
				URL:  f.DocsURL,
			},
		},
		Resources: []ASFFResource{{
			Type:   f.ResourceType,
			ID:     resID,
			Region: f.Region,
			// Partition follows the finding's region (not the scanner-built
			// resource ARN, whose partition is hardcoded "aws" in common.go and
			// so unreliable in GovCloud/China). Commercial stays "aws".
			Partition: PartitionForRegion(f.Region),
		}},
		Compliance: &ASFFCompliance{
			Status:              cstatus,
			RelatedRequirements: relReq,
		},
		ProductFields: map[string]string{
			"cryptamap:posture":     string(f.Posture),
			"cryptamap:moscaScore":  fmt.Sprintf("%d", f.Mosca.Score),
			"cryptamap:assetBomRef": f.AssetBomRef,
		},
		RecordState:   "ACTIVE",
		WorkflowState: "NEW",
	}
}

// WriteASFF writes ASFF findings as a JSON array.
func WriteASFF(w io.Writer, scan models.ScanResult, productArn string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(BuildASFFFindings(scan, productArn))
}
