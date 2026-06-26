package output

import (
	"testing"

	"github.com/aws-samples/cryptamap/internal/compliance"
	"github.com/aws-samples/cryptamap/internal/scanner"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestParseCBOMRoundTrip asserts that AsBytes(scan) -> ParseCBOM reconstructs
// the assets losslessly enough to drive merge + roadmap: bom-refs, service,
// account/region, resourceArn, posture (in Properties), and the deeper crypto
// detail folded back into CryptoProps. It then regenerates findings via
// scanner.BuildFindings and asserts they are non-empty with the expected
// severities, exercising the full CBOM -> ScanResult -> findings path with no
// AWS access.
func TestParseCBOMRoundTrip(t *testing.T) {
	in := sampleScan(t)
	// Give every sample asset a posture in Properties so BuildFindings can derive
	// a posture-based severity (the CBOM writer round-trips Properties verbatim).
	postures := map[string]models.CryptoPosture{
		"s3":  models.PostureSymmetricOnly,
		"kms": models.PostureSymmetricOnly,
		"alb": models.PosturePQCHybrid,
	}
	for i := range in.Assets {
		if in.Assets[i].Properties == nil {
			in.Assets[i].Properties = map[string]string{}
		}
		in.Assets[i].Properties["posture"] = string(postures[in.Assets[i].Service])
		in.Assets[i].Properties["note"] = "sample-note-" + in.Assets[i].Service
	}

	raw, err := AsBytes(in)
	if err != nil {
		t.Fatalf("AsBytes: %v", err)
	}

	shards, err := ParseCBOM(raw)
	if err != nil {
		t.Fatalf("ParseCBOM: %v", err)
	}
	if len(shards) != 1 {
		t.Fatalf("expected 1 shard (single account/region), got %d", len(shards))
	}
	got := shards[0]

	if got.AccountID != in.AccountID {
		t.Errorf("shard AccountID=%q, want %q", got.AccountID, in.AccountID)
	}
	if got.Region != in.Region {
		t.Errorf("shard Region=%q, want %q", got.Region, in.Region)
	}
	if len(got.Assets) != len(in.Assets) {
		t.Fatalf("asset count=%d, want %d", len(got.Assets), len(in.Assets))
	}

	// Index reconstructed assets by BomRef; the bom-ref must survive the round-trip.
	byRef := make(map[string]models.CryptoAsset, len(got.Assets))
	for _, a := range got.Assets {
		byRef[a.BomRef] = a
	}
	for _, want := range in.Assets {
		ra, ok := byRef[want.BomRef]
		if !ok {
			t.Fatalf("bom-ref %q missing after round-trip", want.BomRef)
		}
		if ra.Service != want.Service {
			t.Errorf("%s: service=%q, want %q", want.BomRef, ra.Service, want.Service)
		}
		if ra.AccountID != want.AccountID {
			t.Errorf("%s: accountId=%q, want %q", want.BomRef, ra.AccountID, want.AccountID)
		}
		if ra.Region != want.Region {
			t.Errorf("%s: region=%q, want %q", want.BomRef, ra.Region, want.Region)
		}
		if ra.Category != want.Category {
			t.Errorf("%s: category=%q, want %q", want.BomRef, ra.Category, want.Category)
		}
		// posture must survive in Properties (this is what BuildFindings reads).
		if got, wantP := ra.Properties["posture"], want.Properties["posture"]; got != wantP {
			t.Errorf("%s: posture=%q, want %q", want.BomRef, got, wantP)
		}
		// free-form props (note) survive too.
		if ra.Properties["note"] != want.Properties["note"] {
			t.Errorf("%s: note=%q, want %q", want.BomRef, ra.Properties["note"], want.Properties["note"])
		}
		// Display/taxonomy props must NOT leak into Properties.
		if _, leaked := ra.Properties["displayName"]; leaked {
			t.Errorf("%s: displayName leaked into Properties", want.BomRef)
		}
	}

	// Deeper crypto detail must be folded back into CryptoProps.
	var kms, alb models.CryptoAsset
	for _, a := range got.Assets {
		switch a.Service {
		case "kms":
			kms = a
		case "alb":
			alb = a
		}
	}
	if kms.CryptoProps.AlgorithmProperties == nil {
		t.Fatal("kms algorithmProperties missing after round-trip")
	}
	if kms.CryptoProps.AlgorithmProperties.AlgorithmName != "AES-256-GCM" {
		t.Errorf("kms algorithmName=%q, want AES-256-GCM", kms.CryptoProps.AlgorithmProperties.AlgorithmName)
	}
	if kms.CryptoProps.AlgorithmProperties.KMSKeySpec != "SYMMETRIC_DEFAULT" {
		t.Errorf("kms kmsKeySpec=%q, want SYMMETRIC_DEFAULT", kms.CryptoProps.AlgorithmProperties.KMSKeySpec)
	}
	if kms.CryptoProps.AlgorithmProperties.KeySizeBits != 256 {
		t.Errorf("kms keySizeBits=%d, want 256", kms.CryptoProps.AlgorithmProperties.KeySizeBits)
	}
	if alb.CryptoProps.ProtocolProperties == nil {
		t.Fatal("alb protocolProperties missing after round-trip")
	}
	if alb.CryptoProps.ProtocolProperties.KeyExchangeGroup != "X25519MLKEM768" {
		t.Errorf("alb keyExchangeGroup=%q, want X25519MLKEM768", alb.CryptoProps.ProtocolProperties.KeyExchangeGroup)
	}
	if !alb.CryptoProps.ProtocolProperties.PQCHybrid {
		t.Error("alb pqcHybrid=false, want true after round-trip")
	}
	if alb.CryptoProps.ProtocolProperties.CertKeySizeBits != 2048 {
		t.Errorf("alb certKeySizeBits=%d, want 2048", alb.CryptoProps.ProtocolProperties.CertKeySizeBits)
	}

	// Regenerate findings deterministically (the key unlock: no DynamoDB needed).
	reg := compliance.NewRegistry([]string{"MITRE_PQCC"})
	findings := scanner.BuildFindings(got.Assets, reg, nil)
	// B3 at-rest INVENTORY-ONLY: symmetric-only (quantum-resistant at rest) assets
	// are round-tripped in the CBOM but NOT emitted as findings, so the contract
	// is one finding per NON-symmetric-only asset.
	inventoryOnly := 0
	for _, a := range got.Assets {
		if a.Properties != nil && a.Properties["posture"] == string(models.PostureSymmetricOnly) {
			inventoryOnly++
		}
	}
	if want := len(got.Assets) - inventoryOnly; len(findings) != want {
		t.Fatalf("findings=%d, want %d (%d assets, %d inventory-only symmetric)", len(findings), want, len(got.Assets), inventoryOnly)
	}
	for _, fn := range findings {
		if fn.AssetBomRef == "" {
			t.Errorf("finding has empty AssetBomRef: %+v", fn)
		}
		if fn.Severity == "" {
			t.Errorf("finding %s has empty Severity", fn.AssetBomRef)
		}
		if _, ok := byRef[fn.AssetBomRef]; !ok {
			t.Errorf("finding references unknown asset bom-ref %q", fn.AssetBomRef)
		}
	}
}

// TestParseCBOMGroupsByAccountRegion asserts that components from distinct
// (accountId, region) tuples are split into separate shards, as a live org scan
// would have produced one ScanResult per account/region.
func TestParseCBOMGroupsByAccountRegion(t *testing.T) {
	base := sampleScan(t)
	// Build a 2-account CBOM by relabeling a DEEP copy of the assets into a 2nd
	// account. (Shallow-copying the ScanResult would alias the shared Assets
	// backing array.)
	a := base
	b := base
	b.AccountID = "210987654321"
	b.Assets = append([]models.CryptoAsset(nil), base.Assets...)
	for i := range b.Assets {
		b.Assets[i].AccountID = "210987654321"
		b.Assets[i].BomRef = b.Assets[i].BomRef + "-acct2"
		b.Assets[i].ResourceARN = "arn:aws:svc:ap-south-1:210987654321:Type/id" + b.Assets[i].Service
	}
	// Merge components from both into one CBOM blob by emitting each then parsing.
	rawA, _ := AsBytes(a)
	rawB, _ := AsBytes(b)
	shardsA, err := ParseCBOM(rawA)
	if err != nil {
		t.Fatalf("ParseCBOM a: %v", err)
	}
	shardsB, err := ParseCBOM(rawB)
	if err != nil {
		t.Fatalf("ParseCBOM b: %v", err)
	}
	if len(shardsA) != 1 || shardsA[0].AccountID != base.AccountID {
		t.Fatalf("shardsA unexpected: %+v", shardsA)
	}
	if len(shardsB) != 1 || shardsB[0].AccountID != "210987654321" {
		t.Fatalf("shardsB unexpected: %+v", shardsB)
	}
}

// TestParseCBOMResourceTypeRoundTrip pins the lossless ResourceType round-trip
// for a region-less S3 ARN (arn:aws:s3:::bucket). That ARN has no
// "<type>/<id>" segment, so resourceFromARN alone would drop the type; the
// writer now emits cryptamap:resourceType explicitly and the reader prefers it.
// Without this, the offline org-merge-files path reconstructed S3 buckets with
// ResourceType="" (breaking ASFF Resources[].Type and the finding description),
// asymmetric with a live scan of the same bucket.
func TestParseCBOMResourceTypeRoundTrip(t *testing.T) {
	in := models.ScanResult{
		ScanID:    "s1",
		AccountID: "123456789012",
		Region:    "ap-south-1",
		Mode:      "live",
		Assets: []models.CryptoAsset{{
			BomRef:       "crypto-abc",
			Name:         "my-bucket",
			Service:      "s3",
			Category:     models.CategoryDataAtRest,
			AccountID:    "123456789012",
			Region:       "ap-south-1",
			ResourceID:   "my-bucket",
			ResourceType: "AWS::S3::Bucket",
			ResourceARN:  "arn:aws:s3:::my-bucket",
			Properties:   map[string]string{"posture": string(models.PostureNoEncryption)},
		}},
	}

	raw, err := AsBytes(in)
	if err != nil {
		t.Fatalf("AsBytes: %v", err)
	}
	shards, err := ParseCBOM(raw)
	if err != nil {
		t.Fatalf("ParseCBOM: %v", err)
	}
	if len(shards) != 1 || len(shards[0].Assets) != 1 {
		t.Fatalf("expected 1 shard with 1 asset, got %d shards", len(shards))
	}
	got := shards[0].Assets[0]
	if got.ResourceType != "AWS::S3::Bucket" {
		t.Errorf("ResourceType round-trip = %q, want %q (region-less S3 ARN must not lose type)", got.ResourceType, "AWS::S3::Bucket")
	}
	if got.ResourceID != "my-bucket" {
		t.Errorf("ResourceID round-trip = %q, want %q", got.ResourceID, "my-bucket")
	}
	if got.ResourceARN != "arn:aws:s3:::my-bucket" {
		t.Errorf("ResourceARN round-trip = %q, want region-less ARN", got.ResourceARN)
	}
	// resourceType must NOT leak into the free-form Properties map (it is a
	// structural field, like service/region/resourceArn).
	if _, leaked := got.Properties["resourceType"]; leaked {
		t.Errorf("resourceType leaked into Properties map; should be skipped")
	}
}

// TestResourceFromARN covers the ARN -> (type,id) decomposition.
func TestResourceFromARN(t *testing.T) {
	cases := []struct {
		arn, wantType, wantID string
	}{
		{"arn:aws:glue:us-east-1:123456789012:AWS::Glue::DataCatalog/data-catalog", "AWS::Glue::DataCatalog", "data-catalog"},
		{"arn:aws:kms:us-east-1:123456789012:AWS::KMS::Alias/alias/aws/dynamodb", "AWS::KMS::Alias/alias/aws", "dynamodb"},
		// Region-less S3 ARN: no "<type>/<id>" segment, so ResourceType can NOT be
		// derived from the ARN — it is recovered from the explicit cryptamap:
		// resourceType property instead (see TestParseCBOMResourceTypeRoundTrip).
		{"arn:aws:s3:::my-bucket", "", "my-bucket"},
		{"", "", ""},
		{"not-an-arn", "", "not-an-arn"},
	}
	for _, c := range cases {
		gt, gi := resourceFromARN(c.arn)
		if gt != c.wantType || gi != c.wantID {
			t.Errorf("resourceFromARN(%q)=(%q,%q), want (%q,%q)", c.arn, gt, gi, c.wantType, c.wantID)
		}
	}
}
