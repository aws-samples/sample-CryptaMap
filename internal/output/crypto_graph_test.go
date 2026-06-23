package output

import (
	"testing"
	"time"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// graphScan builds a scan exercising every refType-bearing shape plus the
// edge cases the linker must handle: genuine cert signature algorithms, genuine
// SSH/IPsec cipher-suite algorithm lists, a suite whose Algorithms is empty (a
// label-only suite, like a real config-scan TLS endpoint), an empty
// signatureAlgorithmRef (must not synthesize an empty-named node), and two
// DISTINCT tokens that slugify to the same base (collision handling).
func graphScan() models.ScanResult {
	now := time.Now().UTC()
	mk := func(ref, name, svc string, cat models.Category, cp models.CryptoProperties) models.CryptoAsset {
		return models.CryptoAsset{
			BomRef: ref, Name: name, Service: svc, Category: cat,
			AccountID: "111111111111", Region: "ap-south-1",
			ResourceID: name, DiscoveredAt: now, CryptoProps: cp,
			Properties: map[string]string{"posture": "non-pqc-classical"},
		}
	}
	return models.ScanResult{
		ScanID: "graph-test", AccountID: "111111111111", Region: "ap-south-1",
		Mode: "test", ToolVersion: "test",
		Assets: []models.CryptoAsset{
			// Certificate with a genuine signature algorithm token.
			mk("crypto-cert-1", "cert-1", "acm", models.CategoryCertificate, models.CryptoProperties{
				AssetType: models.AssetTypeCertificate,
				CertificateProperties: &models.CertificateProperties{
					SubjectName: "CN=a.example.com", SignatureAlgorithmRef: "SHA256WITHRSA",
					CertificateFormat: "X.509",
				},
			}),
			// Second cert reusing the SAME signature algorithm — must share ONE node.
			mk("crypto-cert-2", "cert-2", "acm", models.CategoryCertificate, models.CryptoProperties{
				AssetType: models.AssetTypeCertificate,
				CertificateProperties: &models.CertificateProperties{
					SubjectName: "CN=b.example.com", SignatureAlgorithmRef: "SHA256WITHRSA",
					CertificateFormat: "X.509",
				},
			}),
			// Cert with an EMPTY signatureAlgorithmRef (honest blank) — no node.
			mk("crypto-cert-3", "cert-3", "acm", models.CategoryCertificate, models.CryptoProperties{
				AssetType: models.AssetTypeCertificate,
				CertificateProperties: &models.CertificateProperties{
					SubjectName: "CN=c.example.com", CertificateFormat: "X.509",
				},
			}),
			// SSH protocol with a genuine KEX algorithm list + a label-only suite.
			mk("crypto-ssh-1", "transfer-1", "transferfamily", models.CategoryDataInTransit, models.CryptoProperties{
				AssetType: models.AssetTypeProtocol,
				ProtocolProperties: &models.ProtocolProperties{
					Type: "ssh",
					CipherSuites: []models.CipherSuite{
						{Name: "ssh-kex", Algorithms: []string{"ecdh-sha2-nistp256", "mlkem768x25519-sha256"}},
						{Name: "service-label-only"}, // no Algorithms — must stay label-only
					},
				},
			}),
			// Two DISTINCT tokens that slugify identically ("AES-256/GCM" vs
			// "AES_256_GCM") — collision suffixing must give them distinct refs.
			mk("crypto-ipsec-1", "vpn-1", "vpn", models.CategoryDataInTransit, models.CryptoProperties{
				AssetType: models.AssetTypeProtocol,
				ProtocolProperties: &models.ProtocolProperties{
					Type: "ipsec",
					CipherSuites: []models.CipherSuite{
						{Name: "ipsec-encryption", Algorithms: []string{"AES-256/GCM", "AES_256_GCM"}},
					},
				},
			}),
		},
	}
}

func TestCryptoGraph_NoDanglingRefs(t *testing.T) {
	bom := buildCBOM(graphScan())

	refs := map[string]bool{}
	for _, c := range bom.Components {
		refs[c.BomRef] = true
	}

	occurrences := 0
	for _, c := range bom.Components {
		if c.CryptoProperties == nil {
			continue
		}
		if cp := c.CryptoProperties.CertificateProperties; cp != nil && cp.SignatureAlgorithmRef != "" {
			occurrences++
			if !refs[cp.SignatureAlgorithmRef] {
				t.Errorf("certificate %q signatureAlgorithmRef %q resolves to no component", c.Name, cp.SignatureAlgorithmRef)
			}
		}
		if pp := c.CryptoProperties.ProtocolProperties; pp != nil {
			for _, cs := range pp.CipherSuites {
				for _, a := range cs.Algorithms {
					occurrences++
					if !refs[a] {
						t.Errorf("protocol %q cipherSuite %q algorithm ref %q resolves to no component", c.Name, cs.Name, a)
					}
				}
			}
		}
	}
	if occurrences == 0 {
		t.Fatal("test built no refType occurrences — fixture is broken")
	}
}

func TestCryptoGraph_SyntheticNodeShape(t *testing.T) {
	bom := buildCBOM(graphScan())

	synth := map[string]CDXComponent{}
	for _, c := range bom.Components {
		if isSyntheticComponent(c) {
			synth[c.Name] = c
		}
	}
	// Distinct genuine tokens: SHA256WITHRSA, ecdh-sha2-nistp256,
	// mlkem768x25519-sha256, AES-256/GCM, AES_256_GCM = 5. The empty ref and the
	// label-only suite must NOT produce nodes.
	if len(synth) != 5 {
		names := make([]string, 0, len(synth))
		for n := range synth {
			names = append(names, n)
		}
		t.Fatalf("expected 5 synthetic algorithm nodes, got %d: %v", len(synth), names)
	}

	for name, c := range synth {
		if c.Type != "cryptographic-asset" {
			t.Errorf("synthetic %q type=%q, want cryptographic-asset", name, c.Type)
		}
		if c.CryptoProperties == nil || c.CryptoProperties.AssetType != models.AssetTypeAlgorithm {
			t.Errorf("synthetic %q must have cryptoProperties.assetType=algorithm", name)
		}
		// Synthetic nodes must carry NO account/region/service (they are not
		// discovered resources) so they never pollute asset accounting.
		for _, p := range c.Properties {
			switch p.Name {
			case "cryptamap:accountId", "cryptamap:region", "cryptamap:service", "cryptamap:resourceArn":
				t.Errorf("synthetic %q must not carry %s", name, p.Name)
			}
		}
		if v, ok := propValue(c, "cryptamap:algorithmName"); !ok || v != name {
			t.Errorf("synthetic %q algorithmName=%q, want %q", name, v, name)
		}
	}

	// An empty signatureAlgorithmRef must NOT have produced an empty-named node.
	if _, bad := synth[""]; bad {
		t.Error("an empty-named synthetic node was created from an empty ref")
	}
}

func TestCryptoGraph_CollisionDistinctRefs(t *testing.T) {
	bom := buildCBOM(graphScan())
	// "AES-256/GCM" and "AES_256_GCM" slugify to the same base; their refs must differ.
	var refs []string
	for _, c := range bom.Components {
		if isSyntheticComponent(c) && (c.Name == "AES-256/GCM" || c.Name == "AES_256_GCM") {
			refs = append(refs, c.BomRef)
		}
	}
	if len(refs) != 2 {
		t.Fatalf("expected 2 colliding-token nodes, got %d", len(refs))
	}
	if refs[0] == refs[1] {
		t.Errorf("colliding tokens got the SAME bom-ref %q — collision suffixing failed", refs[0])
	}
}

func TestCryptoGraph_Deterministic(t *testing.T) {
	a := buildCBOM(graphScan())
	b := buildCBOM(graphScan())
	if len(a.Components) != len(b.Components) {
		t.Fatalf("component count differs across runs: %d vs %d", len(a.Components), len(b.Components))
	}
	for i := range a.Components {
		if a.Components[i].BomRef != b.Components[i].BomRef {
			t.Errorf("component %d bom-ref differs across runs: %q vs %q", i, a.Components[i].BomRef, b.Components[i].BomRef)
		}
	}
}

// TestPQEvidence_CapableVsConfirmed asserts the PQ-hybrid evidence qualifier:
// a config/policy-name-derived PQ-hybrid asset is "capable"; only an observed
// negotiation (cloudtrail_evidence) is "confirmed"; non-PQ assets carry no
// qualifier. This is the v1 honesty split so the headline % never reports a
// permitted-but-unproven PQ endpoint as proven.
func TestPQEvidence_CapableVsConfirmed(t *testing.T) {
	now := time.Now().UTC()
	mk := func(name, svc string, pqc bool) models.CryptoAsset {
		return models.CryptoAsset{
			BomRef: "crypto-" + name, Name: name, Service: svc,
			Category: models.CategoryDataInTransit, AccountID: "111111111111",
			Region: "ap-south-1", ResourceID: name, DiscoveredAt: now,
			Properties: map[string]string{"posture": "pqc-hybrid"},
			CryptoProps: models.CryptoProperties{
				AssetType: models.AssetTypeProtocol,
				ProtocolProperties: &models.ProtocolProperties{
					Type: "tls", Version: "1.3", PQCHybrid: pqc, KeyExchangeGroup: "X25519MLKEM768",
				},
			},
		}
	}
	scan := models.ScanResult{
		ScanID: "pqev", AccountID: "111111111111", Region: "ap-south-1", Mode: "test",
		Assets: []models.CryptoAsset{
			mk("alb-policy", "alb", true),               // config/name-derived → capable
			mk("observed", "cloudtrail_evidence", true), // observed negotiation → confirmed
			mk("classical", "alb", false),               // not PQ → no qualifier
		},
	}
	bom := buildCBOM(scan)
	want := map[string]string{"crypto-alb-policy": "capable", "crypto-observed": "confirmed"}
	got := map[string]string{}
	for _, c := range bom.Components {
		if v, ok := propValue(c, "cryptamap:pqEvidence"); ok {
			got[c.BomRef] = v
		}
		if c.BomRef == "crypto-classical" {
			if _, ok := propValue(c, "cryptamap:pqEvidence"); ok {
				t.Error("non-PQ asset must not carry cryptamap:pqEvidence")
			}
		}
	}
	for ref, exp := range want {
		if got[ref] != exp {
			t.Errorf("%s: pqEvidence = %q, want %q", ref, got[ref], exp)
		}
	}
}

// TestEnumConstants_AllSchemaValid is an exhaustive offline guard: it emits a
// CBOM component for EVERY model enum constant that lands in a CycloneDX enum
// field (assetType, algorithmProperties.primitive, relatedCryptoMaterialProperties
// .state) and validates each against the official 1.7 schema. This catches a model
// constant drifting out of schema conformance WITHOUT needing a live AWS scan —
// the bug class that the ikev2 + related-material defects belonged to.
func TestEnumConstants_AllSchemaValid(t *testing.T) {
	schema := compileCDXSchema(t)
	now := time.Now().UTC()
	base := func(name string, cp models.CryptoProperties) models.ScanResult {
		return models.ScanResult{
			ScanID: "enum", AccountID: "111111111111", Region: "ap-south-1",
			Mode: "test", ToolVersion: "test",
			Assets: []models.CryptoAsset{{
				BomRef: "crypto-" + name, Name: name, Service: "kms_spec",
				Category: models.CategoryKeyManagement, AccountID: "111111111111",
				Region: "ap-south-1", ResourceID: name, DiscoveredAt: now,
				Properties:  map[string]string{"posture": "non-pqc-classical"},
				CryptoProps: cp,
			}},
		}
	}

	// Every algorithm primitive constant.
	primitives := []models.AlgorithmPrimitive{
		models.PrimitiveAE, models.PrimitiveBlockCipher, models.PrimitiveKEM,
		models.PrimitiveSignature, models.PrimitiveHash, models.PrimitiveKeyAgree,
		models.PrimitiveKDF, models.PrimitiveMAC,
	}
	for _, p := range primitives {
		t.Run("primitive="+string(p), func(t *testing.T) {
			validateCBOM(t, schema, buildCBOM(base("alg", models.CryptoProperties{
				AssetType:           models.AssetTypeAlgorithm,
				AlgorithmProperties: &models.AlgorithmProperties{Primitive: p},
			})))
		})
	}

	// Every CryptoState constant on a related-material asset (StateUnknown must be
	// dropped by sanitizeForCDX, so this also proves the guard holds end-to-end).
	for _, s := range []models.CryptoState{models.StateActive, models.StateSuspended, models.StateDestroyed, models.StateUnknown} {
		t.Run("state="+string(s), func(t *testing.T) {
			validateCBOM(t, schema, buildCBOM(base("rcm", models.CryptoProperties{
				AssetType: models.AssetTypeRelatedMaterial,
				RelatedCryptoMaterialProperties: &models.RelatedCryptoMaterialProperties{
					Type: "secret-key", State: s,
				},
			})))
		})
	}

	// Non-enum algorithm modes (e.g. "xts" for EBS/FSx/MGN disk encryption) must be
	// remapped to a valid CDX enum member by sanitizeForCDX, with the true mode
	// preserved on cryptamap:mode. Validates the guard end-to-end.
	t.Run("mode=xts-remapped", func(t *testing.T) {
		scan := base("xts", models.CryptoProperties{
			AssetType: models.AssetTypeAlgorithm,
			AlgorithmProperties: &models.AlgorithmProperties{
				Primitive: models.PrimitiveAE, Mode: "xts", AlgorithmName: "AES-256-XTS",
			},
		})
		bom := buildCBOM(scan)
		validateCBOM(t, schema, bom) // must be schema-valid despite the "xts" input
		// And the true mode must survive as a flat prop.
		var sawMode bool
		for _, c := range bom.Components {
			if c.BomRef != "crypto-xts" {
				continue
			}
			if c.CryptoProperties != nil && c.CryptoProperties.AlgorithmProperties != nil {
				if m := c.CryptoProperties.AlgorithmProperties.Mode; m != "" && !validCDXMode(m) {
					t.Errorf("non-enum mode %q leaked into schema field", m)
				}
			}
			if v, ok := propValue(c, "cryptamap:mode"); ok && v == "xts" {
				sawMode = true
			}
		}
		if !sawMode {
			t.Error("true mode 'xts' was not preserved as cryptamap:mode")
		}
	})

	// Every assetType constant.
	for _, at := range []models.AssetType{models.AssetTypeAlgorithm, models.AssetTypeCertificate, models.AssetTypeProtocol, models.AssetTypeRelatedMaterial} {
		t.Run("assetType="+string(at), func(t *testing.T) {
			cp := models.CryptoProperties{AssetType: at}
			switch at {
			case models.AssetTypeAlgorithm:
				cp.AlgorithmProperties = &models.AlgorithmProperties{Primitive: models.PrimitiveAE}
			case models.AssetTypeCertificate:
				cp.CertificateProperties = &models.CertificateProperties{CertificateFormat: "X.509"}
			case models.AssetTypeProtocol:
				cp.ProtocolProperties = &models.ProtocolProperties{Type: "tls"}
			case models.AssetTypeRelatedMaterial:
				cp.RelatedCryptoMaterialProperties = &models.RelatedCryptoMaterialProperties{Type: "key"}
			}
			validateCBOM(t, schema, buildCBOM(base("at", cp)))
		})
	}
}

// TestRelatedMaterial_EnumConformance asserts the related-crypto-material path
// emits ONLY schema-valid enum values. It exercises the exact shapes the real
// scanners produce — including the previously-invalid state "unknown" — and
// requires the marshaled cryptoProperties to carry a valid (or omitted) state.
func TestRelatedMaterial_EnumConformance(t *testing.T) {
	now := time.Now().UTC()
	mk := func(name string, cp models.CryptoProperties) models.CryptoAsset {
		return models.CryptoAsset{
			BomRef: "crypto-" + name, Name: name, Service: "kms_spec",
			Category: models.CategoryKeyManagement, AccountID: "111111111111",
			Region: "ap-south-1", ResourceID: name, DiscoveredAt: now,
			Properties:  map[string]string{"posture": "non-pqc-classical"},
			CryptoProps: cp,
		}
	}
	rcm := func(typ string, state models.CryptoState) models.CryptoProperties {
		return models.CryptoProperties{
			AssetType: models.AssetTypeRelatedMaterial,
			RelatedCryptoMaterialProperties: &models.RelatedCryptoMaterialProperties{
				Type: typ, State: state,
			},
		}
	}
	scan := models.ScanResult{
		ScanID: "rcm-test", AccountID: "111111111111", Region: "ap-south-1",
		Mode: "test", ToolVersion: "test",
		Assets: []models.CryptoAsset{
			mk("hsm", rcm("key", models.StateActive)),                  // CloudHSM (fixed type)
			mk("alias", rcm("other", models.StateActive)),              // KMS alias (fixed type)
			mk("secret", rcm("credential", models.StateActive)),        // Secrets Mgr (fixed type)
			mk("unknownstate", rcm("secret-key", models.StateUnknown)), // unknown state must be dropped
		},
	}

	validState := map[string]bool{
		"pre-activation": true, "active": true, "suspended": true,
		"deactivated": true, "compromised": true, "destroyed": true,
	}
	validType := map[string]bool{
		"private-key": true, "public-key": true, "secret-key": true, "key": true,
		"ciphertext": true, "signature": true, "digest": true, "initialization-vector": true,
		"nonce": true, "seed": true, "salt": true, "shared-secret": true, "tag": true,
		"additional-data": true, "password": true, "credential": true, "token": true,
		"other": true, "unknown": true,
	}

	bom := buildCBOM(scan)
	checked := 0
	for _, c := range bom.Components {
		if isSyntheticComponent(c) || c.CryptoProperties == nil {
			continue
		}
		rcmp := c.CryptoProperties.RelatedCryptoMaterialProperties
		if rcmp == nil {
			continue
		}
		checked++
		if !validType[rcmp.Type] {
			t.Errorf("component %q related-material type %q is not a valid CDX 1.7 enum member", c.Name, rcmp.Type)
		}
		if rcmp.State != "" && !validState[string(rcmp.State)] {
			t.Errorf("component %q related-material state %q is not a valid CDX 1.7 enum member (must be dropped)", c.Name, rcmp.State)
		}
	}
	if checked != 4 {
		t.Fatalf("expected 4 related-material components, checked %d", checked)
	}

	// The unknown-state asset must still carry its state on the flat prop (not lost).
	// Match by bom-ref: the component Name is the friendly "<DisplayName> — <name>".
	var foundFlat bool
	for _, c := range bom.Components {
		if c.BomRef != "crypto-unknownstate" {
			continue
		}
		if v, ok := propValue(c, "cryptamap:materialState"); ok && v == "unknown" {
			foundFlat = true
		}
		// And the schema field must be empty (invalid "unknown" dropped).
		if rcmp := c.CryptoProperties.RelatedCryptoMaterialProperties; rcmp != nil && rcmp.State != "" {
			t.Errorf("unknownstate: invalid state leaked into schema field: %q", rcmp.State)
		}
	}
	if !foundFlat {
		t.Error("unknownstate: dropped state was not preserved as cryptamap:materialState")
	}
}

// TestCryptoGraph_RoundTripExcludesSynthetic asserts ParseCBOM drops the
// synthetic algorithm nodes so they never become phantom assets.
func TestCryptoGraph_RoundTripExcludesSynthetic(t *testing.T) {
	scan := graphScan()
	raw, err := AsBytes(scan)
	if err != nil {
		t.Fatalf("AsBytes: %v", err)
	}
	parsed, err := ParseCBOM(raw)
	if err != nil {
		t.Fatalf("ParseCBOM: %v", err)
	}
	total := 0
	for _, sr := range parsed {
		for _, a := range sr.Assets {
			total++
			// No re-ingested asset may carry an empty account (the synthetic-node
			// signature) or a synthetic marker.
			if a.AccountID == "" {
				t.Errorf("round-tripped asset %q has empty AccountID — a synthetic node leaked through", a.Name)
			}
			if a.Properties["synthetic"] == "true" {
				t.Errorf("round-tripped asset %q carries synthetic=true", a.Name)
			}
		}
	}
	if total != len(scan.Assets) {
		t.Errorf("round-trip asset count %d != original %d (synthetic nodes leaked or assets lost)", total, len(scan.Assets))
	}
}
