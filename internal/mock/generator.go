package mock

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// Generator emits synthetic CryptoAssets for one (account, region) at a configurable scale.
type Generator struct {
	AccountID string
	Region    string
	Scale     int
	Seed      int64
}

// PostureFor returns the posture chosen by Template's distribution.
func PostureFor(t Template, r *rand.Rand) models.CryptoPosture {
	roll := r.Intn(100)
	cum := 0
	if cum += t.PctNoEncryption; roll < cum {
		return models.PostureNoEncryption
	}
	if cum += t.PctLegacyTLS; roll < cum {
		return models.PostureLegacyTLS
	}
	if cum += t.PctNonPQCClassical; roll < cum {
		return models.PostureNonPQCClassical
	}
	if cum += t.PctPQCHybrid; roll < cum {
		return models.PosturePQCHybrid
	}
	if cum += t.PctSymmetricOnly; roll < cum {
		return models.PostureSymmetricOnly
	}
	return models.PostureUnknown
}

// renderAlgorithmProps fills algorithmProperties for a given category + posture.
func renderAlgorithmProps(category models.Category, posture models.CryptoPosture) (models.AlgorithmProperties, string) {
	switch category {
	case models.CategoryDataAtRest:
		return models.AlgorithmProperties{
			Primitive: models.PrimitiveAE, Mode: "gcm",
			ParameterSetIdentifier: "256",
			ClassicalSecurityLevel: 256, NistQuantumSecurityLevel: 5, // AES-256 anchors NIST Category 5
		}, "AES-256-GCM"
	case models.CategoryDataInTransit:
		switch posture {
		case models.PostureLegacyTLS:
			return models.AlgorithmProperties{
				Primitive: models.PrimitiveKeyAgree, ParameterSetIdentifier: "2048",
				ClassicalSecurityLevel: 112,
			}, "TLS-RSA-AES128-CBC-SHA"
		case models.PostureNonPQCClassical:
			return models.AlgorithmProperties{
				Primitive: models.PrimitiveKeyAgree, Curve: "secp256r1",
				ClassicalSecurityLevel: 128,
			}, "TLS_AES_256_GCM_SHA384"
		case models.PosturePQCHybrid:
			return models.AlgorithmProperties{
				Primitive: models.PrimitiveKEM, ParameterSetIdentifier: "768",
				ClassicalSecurityLevel: 192, NistQuantumSecurityLevel: 3,
			}, "X25519+ML-KEM-768"
		}
		return models.AlgorithmProperties{Primitive: models.PrimitiveKeyAgree}, "TLS"
	case models.CategoryCertificate:
		switch posture {
		case models.PostureNonPQCClassical:
			return models.AlgorithmProperties{
				Primitive: models.PrimitiveSignature, ParameterSetIdentifier: "2048",
				ClassicalSecurityLevel: 112,
			}, "RSA-PSS-SHA-256-2048"
		case models.PosturePQCHybrid:
			return models.AlgorithmProperties{
				Primitive: models.PrimitiveSignature, ParameterSetIdentifier: "ML-DSA-65",
				NistQuantumSecurityLevel: 3,
			}, "ML-DSA-65"
		}
		return models.AlgorithmProperties{
			Primitive: models.PrimitiveSignature, Curve: "secp256r1",
			ClassicalSecurityLevel: 128,
		}, "ECDSA-P256-SHA256"
	case models.CategoryKeyManagement:
		switch posture {
		case models.PosturePQCHybrid:
			return models.AlgorithmProperties{
				Primitive: models.PrimitiveKEM, ParameterSetIdentifier: "ML-KEM-768",
				NistQuantumSecurityLevel: 3,
			}, "ML-KEM-768"
		case models.PostureNonPQCClassical:
			// A non-PQC-classical KMS key is an ASYMMETRIC RSA/ECC key (signature
			// primitive), NOT symmetric AES — keep the spec consistent with the
			// posture so the panel doesn't show "AES-256" next to a classical-broken
			// label.
			return models.AlgorithmProperties{
				Primitive: models.PrimitiveSignature, ParameterSetIdentifier: "2048",
				ClassicalSecurityLevel: 112,
			}, "RSA_2048"
		}
		return models.AlgorithmProperties{
			Primitive: models.PrimitiveAE, ParameterSetIdentifier: "256",
			ClassicalSecurityLevel: 256, NistQuantumSecurityLevel: 5, // AES-256 anchors NIST Category 5
		}, "SYMMETRIC_DEFAULT (AES-256)"
	case models.CategorySDKLibrary:
		switch posture {
		case models.PosturePQCHybrid:
			return models.AlgorithmProperties{
				Primitive: models.PrimitiveKEM, ParameterSetIdentifier: "ML-KEM-768",
				NistQuantumSecurityLevel: 3,
			}, "AWS-LC-PQC"
		}
		return models.AlgorithmProperties{
			Primitive: models.PrimitiveKeyAgree, Curve: "secp256r1",
			ClassicalSecurityLevel: 128,
		}, "AWS-LC-Classical"
	}
	return models.AlgorithmProperties{}, "unknown"
}

// mlkemHybridGroups is the doc-known hybrid PQ key-exchange group set that AWS
// PQ TLS policies (ELB/API Gateway "-PQ-2025-09") support. Used as a faithful
// "supported" KEX label on mock PQ-hybrid in-transit assets.
const mlkemHybridGroups = "SecP256r1MLKEM768,SecP384r1MLKEM1024,X25519MLKEM768"

// mockCertBearingServices are the in-transit asset types whose REAL scanner can
// fill cert signature algorithm + key size by resolving a bound ACM cert. The
// mock mirrors that so the demo dashboard shows cert detail where it is genuinely
// obtainable (and stays blank where it is not — e.g. nlb/cloudtrail_evidence).
var mockCertBearingServices = map[string]bool{
	"apigw_rest":         true,
	"apigw_http":         true,
	"cloudfront":         true,
	"alb":                true,
	"redshift_transit":   true,
	"opensearch_transit": true,
}

// enrichMockProtocolDetail fills the KEX-group / PQC-hybrid / cert fields on a
// mock in-transit ProtocolProperties to match the real-scanner completeness
// contract. It NEVER fabricates a handshake-only negotiated KEX onto a config-
// scan asset: the only "negotiated" KEX belongs to cloudtrail_evidence (runtime
// observed); PQ-policy services get the doc-known SUPPORTED group set; cert-
// bearing services get a representative ACM cert sig/key.
func enrichMockProtocolDetail(service string, posture models.CryptoPosture, pp *models.ProtocolProperties) {
	hybrid := posture == models.PosturePQCHybrid
	// TLS floor (minimum accepted version): a legacy-TLS asset floors at 1.0; a
	// PQC-hybrid asset floors at 1.3 (PQ requires TLS 1.3); everything else 1.2.
	// Property only — never a posture/tier. Skip for non-TLS protocol types.
	if pp.Type == "tls" {
		switch {
		case posture == models.PostureLegacyTLS:
			pp.TLSMinVersion = "1.0"
		case hybrid:
			pp.TLSMinVersion = "1.3"
		default:
			pp.TLSMinVersion = "1.2"
		}
	}
	switch service {
	case "cloudtrail_evidence":
		// Runtime-observed negotiated group (the one place a real negotiated KEX is
		// knowable). Show a concrete ML-KEM group on the hybrid assets.
		if hybrid {
			pp.KeyExchangeGroup = "X25519MLKEM768"
			pp.PQCHybrid = true
		} else {
			pp.KeyExchangeGroup = "x25519"
		}
	case "alb", "nlb", "apigw_rest":
		// PQ security-policy services: the policy NAME enables hybrid PQ; the groups
		// are a doc-sourced SUPPORTED set, not a negotiated one.
		if hybrid {
			pp.PQCHybrid = true
			pp.KeyExchangeGroup = mlkemHybridGroups
		}
	case "transferfamily":
		// Transfer Family is SSH, not TLS: model it as the real transferfamily
		// scanner does (classifyTransferPolicy). The KEX/cipher/MAC suites carry the
		// genuine SSH algorithm tokens AWS DescribeSecurityPolicy returns, so the
		// CBOM emitter links them into the protocol->algorithm crypto graph. PQ
		// assets enable the ML-KEM hybrid SSH KEX group.
		pp.Type = "ssh"
		pp.Version = ""
		pp.TLSMinVersion = ""
		kexAlgos := []string{"ecdh-sha2-nistp256"}
		pp.KeyExchangeGroup = "ecdh-sha2-nistp256"
		if hybrid {
			pp.PQCHybrid = true
			pp.KeyExchangeGroup = "mlkem768x25519-sha256"
			// PQ asset offers the hybrid group first, classical as fallback.
			kexAlgos = []string{"mlkem768x25519-sha256", "ecdh-sha2-nistp256"}
		}
		pp.CipherSuites = []models.CipherSuite{
			{Name: "ssh-kex", Algorithms: kexAlgos},
			{Name: "ssh-ciphers", Algorithms: []string{"aes256-gcm@openssh.com", "aes128-ctr"}},
			{Name: "ssh-macs", Algorithms: []string{"hmac-sha2-256", "hmac-sha2-512"}},
		}
	case "vpn":
		// Site-to-Site VPN is IPsec, not TLS: model it as the real VPN scanner does
		// (classifyVPNTunnel). The encryption/integrity suites carry the genuine
		// IPsec algorithm tokens the EC2 VPN API returns, so they link into the
		// crypto graph. AWS VPN has no PQ KEX option, so PQCHybrid stays false.
		pp.Type = "ipsec"
		pp.Version = ""
		pp.TLSMinVersion = ""
		pp.PQCHybrid = false
		pp.KeyExchangeGroup = "DH-group-20"
		pp.IkeV2TransformTypes = []string{"ikev2"}
		pp.CipherSuites = []models.CipherSuite{
			{Name: "ipsec-encryption", Algorithms: []string{"AES256-GCM-16"}},
			{Name: "ipsec-integrity", Algorithms: []string{"SHA2-256"}},
		}
	}
	// Cert signature algorithm + key size for cert-bearing services (ACM is
	// classical-only, so a representative RSA-2048 cert). Skipped for non-cert
	// types (nlb/cloudtrail_evidence/db-transit) where it is not applicable.
	if mockCertBearingServices[service] {
		pp.CertSignatureAlgorithm = "SHA256WITHRSA"
		pp.CertKeySizeBits = 2048
	}
}

// GenerateAssets returns scale assets per template.
func (g *Generator) GenerateAssets() []models.CryptoAsset {
	r := rand.New(rand.NewSource(g.Seed))
	if g.Scale <= 0 {
		g.Scale = 20
	}
	templates := Templates()
	assets := make([]models.CryptoAsset, 0, g.Scale*len(templates))
	// Reference time for synthetic cert validity windows. FIXED (not time.Now) so a
	// given Seed yields byte-identical output across runs — required for the
	// committed demo artifact's `gen-dashboard-mock -check` CI guard and for clean
	// diffs. Mock cert dates are illustrative only, so a fixed epoch is correct.
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, t := range templates {
		for i := 0; i < g.Scale; i++ {
			posture := PostureFor(t, r)
			algProps, algName := renderAlgorithmProps(t.Category, posture)
			name := fmt.Sprintf(t.NamePattern, i)
			arn := fmt.Sprintf("arn:aws:%s:%s:%s:%s/%s", t.Service, g.Region, g.AccountID, t.ResourceType, name)
			cp := models.CryptoProperties{
				AssetType:           models.AssetTypeAlgorithm,
				AlgorithmProperties: &algProps,
			}
			if t.Category == models.CategoryDataInTransit {
				cp.AssetType = models.AssetTypeProtocol
				cp.AlgorithmProperties = nil
				ver := "1.2"
				if posture == models.PostureLegacyTLS {
					ver = "1.0"
				}
				if posture == models.PosturePQCHybrid {
					ver = "1.3"
				}
				// algName labels the negotiated suite (Name only). It is NOT copied
				// into Algorithms: that is a CycloneDX refType array (bom-refs to
				// algorithm components), so a suite name / label there would be a
				// dangling reference. This mirrors the real TLS scanners
				// (services.TLSProtocolProps). The crypto dependency graph is
				// demonstrated via the certificate signatureAlgorithmRef links below.
				pp := &models.ProtocolProperties{
					Type:    "tls",
					Version: ver,
					CipherSuites: []models.CipherSuite{{
						Name: algName,
					}},
				}
				// Faithful crypto-detail enrichment (mirrors the real-scanner
				// completeness contract): only populate fields a REAL config/observed
				// scan could fill for this asset type — never fabricate a handshake-
				// only field onto a config-scan asset.
				enrichMockProtocolDetail(t.Service, posture, pp)
				cp.ProtocolProperties = pp
			}
			if t.Category == models.CategoryCertificate {
				cp.AssetType = models.AssetTypeCertificate
				cp.CertificateProperties = &models.CertificateProperties{
					SubjectName:           "CN=" + name + ".example.com",
					IssuerName:            "CN=Amazon RSA 2048 M01",
					NotValidBefore:        now.AddDate(0, -6, 0),
					NotValidAfter:         now.AddDate(1, 0, 0),
					SignatureAlgorithmRef: algName,
					CertificateFormat:     "X.509",
				}
			}
			// Flat cryptamap:* detail props the dashboard panel reads (the CDX
			// writer also flattens nested fields here, but the mock sets them
			// directly so AlgorithmDetail shows a friendly algorithm name + key
			// spec instead of a raw primitive code / blank).
			detailProps := map[string]string{
				"posture": string(posture),
			}
			// A no-encryption verdict must NEVER be bare: the real scanners attach an
			// explanatory note (e.g. s3.go's "no explicit bucket encryption rule …")
			// so a regulator-facing "no-encryption" is always accompanied by the WHY,
			// never a confident, context-free alarm. The mock mirrors that contract so
			// the systemic honesty-invariant suite (internal/scanner/invariants_test.go)
			// exercises it on deterministic data.
			if posture == models.PostureNoEncryption {
				detailProps["note"] = fmt.Sprintf(
					"No encryption configuration detected for this %s resource; flagged for review. (synthetic mock asset)",
					t.Service)
			}
			if t.Category == models.CategoryDataAtRest || t.Category == models.CategoryKeyManagement {
				detailProps["algorithmName"] = algName
				if algProps.Mode != "" {
					detailProps["mode"] = algProps.Mode
				}
				if algProps.ParameterSetIdentifier != "" {
					detailProps["keySizeBits"] = algProps.ParameterSetIdentifier
				}
			}
			// KMS key spec: the panel's dedicated row, kept CONSISTENT with the
			// posture so a key spec never contradicts its label (a non-PQC-classical
			// KMS key is asymmetric RSA, not symmetric AES).
			if t.Service == "kms" || t.Category == models.CategoryKeyManagement {
				switch posture {
				case models.PosturePQCHybrid:
					detailProps["kmsKeySpec"] = "ML_KEM_768"
				case models.PostureNonPQCClassical:
					detailProps["kmsKeySpec"] = "RSA_2048"
				default:
					detailProps["kmsKeySpec"] = "SYMMETRIC_DEFAULT"
				}
			}
			assets = append(assets, models.CryptoAsset{
				BomRef:       models.BomRefForARN(arn),
				Name:         name,
				Description:  fmt.Sprintf("Mock %s asset for %s", t.ResourceType, t.Service),
				Service:      t.Service,
				Category:     t.Category,
				AccountID:    g.AccountID,
				Region:       g.Region,
				ResourceID:   name,
				ResourceARN:  arn,
				ResourceType: t.ResourceType,
				CryptoProps:  cp,
				DiscoveredAt: now,
				Properties:   detailProps,
			})
		}
	}
	return assets
}
