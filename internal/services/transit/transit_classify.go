package transit

// transit_classify.go holds the PURE, SDK-free classification helpers used by
// the deepened transit readers (Transfer Family, VPN/IPsec, MSK, OpenSearch).
//
// Keeping the field-to-model mapping logic here — taking only plain Go slices
// and strings, returning models types — means it is unit-testable without any
// live AWS client. The readers themselves become thin SDK-extraction shims that
// nil-guard the SDK pointers and then call into these helpers.

import (
	"fmt"
	"strings"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// isMLKEMKex reports whether an SSH key-exchange algorithm name denotes an
// ML-KEM (post-quantum) hybrid group. AWS Transfer Family's PQ-SSH policies
// expose KEX names like "mlkem768x25519-sha256", "mlkem768nistp256-sha256",
// and "mlkem1024nistp384-sha384". The match is case-insensitive and tolerates
// both the "mlkem" and "ml-kem" spellings.
func isMLKEMKex(kex string) bool {
	k := strings.ToLower(kex)
	return strings.Contains(k, "mlkem") || strings.Contains(k, "ml-kem")
}

// postureFromTransferKexs infers a CryptoPosture from the SSH KEX list of a
// Transfer Family security policy. If any KEX is an ML-KEM hybrid the posture
// is PQC-hybrid; otherwise (when at least one KEX is present) it is classical.
// When the list is empty it returns the empty posture so the caller can keep
// its own fallback (e.g. the legacy policy-name string match).
func postureFromTransferKexs(kexs []string) models.CryptoPosture {
	if len(kexs) == 0 {
		return models.CryptoPosture("")
	}
	for _, k := range kexs {
		if isMLKEMKex(k) {
			return models.PosturePQCHybrid
		}
	}
	return models.PostureNonPQCClassical
}

// classifyTransferPolicy maps a Transfer Family server security policy's SSH and
// TLS algorithm lists into ProtocolProperties{Type:"ssh"}. It emits one cipher
// suite each for the KEX, cipher, and MAC lists (plus a separate tls-ciphers
// suite when TLS ciphers are present), sets KeyExchangeGroup to the first KEX,
// and flags PQCHybrid when any KEX is an ML-KEM hybrid group.
func classifyTransferPolicy(kexs, ciphers, macs, tlsCiphers []string) models.CryptoProperties {
	pp := &models.ProtocolProperties{Type: "ssh"}

	if len(kexs) > 0 {
		pp.KeyExchangeGroup = kexs[0]
		pp.CipherSuites = append(pp.CipherSuites, models.CipherSuite{
			Name:       "ssh-kex",
			Algorithms: append([]string(nil), kexs...),
		})
		for _, k := range kexs {
			if isMLKEMKex(k) {
				pp.PQCHybrid = true
				break
			}
		}
	}
	if len(ciphers) > 0 {
		pp.CipherSuites = append(pp.CipherSuites, models.CipherSuite{
			Name:       "ssh-ciphers",
			Algorithms: append([]string(nil), ciphers...),
		})
	}
	if len(macs) > 0 {
		pp.CipherSuites = append(pp.CipherSuites, models.CipherSuite{
			Name:       "ssh-macs",
			Algorithms: append([]string(nil), macs...),
		})
	}
	if len(tlsCiphers) > 0 {
		pp.CipherSuites = append(pp.CipherSuites, models.CipherSuite{
			Name:       "tls-ciphers",
			Algorithms: append([]string(nil), tlsCiphers...),
		})
	}

	return models.CryptoProperties{
		AssetType:          models.AssetTypeProtocol,
		ProtocolProperties: pp,
	}
}

// classifyVPNTunnel maps the negotiated IPsec/IKE algorithms of a Site-to-Site
// VPN tunnel into ProtocolProperties{Type:"ipsec"}. Encryption and integrity
// algorithms (phase 1 + phase 2) become cipher suites, the IKE versions become
// IkeV2TransformTypes, and the first DH group number becomes the
// KeyExchangeGroup label (e.g. "DH-group-20").
//
// NOTE: AWS DH groups 20/21/24 are classical ECP/MODP groups, NOT post-quantum,
// so PQCHybrid is left false here — VPN has no PQ KEX option today.
func classifyVPNTunnel(phase1Enc, phase2Enc, phase1Integ, phase2Integ []string, dhGroups []int32, ikeVersions []string) models.CryptoProperties {
	pp := &models.ProtocolProperties{Type: "ipsec"}

	enc := dedupeStrings(append(append([]string(nil), phase1Enc...), phase2Enc...))
	if len(enc) > 0 {
		pp.CipherSuites = append(pp.CipherSuites, models.CipherSuite{
			Name:       "ipsec-encryption",
			Algorithms: enc,
		})
	}
	integ := dedupeStrings(append(append([]string(nil), phase1Integ...), phase2Integ...))
	if len(integ) > 0 {
		pp.CipherSuites = append(pp.CipherSuites, models.CipherSuite{
			Name:       "ipsec-integrity",
			Algorithms: integ,
		})
	}
	if len(ikeVersions) > 0 {
		pp.IkeV2TransformTypes = dedupeStrings(append([]string(nil), ikeVersions...))
	}
	if len(dhGroups) > 0 {
		pp.KeyExchangeGroup = fmt.Sprintf("DH-group-%d", dhGroups[0])
	}

	return models.CryptoProperties{
		AssetType:          models.AssetTypeProtocol,
		ProtocolProperties: pp,
	}
}

// classifyMSKTransit maps an MSK cluster's client-broker encryption setting and
// optional in-cluster (broker-to-broker) encryption flag into a TLS protocol
// block plus posture. inClusterStr is "" when the flag was not present, else
// "true"/"false" — the caller stamps it into Properties["inClusterEncryption"].
//
// The ClientBroker enum is DEFINITIONAL (per the kafka SDK doc + MSK developer
// guide): "TLS" enables TLS-only client-broker traffic; "TLS_PLAINTEXT" enables
// BOTH TLS-encrypted AND plaintext traffic; "PLAINTEXT" is plaintext-only. A
// TLS_PLAINTEXT cluster therefore must NOT be reported identically to a pure-TLS
// cluster — it is a mixed/not-fully-enforced state. enforced is "true" only for
// pure "TLS", "false" for the plaintext-accepting modes; the caller stamps it
// into Properties["transitEncryptionEnforced"] and the raw clientBroker value
// into Properties["clientBroker"].
func classifyMSKTransit(clientBroker string, inCluster *bool) (ver, suite string, posture models.CryptoPosture, props models.CryptoProperties, inClusterStr, enforced string) {
	ver = "1.2"
	suite = "AWS-managed"
	posture = models.PostureNonPQCClassical
	enforced = "true"

	switch strings.ToUpper(clientBroker) {
	case "PLAINTEXT":
		posture = models.PostureNoEncryption
		ver = "none"
		suite = "PLAINTEXT"
		enforced = "false"
	case "TLS_PLAINTEXT":
		// Mixed mode: TLS offered but plaintext still accepted. There is no
		// PostureMixed constant; legacy-tls is the closest weakened-transit
		// signal (it is provably NOT fully-enforced TLS). Keep a classical-TLS
		// protocol block but mark it not-enforced.
		posture = models.PostureLegacyTLS
		suite = "TLS_PLAINTEXT-mixed"
		enforced = "false"
	case "TLS":
		// TLS-only — plaintext refused.
		posture = models.PostureNonPQCClassical
		enforced = "true"
	}

	if inCluster != nil {
		if *inCluster {
			inClusterStr = "true"
		} else {
			inClusterStr = "false"
		}
	}

	// suite here is a state label ("AWS-managed", "PLAINTEXT", "TLS_PLAINTEXT-mixed"),
	// not an algorithm — record it as the suite Name only. CipherSuite.Algorithms is
	// a CycloneDX refType array (bom-refs to algorithm components); a label must not
	// be copied into it (it would be a dangling reference).
	props = models.CryptoProperties{
		AssetType: models.AssetTypeProtocol,
		ProtocolProperties: &models.ProtocolProperties{
			Type:    "tls",
			Version: ver,
			CipherSuites: []models.CipherSuite{{
				Name: suite,
			}},
		},
	}
	return ver, suite, posture, props, inClusterStr, enforced
}

// classifyOpenSearchTLSPolicy maps an OpenSearch domain's TLSSecurityPolicy
// enum value to a TLS version and posture. It matches the REAL enum constants
// (correcting the previous bogus "1-2-pq" substring match, which matched no
// real policy). None of the real OpenSearch TLS policies are post-quantum, so
// pqcHybrid is never set true.
func classifyOpenSearchTLSPolicy(policy string) (ver string, posture models.CryptoPosture, pqcHybrid bool) {
	switch policy {
	case "Policy-Min-TLS-1-0-2019-07":
		return "1.0", models.PostureLegacyTLS, false
	case "Policy-Min-TLS-1-2-2019-07":
		return "1.2", models.PostureNonPQCClassical, false
	case "Policy-Min-TLS-1-2-PFS-2023-10":
		// TLS 1.2 up to 1.3 with perfect forward secrecy — classical PFS, not PQ.
		return "1.3", models.PostureNonPQCClassical, false
	case "Policy-Min-TLS-1-2-RFC9151-FIPS-2024-08":
		// TLS 1.3 + FIPS — classical, not PQ.
		return "1.3", models.PostureNonPQCClassical, false
	default:
		// Empty or unrecognized policy: conservative classical default.
		return "1.2", models.PostureNonPQCClassical, false
	}
}

// openSearchEnforceHTTPSOverride decides whether an OpenSearch domain's
// DomainEndpointOptions.EnforceHTTPS pointer downgrades a classical-TLS verdict
// to no-encryption. EnforceHTTPS=false means the endpoint accepts plaintext HTTP
// connections regardless of the configured TLSSecurityPolicy (the policy floor
// only governs HTTPS when it happens to be used), so the domain must NOT be
// reported as clean classical TLS — mirroring MSK's TLS_PLAINTEXT and
// elasticache's "preferred" mixed-mode handling. It returns plaintextAllowed
// true only when the pointer is non-nil and false; a nil pointer (field absent)
// leaves the caller's classical verdict untouched (no fabricated alarm).
func openSearchEnforceHTTPSOverride(enforceHTTPS *bool) (plaintextAllowed bool, note string) {
	if enforceHTTPS != nil && !*enforceHTTPS {
		return true, "OpenSearch domain has EnforceHTTPS disabled; the endpoint permits plaintext HTTP connections, so transit traffic is not guaranteed encrypted (the TLSSecurityPolicy floor applies only when HTTPS is used)."
	}
	return false, ""
}

// classifyIoTSecurityPolicy maps an AWS IoT Core domain-configuration TLS
// security-policy name to a TLS version + posture. The policy names encode the
// minimum TLS version: IoTSecurityPolicy_TLS13_* => TLS 1.3,
// IoTSecurityPolicy_TLS12_* => TLS 1.2. AWS IoT Core supports ONLY TLS 1.2 and
// 1.3 — it has no TLS 1.0/1.1 endpoint — so the "_1_0" token in a policy name
// (e.g. IoTSecurityPolicy_TLS12_1_0_2022_10) is a CIPHER-SET vintage, not a TLS
// 1.0 floor; those policies are negotiated under TLS 1.2 per the IoT policy table.
// Classifying "TLS12_1_0" as legacy TLS 1.0 was a FALSE-ALARM. No IoT security
// policy is post-quantum today, so the posture is never PQC-hybrid. An empty/
// unrecognized policy returns ("", PostureUnknown) so a guessed default never
// masquerades as observed.
func classifyIoTSecurityPolicy(policy string) (ver string, posture models.CryptoPosture) {
	up := strings.ToUpper(policy)
	switch {
	case strings.Contains(up, "TLS13"):
		return "1.3", models.PostureNonPQCClassical
	case strings.Contains(up, "TLS12"):
		// Covers both TLS12_1_2_* and the older TLS12_1_0_* cipher-set vintage —
		// both negotiate under TLS 1.2 (IoT Core has no TLS 1.0/1.1 endpoint).
		return "1.2", models.PostureNonPQCClassical
	default:
		return "", models.PostureUnknown
	}
}

// dbCertKeyFamily maps an RDS/Aurora/DocumentDB CA-certificate identifier to
// the leaf server certificate's signature-algorithm label and public-key size
// in bits. The CA id (e.g. "rds-ca-rsa2048-g1", "rds-ca-ecc384-g1",
// "rds-ca-rsa4096-g1") encodes the key family of the server cert it signs — a
// genuine PQ-relevant signal (RSA vs ECDSA, 2048 vs 4096 vs P-384). Returns
// ("", 0) for an unrecognized id so nothing is fabricated. Matched
// case-insensitively on substrings to tolerate the "-g1"/"-g2" generation
// suffixes AWS appends.
func dbCertKeyFamily(caID string) (sigAlgo string, keyBits int) {
	c := strings.ToLower(caID)
	switch {
	case strings.Contains(c, "ecc384"):
		return "ecdsa-with-SHA384", 384
	case strings.Contains(c, "ecc256"):
		return "ecdsa-with-SHA256", 256
	case strings.Contains(c, "rsa4096"):
		return "sha384WithRSAEncryption", 4096
	case strings.Contains(c, "rsa2048"):
		return "sha256WithRSAEncryption", 2048
	default:
		return "", 0
	}
}

// dbSSLEnforcement is the tri-state result of inspecting an RDS/Aurora DB (or
// cluster) parameter group for an enforce-TLS toggle. RDS rates a DB
// "encrypted-in-transit" only because TLS is AVAILABLE — clients may still
// connect in plaintext unless the engine is told to require TLS. The toggle is
//   - require_secure_transport=1  (MySQL / Aurora-MySQL, MariaDB)
//   - rds.force_ssl=1             (PostgreSQL / Aurora-PostgreSQL)
//
// "unknown" (the zero value) means the parameter group could not be read or the
// toggle was absent — neither a confirmed all-clear nor a confirmed gap, so the
// honesty contract leaves the cert-derived posture untouched rather than
// fabricating an alarm.
type dbSSLEnforcement string

const (
	dbSSLUnknown     dbSSLEnforcement = "unknown"
	dbSSLEnforced    dbSSLEnforcement = "enforced"
	dbSSLNotEnforced dbSSLEnforcement = "not-enforced"
)

// dbSSLEnforceParamNames are the engine-family parameters that, when set to "1",
// force every client connection to negotiate TLS. Matched case-insensitively.
var dbSSLEnforceParamNames = map[string]struct{}{
	"require_secure_transport": {},
	"rds.force_ssl":            {},
}

// classifyDBSSLEnforcement scans a parameter-group's name->value pairs for the
// enforce-TLS toggle and reports the tri-state enforcement. The reader (an SDK
// shim) supplies a plain map so this stays SDK-free and unit-testable. It
// returns dbSSLUnknown when no relevant parameter is present so a missing toggle
// never reads as either an all-clear or an alarm. A value of "1" (or
// "true"/"on") means enforced; any other explicit value means not-enforced.
func classifyDBSSLEnforcement(params map[string]string) dbSSLEnforcement {
	result := dbSSLUnknown
	for name, value := range params {
		if _, ok := dbSSLEnforceParamNames[strings.ToLower(name)]; !ok {
			continue
		}
		if strings.TrimSpace(value) == "" {
			// Toggle present but unset (engine default). RDS defaults both
			// toggles to off, so an unset value is a real not-enforced state.
			result = dbSSLNotEnforced
			continue
		}
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "1", "true", "on":
			return dbSSLEnforced
		default:
			result = dbSSLNotEnforced
		}
	}
	return result
}

// dedupeStrings returns the input with empty entries dropped and duplicates
// removed, preserving first-seen order. Used to keep VPN cipher-suite lists
// tidy when phase 1 and phase 2 share algorithms across tunnels.
func dedupeStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
