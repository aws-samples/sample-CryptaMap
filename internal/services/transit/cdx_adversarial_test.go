package transit

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
	transfertypes "github.com/aws/aws-sdk-go-v2/service/transfer/types"

	"github.com/aws-samples/cryptamap/internal/output"
	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// TestTransitClassifiers_AdversarialInputs is the "Edge #2" hardening pass for
// the transit package: it feeds the protocol-shape hot paths — the pure classify
// helpers (classifyVPNTunnel / classifyTransferPolicy / classifyMSKTransit /
// classifySSLPolicy / classifyOpenSearchTLSPolicy / classifyIoTSecurityPolicy)
// and a couple of scan() seams — with HOSTILE inputs that real AWS can return but
// the happy-path fakes never exercise: nil pointers, empty slices, all-nil
// resources, UNKNOWN/future enum strings, empty strings, 10k-char strings, and
// mixed valid+garbage algorithm lists (the exact shapes — cipherSuites,
// ikev2TransformTypes, protocolProperties.type — where prior CycloneDX-shape bugs
// lived).
//
// The contract per case is ONLY:
//
//	(i) the call NEVER panics (a per-case deferred recover() turns any panic into
//	    a t.Errorf carrying the triggering input — the process is not crashed), and
//	(ii) whenever it produces >=1 asset, the emitted CBOM passes the official
//	    CycloneDX 1.7 schema (output.ValidateAssetsCBOM). Returning 0 assets or an
//	    error on garbage is acceptable; a PANIC or a schema-validation failure on
//	    non-empty output is a REAL ROBUSTNESS BUG and is left failing + reported.
//
// CONFIRMED ROBUSTNESS BUG (this test is RED on purpose — do NOT delete the
// triggering cases; the fix belongs in the scanner source, not here):
//
//	The transit classify helpers copy a raw AWS algorithm list straight into
//	models.CipherSuite.Algorithms WITHOUT dropping empty strings:
//	  - classifyTransferPolicy (transit_classify.go:55-83): the ssh-kex / ssh-ciphers
//	    / ssh-macs / tls-ciphers suites do `Algorithms: append([]string(nil), <list>...)`.
//	  - classifySSLPolicy (ssl_policy.go:134-149 build + :182-187 emit): the
//	    "tls-ciphers" suite's Algorithms includes any `*c.Name` whose value is ""
//	    (only nil names are skipped, not empty-string names).
//	The CycloneDX 1.7 schema constrains cipherSuites[].algorithms[] items to a
//	refType with minLength >= 1 (testdata/schemas/cryptography-defs.schema.json),
//	so a single "" entry — which AWS APIs CAN return (e.g. a blank/omitted cipher
//	name, or a future policy with an empty algorithm token) — produces a
//	schema-INVALID CBOM. classifyVPNTunnel is NOT affected because it routes its
//	lists through dedupeStrings(), which drops "" (the safe pattern the other two
//	helpers should adopt). Failing cases below: classifyTransferPolicy
//	{empty-strings, mlkem-mixed-garbage, only-tls-ciphers}, classifySSLPolicy
//	{unknown-protocol-versions, mixed-valid-garbage-ciphers}, and
//	scan_transferfamily_adversarial (which reaches classifyTransferPolicy with an
//	"" cipher from the security policy).
func TestTransitClassifiers_AdversarialInputs(t *testing.T) {
	if err := output.ValidateCBOMBytes([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)); err != nil {
		t.Skipf("vendored CDX schema unavailable, skipping adversarial conformance: %v", err)
	}

	const acct, region = "111122223333", "ap-south-1"
	big := strings.Repeat("A", 10000)

	// wrap stamps a classify helper's CryptoProperties into a full asset so the
	// emitted CBOM (the real shape exported to disk) can be schema-validated.
	wrap := func(props models.CryptoProperties) []models.CryptoAsset {
		a := services.NewAsset("transit-adversarial", models.CategoryDataInTransit, acct, region, "res-1", "AWS::Test::Resource", props)
		return []models.CryptoAsset{a}
	}

	// checkAssets is the shared (i)+(ii) assertion for a slice of assets that were
	// produced WITHOUT a panic. err is whatever the producer returned.
	checkAssets := func(t *testing.T, desc string, assets []models.CryptoAsset, err error) {
		t.Helper()
		// An error on adversarial input is acceptable. We only validate the shape
		// of any assets that were nonetheless returned.
		if len(assets) == 0 {
			return
		}
		if verr := output.ValidateAssetsCBOM(assets); verr != nil {
			t.Errorf("[%s] returned %d asset(s) but CBOM FAILED CycloneDX 1.7 schema validation: %v", desc, len(assets), verr)
		}
	}

	// runClassify runs a pure classify helper under panic capture and validates
	// the resulting CryptoProperties as a wrapped asset.
	runClassify := func(t *testing.T, desc string, fn func() models.CryptoProperties) {
		t.Helper()
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("PANIC in classify [%s]: %v", desc, r)
			}
		}()
		props := fn()
		checkAssets(t, desc, wrap(props), nil)
	}

	// ---------------------------------------------------------------------
	// classifyVPNTunnel — ipsec cipherSuites[].algorithms + ikev2TransformTypes +
	// DH KEX label. This builds the exact array shapes where prior bugs lived.
	// ---------------------------------------------------------------------
	t.Run("classifyVPNTunnel", func(t *testing.T) {
		cases := []struct {
			desc                                    string
			p1Enc, p2Enc, p1Int, p2Int, ikeVersions []string
			dhGroups                                []int32
		}{
			{"all-empty-slices", nil, nil, nil, nil, nil, nil},
			{"all-empty-non-nil", []string{}, []string{}, []string{}, []string{}, []string{}, []int32{}},
			{"empty-strings", []string{""}, []string{"", ""}, []string{""}, []string{""}, []string{""}, []int32{0}},
			{"unknown-ike-version", []string{"AES256-GCM-16"}, nil, []string{"SHA2-512"}, nil, []string{"ikev3-future", "IKEv99"}, []int32{99}},
			{"unknown-cipher-tokens", []string{"FUTURE-PQ-CIPHER", "kyber-ipsec"}, []string{"???"}, []string{"unknown-integ"}, nil, []string{"ikev2"}, []int32{20, 21, 24, -1}},
			{"mixed-valid-and-garbage", []string{"AES256-GCM-16", "", "GARBAGE", "AES128"}, []string{"AES256-GCM-16"}, []string{"SHA2-512", "junk", ""}, []string{"SHA2-256"}, []string{"ikev2", "ikev1", "", "futurev9"}, []int32{20, 0, 21}},
			{"huge-strings", []string{big}, []string{big}, []string{big}, []string{big}, []string{big}, []int32{2147483647}},
			{"negative-dh-only", nil, nil, nil, nil, []string{"ikev2"}, []int32{-2147483648}},
		}
		for _, c := range cases {
			c := c
			runClassify(t, "classifyVPNTunnel/"+c.desc, func() models.CryptoProperties {
				return classifyVPNTunnel(c.p1Enc, c.p2Enc, c.p1Int, c.p2Int, c.dhGroups, c.ikeVersions)
			})
		}
	})

	// ---------------------------------------------------------------------
	// classifyTransferPolicy — ssh protocol type + ssh-kex/ssh-ciphers/ssh-macs/
	// tls-ciphers cipherSuites[].algorithms + PQCHybrid flag.
	// ---------------------------------------------------------------------
	t.Run("classifyTransferPolicy", func(t *testing.T) {
		cases := []struct {
			desc                            string
			kexs, ciphers, macs, tlsCiphers []string
		}{
			{"all-empty", nil, nil, nil, nil},
			{"empty-strings", []string{""}, []string{""}, []string{""}, []string{""}},
			{"unknown-kex-tokens", []string{"future-pq-kex", "sntrup761x25519-future"}, []string{"chacha-future"}, []string{"hmac-future"}, []string{"TLS_FUTURE_PQC"}},
			{"mlkem-mixed-garbage", []string{"mlkem768x25519-sha256", "", "GARBAGE", "ml-kem-1024"}, []string{"aes256-gcm@openssh.com", ""}, []string{"hmac-sha2-256", "junk"}, []string{"TLS_AES_128_GCM_SHA256", "garbage"}},
			{"only-tls-ciphers", nil, nil, nil, []string{"TLS_AES_256_GCM_SHA384", ""}},
			{"huge-strings", []string{big}, []string{big}, []string{big}, []string{big}},
		}
		for _, c := range cases {
			c := c
			runClassify(t, "classifyTransferPolicy/"+c.desc, func() models.CryptoProperties {
				return classifyTransferPolicy(c.kexs, c.ciphers, c.macs, c.tlsCiphers)
			})
		}
	})

	// ---------------------------------------------------------------------
	// classifyMSKTransit — tls protocol with name-only cipherSuite; the
	// clientBroker enum is the hot path (unknown value must not corrupt the block).
	// ---------------------------------------------------------------------
	t.Run("classifyMSKTransit", func(t *testing.T) {
		tru := true
		fls := false
		cases := []struct {
			desc         string
			clientBroker string
			inCluster    *bool
		}{
			{"empty-broker", "", nil},
			{"unknown-broker-future", "TLS_QUANTUM_FUTURE", &tru},
			{"unknown-broker-garbage", "????", &fls},
			{"lowercase-tls", "tls", nil},
			{"huge-broker", big, &tru},
			{"plaintext", "PLAINTEXT", &fls},
			{"tls-plaintext-mixed", "TLS_PLAINTEXT", &tru},
		}
		for _, c := range cases {
			c := c
			runClassify(t, "classifyMSKTransit/"+c.desc, func() models.CryptoProperties {
				_, _, _, props, _, _ := classifyMSKTransit(c.clientBroker, c.inCluster)
				return props
			})
		}
	})

	// ---------------------------------------------------------------------
	// classifyOpenSearchTLSPolicy + classifyIoTSecurityPolicy — these return
	// scalars, not full props; wrap them in a minimal TLS protocol block to
	// confirm an unknown/empty/huge policy name never yields a bad enum/shape.
	// ---------------------------------------------------------------------
	t.Run("classifyOpenSearchTLSPolicy", func(t *testing.T) {
		for _, policy := range []string{"", "Policy-Future-TLS-9-9", big, "garbage", "Policy-Min-TLS-1-2-PFS-2023-10"} {
			policy := policy
			runClassify(t, "classifyOpenSearchTLSPolicy/"+truncate(policy), func() models.CryptoProperties {
				ver, _, _ := classifyOpenSearchTLSPolicy(policy)
				return services.TLSProtocolProps(ver, policy)
			})
		}
	})

	t.Run("classifyIoTSecurityPolicy", func(t *testing.T) {
		for _, policy := range []string{"", "IoTSecurityPolicy_FUTURE_2099", big, "garbage", "IoTSecurityPolicy_TLS13_1_2_2022_10"} {
			policy := policy
			runClassify(t, "classifyIoTSecurityPolicy/"+truncate(policy), func() models.CryptoProperties {
				ver, _ := classifyIoTSecurityPolicy(policy)
				// ver may be "" for an unknown policy; TLSProtocolProps must still
				// emit a schema-valid block (empty version is dropped by omitempty).
				return services.TLSProtocolProps(ver, policy)
			})
		}
	})

	// ---------------------------------------------------------------------
	// classifySSLPolicy — the richest tls protocol block: name-only suite,
	// algorithms (tls-ciphers), identifiers (ssl-protocols), PQ KEX path. Feed
	// unknown protocol-version strings, nil cipher names, huge strings, and a
	// mixed valid+garbage cipher list (where a copied-raw value would break schema).
	// ---------------------------------------------------------------------
	t.Run("classifySSLPolicy", func(t *testing.T) {
		cases := []struct {
			desc       string
			policyName string
			sp         elbv2types.SslPolicy
		}{
			{"zero-value", "", elbv2types.SslPolicy{}},
			{
				"unknown-protocol-versions",
				"ELBSecurityPolicy-Future-9-9",
				elbv2types.SslPolicy{
					Name:         aws.String("ELBSecurityPolicy-Future-9-9"),
					SslProtocols: []string{"TLSv9.9", "SSLv2", "", "QUIC"},
					Ciphers:      []elbv2types.Cipher{{Name: aws.String("FUTURE_PQ_CIPHER")}, {Name: nil}, {Name: aws.String("")}},
				},
			},
			{
				"nil-cipher-names",
				"p",
				elbv2types.SslPolicy{
					SslProtocols: []string{"TLSv1.2"},
					Ciphers:      []elbv2types.Cipher{{Name: nil}, {Name: nil}},
				},
			},
			{
				"pq-name-with-legacy-floor",
				"ELBSecurityPolicy-TLS13-1-0-PQ-2025-09",
				elbv2types.SslPolicy{
					Name:         aws.String("ELBSecurityPolicy-TLS13-1-0-PQ-2025-09"),
					SslProtocols: []string{"TLSv1", "TLSv1.3"},
					Ciphers:      []elbv2types.Cipher{{Name: aws.String("X25519MLKEM768")}, {Name: aws.String("GARBAGE")}},
				},
			},
			{
				"huge-strings",
				big,
				elbv2types.SslPolicy{
					Name:         aws.String(big),
					SslProtocols: []string{big, "TLSv1.3"},
					Ciphers:      []elbv2types.Cipher{{Name: aws.String(big)}},
				},
			},
			{
				"mixed-valid-garbage-ciphers",
				"ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
				elbv2types.SslPolicy{
					Name:         aws.String("ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"),
					SslProtocols: []string{"TLSv1.2", "TLSv1.3", "junk"},
					Ciphers: []elbv2types.Cipher{
						{Name: aws.String("TLS_AES_128_GCM_SHA256")},
						{Name: aws.String("")},
						{Name: nil},
						{Name: aws.String("\x00\x01garbage")},
					},
				},
			},
		}
		for _, c := range cases {
			c := c
			runClassify(t, "classifySSLPolicy/"+c.desc, func() models.CryptoProperties {
				return classifySSLPolicy(c.sp, c.policyName).props
			})
		}
	})

	// ---------------------------------------------------------------------
	// Scan-seam adversarial drives. These exercise the SDK-extraction shims that
	// nil-guard pointers before delegating to the classifiers — the layer where a
	// nil-pointer-deref on an assumed-present field would live.
	// ---------------------------------------------------------------------

	// VPN: the scanner walks Options.TunnelOptions and each tunnel's algorithm
	// pointer lists. Feed nil Options, nil TunnelOptions, and a tunnel whose every
	// algorithm pointer is nil — the all-nil-pointers adversarial shape.
	t.Run("scan_vpn_adversarial", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("PANIC in VPNScanner.scan adversarial: %v", r)
			}
		}()
		client := &fakeVPNEC2Client{
			out: &ec2.DescribeVpnConnectionsOutput{
				VpnConnections: []ec2types.VpnConnection{
					{VpnConnectionId: nil, Options: nil},                                                                                   // all-nil
					{VpnConnectionId: vpnStrptr(""), Options: &ec2types.VpnConnectionOptions{}},                                            // empty id, nil TunnelOptions
					{VpnConnectionId: vpnStrptr(big), Options: &ec2types.VpnConnectionOptions{TunnelOptions: []ec2types.TunnelOption{{}}}}, // tunnel with all-nil algorithm pointers
				},
			},
		}
		assets, err := VPNScanner{}.scan(context.Background(), client, acct, region)
		checkAssets(t, "scan_vpn_adversarial", assets, err)
	})

	// Transfer Family: server present but DescribeSecurityPolicy returns a policy
	// with all-nil SSH algorithm slices and an unknown/garbage policy name, plus a
	// server whose security-policy lookup misses entirely.
	t.Run("scan_transferfamily_adversarial", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("PANIC in TransferFamilyScanner.scan adversarial: %v", r)
			}
		}()
		const policy = "TransferSecurityPolicy-Future-9999"
		client := &fakeTransferClient{
			listPages: []*transfer.ListServersOutput{
				{Servers: []transfertypes.ListedServer{
					{ServerId: transferfamilyStrptr("s-empty")},
					{ServerId: nil}, // all-nil server
				}},
			},
			describeServers: map[string]*transfer.DescribeServerOutput{
				"s-empty": transferfamilyServerWithPolicy("s-empty", policy),
			},
			describePolicies: map[string]*transfer.DescribeSecurityPolicyOutput{
				policy: {
					SecurityPolicy: &transfertypes.DescribedSecurityPolicy{
						SecurityPolicyName: transferfamilyStrptr(policy),
						SshKexs:            nil,
						SshCiphers:         []string{"", "garbage"},
						SshMacs:            nil,
						Fips:               nil,
					},
				},
			},
		}
		assets, err := TransferFamilyScanner{}.scan(context.Background(), client, acct, region)
		checkAssets(t, "scan_transferfamily_adversarial", assets, err)
	})

	// ALB SSL-policy resolver: drive the resolver (used by ALB/NLB) with a
	// DescribeSSLPolicies fake returning an all-garbage policy.
	t.Run("ssl_policy_resolver_adversarial", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("PANIC in sslPolicyResolver.resolve adversarial: %v", r)
			}
		}()
		resolver := newSSLPolicyResolver(&fakeAdvSSLPolicy{
			out: &elbv2.DescribeSSLPoliciesOutput{
				SslPolicies: []elbv2types.SslPolicy{
					{Name: aws.String("garbage"), SslProtocols: []string{"TLSv9.9"}, Ciphers: []elbv2types.Cipher{{Name: nil}}},
				},
			},
		})
		// resolve unknown name, empty name, and huge name.
		for _, name := range []string{"unknown-policy-future", "", big} {
			res := resolver.resolve(context.Background(), name)
			checkAssets(t, "ssl_policy_resolver/"+truncate(name), wrap(res.props), nil)
		}
	})
}

// truncate keeps subtest names readable when a 10k-char input is used as the name.
func truncate(s string) string {
	if len(s) > 24 {
		return s[:24] + "...(" + itoa(len(s)) + ")"
	}
	if s == "" {
		return "<empty>"
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// fakeAdvSSLPolicy is a minimal sslPolicyDescribeAPI returning one canned output
// for any DescribeSSLPolicies call (the resolver caches per name).
type fakeAdvSSLPolicy struct {
	out *elbv2.DescribeSSLPoliciesOutput
}

func (f *fakeAdvSSLPolicy) DescribeSSLPolicies(ctx context.Context, in *elbv2.DescribeSSLPoliciesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeSSLPoliciesOutput, error) {
	return f.out, nil
}
