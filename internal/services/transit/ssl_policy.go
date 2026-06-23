package transit

import (
	"context"
	"fmt"
	"os"
	"strings"

	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// pqELBKexTokens are the hybrid post-quantum (ML-KEM) key-exchange groups that
// AWS exposes in its PQ ELB security policies. A policy whose cipher / key-
// exchange set contains any of these negotiates hybrid PQ TLS 1.3 and is
// classified PosturePQCHybrid. Matched case-insensitively against the real
// SslPolicy.Ciphers names returned by DescribeSSLPolicies (not the policy name).
var pqELBKexTokens = []string{
	"secp256r1mlkem768",
	"secp384r1mlkem1024",
	"x25519mlkem768",
	"mlkem", // catch-all for any future ML-KEM token spelling
}

// elbPQHybridGroupsDoc is the doc-known set of hybrid post-quantum key-exchange
// groups that AWS ELB "...-PQ-2025-09" security policies support. The API does
// NOT enumerate these groups (DescribeSSLPolicies returns only classical cipher
// suites), so this is a capability label sourced from the ELB security-policy
// documentation, not an observed negotiated group.
// https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html
const elbPQHybridGroupsDoc = "SecP256r1MLKEM768,SecP384r1MLKEM1024,X25519MLKEM768"

// isPQELBPolicyName reports whether an ELB SSL security-policy NAME denotes a
// hybrid post-quantum policy. AWS marks these with "-PQ-" / "PQ-2025" in the
// policy name (e.g. ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09); the ML-KEM
// groups they enable are NOT present in the policy's cipher list, so the name is
// the only config-derivable PQ signal. Matched case-insensitively.
func isPQELBPolicyName(policy string) bool {
	pl := strings.ToLower(policy)
	return strings.Contains(pl, "-pq-") || strings.Contains(pl, "pq-2025")
}

// sslPolicyDescribeAPI is the minimal slice of the elbv2 client the resolver
// uses (only DescribeSSLPolicies). Defining it as an interface keeps the
// resolver — and the ALB/NLB scanners that delegate to it — unit-testable with a
// fake, without a live AWS client. The concrete *elbv2.Client satisfies it.
type sslPolicyDescribeAPI interface {
	DescribeSSLPolicies(ctx context.Context, in *elbv2.DescribeSSLPoliciesInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeSSLPoliciesOutput, error)
}

// sslPolicyResolver caches DescribeSSLPolicies lookups keyed by policy name so a
// distinct policy is described at most once per scan and the result is reused
// across ALB + NLB listeners. The cache holds the derived (version, posture,
// real protocol block) so callers do not re-walk the cipher list.
type sslPolicyResolver struct {
	client sslPolicyDescribeAPI
	cache  map[string]sslPolicyResult
}

// sslPolicyResult is the resolved classification for a single SSL policy.
type sslPolicyResult struct {
	version  string
	posture  models.CryptoPosture
	props    models.CryptoProperties
	observed bool   // true when DescribeSSLPolicies returned real protocol/cipher data
	warning  string // non-empty when the policy needs a co-finding (e.g. PQ + legacy TLS floor)
}

// newSSLPolicyResolver builds an empty resolver bound to an elbv2 client.
func newSSLPolicyResolver(client sslPolicyDescribeAPI) *sslPolicyResolver {
	return &sslPolicyResolver{client: client, cache: map[string]sslPolicyResult{}}
}

// resolve returns the classification for the named SSL policy, calling
// DescribeSSLPolicies once per distinct name and caching the result. On an empty
// name or a describe error it falls back to the legacy name-substring mapping
// (policyVersion) so behavior degrades gracefully rather than failing the scan.
func (r *sslPolicyResolver) resolve(ctx context.Context, policy string) sslPolicyResult {
	if policy == "" {
		ver, posture := policyVersion("")
		return sslPolicyResult{version: ver, posture: posture, props: services.TLSProtocolProps(ver, "")}
	}
	if cached, ok := r.cache[policy]; ok {
		return cached
	}
	if r.client == nil {
		// No authoritative client: degrade to the name-substring mapping (NOT
		// observed) rather than panic — mirrors the describe-error fallback below.
		ver, posture := policyVersion(policy)
		res := sslPolicyResult{version: ver, posture: posture, props: services.TLSProtocolProps(ver, policy)}
		r.cache[policy] = res
		return res
	}

	out, err := r.client.DescribeSSLPolicies(ctx, &elbv2.DescribeSSLPoliciesInput{Names: []string{policy}})
	if err != nil || out == nil || len(out.SslPolicies) == 0 {
		if err != nil {
			fmt.Fprintf(os.Stderr, "alb/nlb DescribeSSLPolicies %s: %v\n", policy, err)
		}
		// Fallback: name-substring mapping. Mark NOT observed so the unknown
		// default does not masquerade as a verified classification.
		ver, posture := policyVersion(policy)
		res := sslPolicyResult{version: ver, posture: posture, props: services.TLSProtocolProps(ver, policy)}
		r.cache[policy] = res
		return res
	}

	res := classifySSLPolicy(out.SslPolicies[0], policy)
	r.cache[policy] = res
	return res
}

// classifySSLPolicy derives (version, posture, protocol block) from the REAL
// SslPolicy.SslProtocols + Ciphers returned by DescribeSSLPolicies, rather than
// from the policy-name substrings. The TLS version is the highest protocol in
// the policy's SslProtocols list; PQ posture is detected from the cipher / key-
// exchange set (ML-KEM hybrid groups). The real cipher names + protocol list are
// surfaced into the CycloneDX protocol block.
func classifySSLPolicy(sp elbv2types.SslPolicy, policyName string) sslPolicyResult {
	// Highest negotiated TLS version from the real protocol list.
	ver := tlsVersionFromProtocols(sp.SslProtocols)

	// Collect the real cipher names. We ALSO try the (legacy) per-cipher ML-KEM
	// token match, but for ELBv2 the hybrid PQ key-exchange groups are NOT cipher
	// names — the DescribeSSLPolicies Ciphers list contains only classical
	// TLS_*/ECDHE_* suites (verified against the ELB security-policy doc). The PQ
	// signal lives in the policy NAME ("...-PQ-2025-09"), so detect it there too.
	// Without this, a real PQ-policy listener on the authoritative (describe-
	// succeeds) path was FALSE-NEGATIVE classified NonPQCClassical instead of
	// PosturePQCHybrid; the name check previously only ran in the fallback path.
	ciphers := make([]string, 0, len(sp.Ciphers))
	pqHybrid := false
	for _, c := range sp.Ciphers {
		if c.Name == nil {
			continue
		}
		name := *c.Name
		ciphers = append(ciphers, name)
		low := strings.ToLower(name)
		for _, tok := range pqELBKexTokens {
			if strings.Contains(low, tok) {
				pqHybrid = true
				break
			}
		}
	}
	if isPQELBPolicyName(policyName) {
		pqHybrid = true
	}

	posture := postureFromTLS(ver, pqHybrid)

	floor := tlsFloorFromProtocols(sp.SslProtocols)
	pp := &models.ProtocolProperties{
		Type:          "tls",
		Version:       ver,
		TLSMinVersion: floor,
		PQCHybrid:     pqHybrid,
		Source:        services.SourceObserved,
	}
	// Downgrade-fallback warning: a PQ-hybrid policy that ALSO permits a legacy
	// TLS floor (1.0/1.1) — e.g. ELBSecurityPolicy-TLS13-1-0-PQ-2025-09 — is NOT a
	// clean all-clear. A downgrade-capable client can still negotiate TLS 1.0, so
	// the PQ KEX never engages. Keep the PQCHybrid credit (the capability is real)
	// but surface the legacy floor (carried on the result, stamped by the caller)
	// so it is not silently scored compliant/Informational.
	warning := ""
	if pqHybrid && (floor == "1.0" || floor == "1.1") {
		warning = "pq-hybrid policy permits a legacy TLS " + floor +
			" floor; a downgrade-capable client can negotiate TLS " + floor +
			" and bypass the post-quantum key exchange"
	}
	// The policy name labels the suite (Name only); the real ciphers populate a
	// second suite. policyName is NOT an algorithm, so it is not copied into
	// Algorithms (a CycloneDX refType array of bom-refs to algorithm components).
	pp.CipherSuites = append(pp.CipherSuites, models.CipherSuite{
		Name: policyName,
	})
	if len(ciphers) > 0 {
		pp.CipherSuites = append(pp.CipherSuites, models.CipherSuite{
			Name:       "tls-ciphers",
			Algorithms: ciphers,
		})
	}
	if len(sp.SslProtocols) > 0 {
		// TLS protocol-version labels ("TLSv1.2", "TLSv1.3") are NOT algorithms;
		// record them as the suite's Identifiers (a free-string array) rather than
		// Algorithms (refType bom-refs to algorithm components).
		pp.CipherSuites = append(pp.CipherSuites, models.CipherSuite{
			Name:        "ssl-protocols",
			Identifiers: append([]string(nil), sp.SslProtocols...),
		})
	}
	if pqHybrid {
		// Record the hybrid KEX group label. Prefer a real ML-KEM token if one
		// somehow appeared in the cipher list; otherwise fall back to the
		// doc-known supported hybrid groups for ELB PQ policies (the groups are
		// NOT enumerated by the API, so this is a capability label sourced from
		// the AWS security-policy doc, not an observed negotiated group).
		for _, c := range ciphers {
			if strings.Contains(strings.ToLower(c), "mlkem") {
				pp.KeyExchangeGroup = c
				break
			}
		}
		if pp.KeyExchangeGroup == "" {
			pp.KeyExchangeGroup = elbPQHybridGroupsDoc
		}
	}

	return sslPolicyResult{
		version: ver,
		posture: posture,
		props: models.CryptoProperties{
			AssetType:          models.AssetTypeProtocol,
			ProtocolProperties: pp,
		},
		observed: true,
		warning:  warning,
	}
}

// tlsVersionFromProtocols returns the highest TLS version present in an ELB SSL
// policy's SslProtocols list (values like "TLSv1.3", "TLSv1.2", "TLSv1.1",
// "TLSv1"). Returns "" when no recognizable protocol is present.
func tlsVersionFromProtocols(protos []string) string {
	has13, has12, has11, has10 := false, false, false, false
	for _, p := range protos {
		switch strings.ToUpper(strings.TrimSpace(p)) {
		case "TLSV1.3":
			has13 = true
		case "TLSV1.2":
			has12 = true
		case "TLSV1.1":
			has11 = true
		case "TLSV1", "TLSV1.0":
			has10 = true
		}
	}
	switch {
	case has13:
		return "1.3"
	case has12:
		return "1.2"
	case has11:
		return "1.1"
	case has10:
		return "1.0"
	default:
		return ""
	}
}

// tlsFloorFromProtocols returns the LOWEST TLS version present in an ELB SSL
// policy's SslProtocols list — the negotiation FLOOR, the counterpart to
// tlsVersionFromProtocols (which returns the highest, used for Version). Returns
// "" when no recognizable protocol is present so no floor is fabricated.
func tlsFloorFromProtocols(protos []string) string {
	has13, has12, has11, has10 := false, false, false, false
	for _, p := range protos {
		switch strings.ToUpper(strings.TrimSpace(p)) {
		case "TLSV1.3":
			has13 = true
		case "TLSV1.2":
			has12 = true
		case "TLSV1.1":
			has11 = true
		case "TLSV1", "TLSV1.0":
			has10 = true
		}
	}
	switch {
	case has10:
		return "1.0"
	case has11:
		return "1.1"
	case has12:
		return "1.2"
	case has13:
		return "1.3"
	default:
		return ""
	}
}

// postureFromTLS maps a (TLS version, PQ-hybrid) pair to a CryptoPosture. A PQ
// hybrid policy is PosturePQCHybrid regardless of version; TLS 1.0/1.1 is
// legacy; an unrecognized/empty version is unknown (so a guessed default never
// masquerades as a verified classical classification); everything else is
// non-pqc-classical.
func postureFromTLS(ver string, pqHybrid bool) models.CryptoPosture {
	if pqHybrid {
		return models.PosturePQCHybrid
	}
	switch ver {
	case "1.0", "1.1":
		return models.PostureLegacyTLS
	case "1.2", "1.3":
		return models.PostureNonPQCClassical
	default:
		return models.PostureUnknown
	}
}
