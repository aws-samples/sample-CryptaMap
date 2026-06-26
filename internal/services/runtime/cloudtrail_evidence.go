// Package runtime provides runtime-evidence scanners that infer crypto posture
// from observed AWS API activity (e.g. CloudTrail) rather than static resource
// configuration. The first such reader is the CloudTrail KMS data-plane reader,
// which records which signing / encryption algorithms are actually being used
// at runtime — surfacing in-use post-quantum (ML-DSA / ML-KEM) vs classical
// (RSA / ECDSA) algorithms that a static configuration scan cannot see.
package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// CloudTrailEvidenceScanner reads recent CloudTrail KMS data-plane events
// (Sign / Encrypt / GenerateDataKey) and emits one asset per distinct
// (eventName, algorithm) pair observed, tagged Properties["evidence"]="runtime".
// It is intentionally conservative: it caps the lookback window and the number
// of paginated pages so it never becomes an expensive or throttling scan, and
// it degrades to zero assets (no error) when CloudTrail surfaces no crypto
// detail. On AccessDenied / throttle it returns whatever it has collected so far
// plus the error, which the engine records in ServiceStats.Errors without
// failing the overall scan.
type CloudTrailEvidenceScanner struct{}

// Name returns the canonical scanner identifier.
func (CloudTrailEvidenceScanner) Name() string { return "cloudtrail_evidence" }

// Category returns the primary category for this scanner. Runtime KMS evidence
// is keyed to key-management (it observes KMS data-plane crypto operations).
func (CloudTrailEvidenceScanner) Category() models.Category { return models.CategoryKeyManagement }

// lookbackWindow bounds how far back LookupEvents searches. CloudTrail
// management-event history is retained ~90 days; we cap the window there.
const lookbackWindow = 90 * 24 * time.Hour

// maxPagesPerEvent caps pagination per event-name to keep the scan cheap and
// avoid throttling over a large window. Each page is up to 50 events.
const maxPagesPerEvent = 4

// cryptoEventNames is the small allowlist of KMS data-plane events whose
// requestParameters expose the in-use algorithm. LookupEvents accepts exactly
// one LookupAttribute per call, so we iterate this list with one filtered call
// (paginated) per event name.
var cryptoEventNames = []string{"Sign", "Encrypt", "GenerateDataKey", "GenerateDataKeyPair", "ReEncrypt", "Verify"}

// runtimeEvidence is the parsed crypto detail extracted from a single
// CloudTrail event's requestParameters blob.
type runtimeEvidence struct {
	algo        string // requestParameters.encryptionAlgorithm
	keySpec     string // requestParameters.keySpec (GenerateDataKey / GenerateDataKeyPair)
	signingAlgo string // requestParameters.signingAlgorithm (Sign / Verify)
}

// parseRuntimeAlgo is the pure, unit-testable core: it unmarshals a CloudTrail
// Event.CloudTrailEvent JSON blob and reads the three crypto-relevant
// requestParameters fields. ok is false when the blob is not valid JSON or
// carries none of the three fields.
func parseRuntimeAlgo(cloudTrailEventJSON string) (algo, keySpec, signingAlgo string, ok bool) {
	var envelope struct {
		RequestParameters struct {
			EncryptionAlgorithm string `json:"encryptionAlgorithm"`
			KeySpec             string `json:"keySpec"`
			KeyPairSpec         string `json:"keyPairSpec"`
			SigningAlgorithm    string `json:"signingAlgorithm"`
		} `json:"requestParameters"`
	}
	if err := json.Unmarshal([]byte(cloudTrailEventJSON), &envelope); err != nil {
		return "", "", "", false
	}
	rp := envelope.RequestParameters
	keySpec = rp.KeySpec
	if keySpec == "" {
		keySpec = rp.KeyPairSpec
	}
	algo = rp.EncryptionAlgorithm
	signingAlgo = rp.SigningAlgorithm
	if algo == "" && keySpec == "" && signingAlgo == "" {
		return "", "", "", false
	}
	return algo, keySpec, signingAlgo, true
}

// runtimePosture maps an observed runtime algorithm/keyspec/signing-algorithm
// string to a CryptoPosture. This classifies a STANDALONE KMS data-plane
// primitive (a Sign signingAlgorithm or a GenerateDataKeyPair keySpec), NOT a TLS
// handshake — so an observed ML-DSA or ML-KEM here is a PURE post-quantum
// primitive -> PQCReady, NOT PQCHybrid (hybrid is reserved for the combined TLS
// KEX group X25519MLKEM768, handled separately in tlsObservedPosture). RSA / ECDSA
// / ECC / EdDSA -> classical; symmetric / AES -> symmetric-only; anything
// unrecognized -> Unknown (never assumed quantum-resistant).
func runtimePosture(algo string) models.CryptoPosture {
	a := strings.ToUpper(algo)
	a = strings.ReplaceAll(a, "-", "_")
	switch {
	case strings.Contains(a, "ML_KEM"), strings.Contains(a, "ML_DSA"), strings.Contains(a, "MLKEM"), strings.Contains(a, "MLDSA"):
		return models.PosturePQCReady
	case strings.HasPrefix(a, "RSA"), strings.HasPrefix(a, "ECDSA"), strings.HasPrefix(a, "ECC"), strings.HasPrefix(a, "SM2"),
		strings.HasPrefix(a, "ED25519"), strings.HasPrefix(a, "EDDSA"), strings.Contains(a, "EDWARDS"):
		// EdDSA / Ed25519 is a CLASSICAL (quantum-vulnerable) signature algorithm —
		// AWS KMS exposes ED25519_SHA_512 / ECC_NIST_EDWARDS25519. These match no
		// prefix above and previously fell to the default; classify them classical.
		return models.PostureNonPQCClassical
	case strings.HasPrefix(a, "SYMMETRIC"), strings.Contains(a, "AES"):
		return models.PostureSymmetricOnly
	}
	// An algorithm string we do not recognize is NOT assumed quantum-resistant. KMS
	// algorithm enums can expand; defaulting an unknown observed algorithm to
	// SymmetricOnly was a FALSE-SAFE (it could hide a new classical or unclassified
	// primitive). Unknown is the honest, conservative verdict.
	return models.PostureUnknown
}

// chooseAlgo picks the most specific algorithm string from a runtimeEvidence:
// signing algorithm first (it names the asymmetric primitive directly), then
// the encryption algorithm, then the key spec.
func (e runtimeEvidence) chooseAlgo() string {
	switch {
	case e.signingAlgo != "":
		return e.signingAlgo
	case e.algo != "":
		return e.algo
	default:
		return e.keySpec
	}
}

// isSymmetricRuntimeAlgo reports whether an observed KMS data-plane algorithm /
// keyspec string names a symmetric primitive (AES key spec / SYMMETRIC_DEFAULT).
// Only these may be labeled AES-256 / AE at-rest; everything else (RSA, ECDSA,
// ECC, ML-DSA, ML-KEM, …) is asymmetric and must NOT be described as AES. The
// match is on AES as a leading token (the KMS keyspecs AES_256 / AES_128), NOT a
// substring — otherwise RSAES_OAEP_* (which contains the letters "AES") would be
// mislabeled symmetric, the exact fabricated-AES bug this fix exists to prevent.
func isSymmetricRuntimeAlgo(chosen string) bool {
	a := strings.ToUpper(strings.ReplaceAll(chosen, "-", "_"))
	return strings.HasPrefix(a, "AES_") || a == "AES" || strings.HasPrefix(a, "SYMMETRIC")
}

// runtimeAlgoProps builds the CryptoProperties algorithm block for an observed
// KMS data-plane operation from the algorithm string that was actually observed
// (chosen) and the event name (which disambiguates a signing op from an
// encryption / key-derivation op). It replaces the previous unconditional
// services.AESAtRestKMS(chosen), which hardcoded AES-256 even for asymmetric /
// signing algorithms (ML_DSA_*, RSA, ECDSA) — a fabricated verdict (a Sign with
// ML_DSA was reported as "AES-256", masking a quantum-relevant primitive).
//
// Rules (honesty contract):
//   - Genuinely symmetric (GenerateDataKey, or an AES_* / SYMMETRIC keyspec):
//     keep the canonical AES-256 AE block (truthful; KMS envelope keys are AES).
//   - Sign / Verify: signature primitive named by the observed algorithm.
//   - Everything else asymmetric (Encrypt, ReEncrypt, GenerateDataKeyPair, an
//     RSA/ECC keyspec): key-encapsulation / public-key primitive (kem).
//   - NistQuantumSecurityLevel is asserted ONLY for symmetric AES (level 1). It
//     is left 0/unset for classical asymmetric (RSA/ECDSA — quantum-vulnerable,
//     so claiming a NIST PQ level would be a fabricated all-clear) and for PQC
//     primitives here too (the authoritative verdict travels via the posture
//     property; we do not guess a level from a CloudTrail string).
//
// The AlgorithmName is always the OBSERVED string so the CBOM reflects reality,
// and the KMS keyspec is stamped when chosen is a keyspec.
func runtimeAlgoProps(eventName, chosen string) models.CryptoProperties {
	if isSymmetricRuntimeAlgo(chosen) {
		// AES envelope key (GenerateDataKey / AES_* / SYMMETRIC_DEFAULT): the
		// AES-256 label is truthful here. Stamp the observed string as the KMS
		// keyspec for provenance.
		return services.AESAtRestKMS(chosen)
	}
	primitive := models.PrimitiveKEM
	if eventName == "Sign" || eventName == "Verify" {
		primitive = models.PrimitiveSignature
	}
	return models.CryptoProperties{
		AssetType: models.AssetTypeAlgorithm,
		AlgorithmProperties: &models.AlgorithmProperties{
			Primitive:     primitive,
			AlgorithmName: chosen,
			KMSKeySpec:    chosen,
		},
	}
}

// tlsEvidence is the parsed transit detail from a CloudTrail event's tlsDetails
// block plus the userIdentity.invokedBy guard and the event source.
type tlsEvidence struct {
	tlsVersion  string
	cipherSuite string
	keyExchange string // the negotiated KEX group, e.g. X25519MLKEM768 / x25519 / secp256r1
	host        string // tlsDetails.clientProvidedHostHeader (FQDN of the service endpoint)
	eventSource string // e.g. secretsmanager.amazonaws.com
	invokedBy   string // userIdentity.invokedBy — set when an AWS service made the call
}

// parseTLSDetails is the pure, unit-testable core for the PQ-TLS observation
// pass. It reads tlsDetails.{tlsVersion,cipherSuite,clientProvidedHostHeader,
// keyExchange}, the event source, and userIdentity.invokedBy. ok is false when
// the blob is invalid JSON OR the tlsDetails block is entirely absent/empty.
// CloudTrail omits tlsDetails for AWS-service-on-your-behalf calls (invokedBy
// set) and keyExchange is only present on newer events — both handled by callers.
func parseTLSDetails(cloudTrailEventJSON string) (tlsEvidence, bool) {
	var envelope struct {
		EventSource  string `json:"eventSource"`
		UserIdentity struct {
			InvokedBy string `json:"invokedBy"`
		} `json:"userIdentity"`
		TLSDetails struct {
			TLSVersion               string `json:"tlsVersion"`
			CipherSuite              string `json:"cipherSuite"`
			ClientProvidedHostHeader string `json:"clientProvidedHostHeader"`
			KeyExchange              string `json:"keyExchange"`
		} `json:"tlsDetails"`
	}
	if err := json.Unmarshal([]byte(cloudTrailEventJSON), &envelope); err != nil {
		return tlsEvidence{}, false
	}
	t := envelope.TLSDetails
	if t.TLSVersion == "" && t.CipherSuite == "" && t.KeyExchange == "" {
		return tlsEvidence{}, false // no tlsDetails at all
	}
	return tlsEvidence{
		tlsVersion:  t.TLSVersion,
		cipherSuite: t.CipherSuite,
		keyExchange: t.KeyExchange,
		host:        t.ClientProvidedHostHeader,
		eventSource: envelope.EventSource,
		invokedBy:   envelope.UserIdentity.InvokedBy,
	}, true
}

// isMLKEMKeyExchange reports whether a CloudTrail keyExchange value is a hybrid
// ML-KEM (post-quantum) group, e.g. X25519MLKEM768 / SecP256r1MLKEM768.
func isMLKEMKeyExchange(keyExchange string) bool {
	k := strings.ToUpper(strings.ReplaceAll(keyExchange, "-", ""))
	return strings.Contains(k, "MLKEM") || strings.Contains(k, "ML_KEM")
}

// tlsObservedPosture classifies an OBSERVED TLS handshake. keyExchange is the
// authoritative signal (it directly names the negotiated KEX group); when it is
// absent (older events) we fall back to the cipherSuite/tlsVersion, which can
// only tell us classical-vs-nothing (no cipher suite name encodes the PQ KEM),
// so the fallback is necessarily lower confidence and never asserts pqc-hybrid.
func tlsObservedPosture(t tlsEvidence) (posture models.CryptoPosture, confidence string, haveKEX bool) {
	if t.keyExchange != "" {
		if isMLKEMKeyExchange(t.keyExchange) {
			return models.PosturePQCHybrid, "high", true // observed PQ-TLS in use
		}
		return models.PostureNonPQCClassical, "high", true // observed classical KEX (x25519/secp256r1)
	}
	// No keyExchange field: we can only say "encrypted TLS, KEX unknown" — classical
	// is the conservative assumption (cannot be PQ without an ML-KEM group), low conf.
	return models.PostureNonPQCClassical, "low", false
}

// Scan iterates the allowlisted KMS data-plane event names, paginates a bounded
// LookupEvents window for each, and emits one asset per distinct
// (eventName, algorithm) observed. It then runs a SECOND, independent pass that
// mines tlsDetails.keyExchange to record OBSERVED post-quantum vs classical TLS
// per service (the harvest-now-decrypt-later transit signal a static scan can't
// see — e.g. whether traffic to Secrets Manager / KMS actually negotiates
// X25519MLKEM768).
// cloudTrailEvidenceAPI is the minimal slice of the cloudtrail client this
// scanner uses. LookupEvents is NextToken-paginated and is the scanner's only
// API call; defining it as an interface keeps the two-pass event-mining logic
// unit-testable with a fake (the concrete *cloudtrail.Client satisfies it).
type cloudTrailEvidenceAPI interface {
	LookupEvents(ctx context.Context, in *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

func (s CloudTrailEvidenceScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := cloudtrail.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it runs the algorithm-evidence pass over the
// allowlisted KMS data-plane event names, then the second tlsDetails.keyExchange
// PQ-TLS pass. A LookupEvents error returns the partial slice + error so the
// engine records it without failing the overall scan.
func (s CloudTrailEvidenceScanner) scan(ctx context.Context, client cloudTrailEvidenceAPI, accountID, region string) ([]models.CryptoAsset, error) {
	now := time.Now().UTC()
	start := now.Add(-lookbackWindow)

	assets := []models.CryptoAsset{}
	seen := map[string]struct{}{} // dedup key: eventName|algo

	for _, eventName := range cryptoEventNames {
		var nextToken *string
		for page := 0; page < maxPagesPerEvent; page++ {
			out, err := client.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
				StartTime: aws.Time(start),
				EndTime:   aws.Time(now),
				LookupAttributes: []cttypes.LookupAttribute{{
					AttributeKey:   cttypes.LookupAttributeKeyEventName,
					AttributeValue: aws.String(eventName),
				}},
				NextToken: nextToken,
			})
			if err != nil {
				// AccessDenied / throttle: return partial slice + error so the
				// engine records it without failing the whole scan.
				return assets, fmt.Errorf("cloudtrail LookupEvents %s: %w", eventName, err)
			}
			for _, ev := range out.Events {
				if ev.CloudTrailEvent == nil {
					continue
				}
				algo, keySpec, signingAlgo, ok := parseRuntimeAlgo(*ev.CloudTrailEvent)
				if !ok {
					continue
				}
				evd := runtimeEvidence{algo: algo, keySpec: keySpec, signingAlgo: signingAlgo}
				chosen := evd.chooseAlgo()
				if chosen == "" {
					continue
				}
				dedupKey := eventName + "|" + chosen
				if _, dup := seen[dedupKey]; dup {
					continue
				}
				seen[dedupKey] = struct{}{}

				props := runtimeAlgoProps(eventName, chosen)
				resourceID := fmt.Sprintf("%s-%s", eventName, chosen)
				a := services.NewAsset("cloudtrail_evidence", models.CategoryKeyManagement,
					accountID, region, resourceID, "AWS::CloudTrail::RuntimeEvidence", props)
				a.Properties["evidence"] = "runtime"
				a.Properties["eventName"] = eventName
				a.Properties["observedAlgorithm"] = chosen
				if signingAlgo != "" {
					a.Properties["signingAlgorithm"] = signingAlgo
				}
				if keySpec != "" {
					a.Properties["keySpec"] = keySpec
				}
				services.PostureProperty(&a, runtimePosture(chosen))
				assets = append(assets, a)
			}
			if out.NextToken == nil || *out.NextToken == "" {
				break
			}
			nextToken = out.NextToken
		}
	}

	// SECOND PASS — observed PQ-TLS transit evidence (A3). Page a bounded window
	// of recent events (no eventName filter, so all service endpoints are sampled)
	// and mine tlsDetails.keyExchange. Emit one transit asset per distinct
	// (eventSource, keyExchange) observed: PosturePQCHybrid when the negotiated
	// group is hybrid ML-KEM (X25519MLKEM768), classical otherwise. This is OBSERVED
	// ground truth — strictly stronger than the static "service supports PQ-TLS"
	// matrix knowledge. Errors here are non-fatal: append partial + return err.
	tlsSeen := map[string]struct{}{} // dedup: eventSource|keyExchange
	var tlsToken *string
	for page := 0; page < maxPagesPerEvent; page++ {
		out, err := client.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
			StartTime: aws.Time(start),
			EndTime:   aws.Time(now),
			NextToken: tlsToken,
		})
		if err != nil {
			return assets, fmt.Errorf("cloudtrail LookupEvents (tls pass): %w", err)
		}
		for _, ev := range out.Events {
			if ev.CloudTrailEvent == nil {
				continue
			}
			t, ok := parseTLSDetails(*ev.CloudTrailEvent)
			if !ok {
				continue
			}
			// Skip AWS-service-on-your-behalf calls: their tlsDetails (when present)
			// reflect an internal AWS hop, not the customer's client transit, so
			// they must not drive a customer-facing posture (honest per principle 3).
			if t.invokedBy != "" {
				continue
			}
			// Only emit when there is a keyExchange to classify on. Without it the
			// signal is too weak to assert a per-service transit posture (we'd be
			// guessing); skip rather than record a low-confidence classical claim
			// for every event.
			if t.keyExchange == "" {
				continue
			}
			svc := t.eventSource
			if svc == "" {
				svc = "unknown"
			}
			dedupKey := svc + "|" + t.keyExchange
			if _, dup := tlsSeen[dedupKey]; dup {
				continue
			}
			tlsSeen[dedupKey] = struct{}{}

			posture, confidence, _ := tlsObservedPosture(t)
			ver := t.tlsVersion
			if ver == "" {
				ver = "1.3"
			}
			// Surface the OBSERVED key-exchange group + PQ-hybrid flag onto the
			// protocol block so the dashboard's "Key exchange group" / "PQC hybrid
			// key exchange" rows render the real handshake evidence. This is the one
			// asset class where the negotiated KEX is genuinely knowable (mined from
			// CloudTrail tlsDetails.keyExchange, e.g. X25519MLKEM768) — using the
			// plain TLSProtocolProps here left KeyExchangeGroup/PQCHybrid empty, so
			// the panel showed "—" despite the evidence existing. No new API call;
			// t.keyExchange is already parsed and is the dedup key (non-empty here).
			isHybrid := isMLKEMKeyExchange(t.keyExchange)
			props := services.TLSProtocolPropsDetailed(ver, t.cipherSuite, t.keyExchange, "", 0, isHybrid)
			resourceID := fmt.Sprintf("%s-%s", svc, t.keyExchange)
			a := services.NewAsset("cloudtrail_evidence", models.CategoryDataInTransit,
				accountID, region, resourceID, "AWS::CloudTrail::RuntimeEvidence", props)
			a.Properties["evidence"] = "runtime-tls"
			a.Properties["eventSource"] = svc
			a.Properties["keyExchange"] = t.keyExchange
			if t.cipherSuite != "" {
				a.Properties["cipherSuite"] = t.cipherSuite
			}
			if t.host != "" {
				a.Properties["endpointHost"] = t.host
			}
			services.PostureProperty(&a, posture)
			services.StampObserved(&a, confidence)
			assets = append(assets, a)
			if services.TruncationCapReached(len(assets), s.Name(), region) {
				return assets, nil
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		tlsToken = out.NextToken
	}

	return assets, nil
}
