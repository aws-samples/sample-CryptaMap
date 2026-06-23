package datarest

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	bdtypes "github.com/aws/aws-sdk-go-v2/service/bedrock/types"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	batypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// BedrockScanner inventories Amazon Bedrock (flagship GenAI) resources for at-rest
// encryption across its resource families: custom (fine-tuned) models, agents,
// knowledge bases, and guardrails.
//
// HONESTY/posture model (always-on, NOT opt-in): Bedrock ALWAYS encrypts its
// stored resources at rest with AES-256; there is no per-resource toggle to turn
// at-rest encryption OFF. What the customer controls is only the KEY TIER — a
// customer-managed CMK (its ARN appears on the resource) vs. the AWS-owned/managed
// default key (the CMK field is ABSENT). Either way the data is AES-256-encrypted
// at rest, so posture is unconditionally SymmetricOnly (a quantum-relevant
// symmetric surface), NEVER NoEncryption. An absent CMK is "no customer key
// custody" (kmsKeyId=AWS_OWNED_KMS_KEY), which is recorded as evidence but is NOT a
// clean all-clear — and crucially is NOT a no-encryption finding (the classic
// false-alarm trap for always-encrypted services).
//
// The "always encrypts at rest with AES-256" claim is a UNIVERSAL AWS-doc
// guarantee with no per-resource API field, so each asset is stamped via
// services.StampDocFact (no knowledge key exists yet for this new scanner).
//
// Resource-family notes:
//   - Custom models  (bedrock):      ListCustomModels -> GetCustomModel.ModelKmsKeyArn
//   - Agents         (bedrockagent): ListAgents       -> GetAgent.Agent.CustomerEncryptionKeyArn
//   - Knowledge bases(bedrockagent): ListKnowledgeBases (the SDK KnowledgeBase
//     resource exposes NO per-knowledge-base CMK field — the CMK lives on the
//     downstream vector/data-store config, scanned elsewhere — so a knowledge base
//     is reported as AWS-managed default at-rest, never fabricating a CMK ARN).
//   - Guardrails     (bedrock):      ListGuardrails   -> GetGuardrail.KmsKeyArn
type BedrockScanner struct{}

// Name returns the canonical service identifier.
func (BedrockScanner) Name() string { return "bedrock" }

// Category returns the primary CryptaMap category.
func (BedrockScanner) Category() models.Category { return models.CategoryDataAtRest }

// bedrockDocURL is the AWS doc backing the universal "Bedrock encrypts at rest
// with AES-256" guarantee that drives the SymmetricOnly posture for every family.
const bedrockDocURL = "https://docs.aws.amazon.com/bedrock/latest/userguide/encryption.html"

// awsOwnedKey is the evidence value stamped when a Bedrock resource carries no
// customer CMK ARN — the AWS-owned/managed default key (still AES-256 at rest).
const awsOwnedKey = "AWS_OWNED_KMS_KEY"

// Scan enumerates every Bedrock resource family and emits one SymmetricOnly asset
// per resource, distinguishing the key tier (customer CMK vs AWS-managed default)
// in evidence. A list error for ONE family is logged to stderr and that family is
// skipped gracefully — a single inaccessible family (e.g. no permissions, or a
// region where the API is unavailable) must not blank the whole Bedrock surface.
func (s BedrockScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region

	bdClient := bedrock.NewFromConfig(cfg)
	baClient := bedrockagent.NewFromConfig(cfg)

	assets := []models.CryptoAsset{}

	// (1) Custom models — bedrock: ListCustomModels -> GetCustomModel.ModelKmsKeyArn
	assets = s.scanCustomModels(ctx, bdClient, accountID, region, assets)
	if services.TruncationCapReached(len(assets), s.Name(), region) {
		return assets, nil
	}
	// (2) Agents — bedrockagent: ListAgents -> GetAgent.Agent.CustomerEncryptionKeyArn
	assets = s.scanAgents(ctx, baClient, accountID, region, assets)
	if services.TruncationCapReached(len(assets), s.Name(), region) {
		return assets, nil
	}
	// (3) Knowledge bases — bedrockagent: ListKnowledgeBases (no per-KB CMK field)
	assets = s.scanKnowledgeBases(ctx, baClient, accountID, region, assets)
	if services.TruncationCapReached(len(assets), s.Name(), region) {
		return assets, nil
	}
	// (4) Guardrails — bedrock: ListGuardrails -> GetGuardrail.KmsKeyArn
	assets = s.scanGuardrails(ctx, bdClient, accountID, region, assets)

	return assets, nil
}

// awsManagedDefaultNote is stamped when a Bedrock resource carries no customer CMK
// ARN. It records the honest middle state: the data IS encrypted at rest (AES-256
// via the AWS-owned/managed default key), so this is NEVER a no-encryption finding,
// but there is no customer key custody, so it is NOT a clean all-clear either.
const awsManagedDefaultNote = "No customer CMK configured; data is encrypted at rest with the AWS-owned/managed default key (AES-256). Always encrypted — not a no-encryption finding — but no customer key custody."

// keyCustodyUnknownNote is stamped when the per-resource Get (GetCustomModel /
// GetAgent / GetGuardrail) FAILED, so the key tier could not be read. Bedrock still
// always encrypts at rest with AES-256 (posture stays SymmetricOnly), but we do NOT
// know whether a customer CMK is configured — so we must NOT fabricate the
// AWS-managed-default verdict. Key custody is honestly undetermined (read failed).
const keyCustodyUnknownNote = "Per-resource encryption config could not be read (Get failed); data is still encrypted at rest with AES-256 (Bedrock always encrypts), but customer key custody (customer CMK vs AWS-managed default) is undetermined."

// kbNoCMKFieldNote is the AWS-managed-default note specific to knowledge bases: the
// SDK KnowledgeBase resource exposes NO per-knowledge-base CMK field, so the
// absence of a CMK here means "not readable / on the downstream store", NOT "the
// customer chose the AWS-managed default" — still always AES-256, still never a
// no-encryption finding, never a fabricated CMK ARN.
const kbNoCMKFieldNote = "Bedrock knowledge base data is encrypted at rest with AES-256; the SDK exposes no per-knowledge-base customer CMK (any CMK is on the downstream data/vector store, scanned separately). Not a no-encryption finding."

// classifyBedrockKeyTier is the PURE classification core shared by every Bedrock
// resource family. Given the customer CMK ARN read from the resource (empty when
// absent / unreadable), whether the per-resource Get FAILED (getErr), and an
// optional family-specific note used for the no-CMK case (defaultNote falls back to
// awsManagedDefaultNote), it returns the posture and the exact key-tier evidence
// properties.
//
// The posture is UNCONDITIONALLY SymmetricOnly: Bedrock always encrypts at rest
// with AES-256 and there is no toggle to disable it, so the key tier is the ONLY
// thing in question — NEVER PostureNoEncryption, and never a fabricated CMK ARN.
//
// HONESTY on read failure: if getErr is true the per-resource config could not be
// read, so we must NOT fabricate the AWS-managed-default verdict (that would assert
// "no customer CMK" we never observed). Instead key custody is recorded as honestly
// undetermined (keyTier=unknown, kmsKeyId=UNRESOLVED) with keyCustodyUnknownNote.
//
// The returned map is exactly the Properties this scanner sets on top of the
// posture/doc-fact stamps, so the table test can assert on the exact keys and
// values without an AWS client.
func classifyBedrockKeyTier(cmkArn string, getErr bool, defaultNote string) (models.CryptoPosture, map[string]string) {
	props := map[string]string{}
	if cmkArn != "" {
		props["kmsKeyId"] = cmkArn
		props["keyTier"] = "customer-managed"
		return models.PostureSymmetricOnly, props
	}
	if getErr {
		props["kmsKeyId"] = "UNRESOLVED"
		props["keyTier"] = "unknown"
		props["note"] = keyCustodyUnknownNote
		return models.PostureSymmetricOnly, props
	}
	if defaultNote == "" {
		defaultNote = awsManagedDefaultNote
	}
	props["kmsKeyId"] = awsOwnedKey
	props["keyTier"] = "aws-managed-default"
	props["note"] = defaultNote
	return models.PostureSymmetricOnly, props
}

// newBedrockAsset builds the baseline SymmetricOnly at-rest asset shared by every
// family: AES-256, posture SymmetricOnly, the always-encrypts doc-fact provenance,
// and the customer-vs-AWS-managed key-tier evidence. getErr is true when the
// per-resource Get failed, so key custody is recorded as honestly undetermined
// instead of the fabricated AWS-managed-default verdict. defaultNote overrides the
// no-CMK note for families with a family-specific honesty note (knowledge bases);
// an empty defaultNote uses the shared awsManagedDefaultNote.
func newBedrockAsset(accountID, region, resourceID, resourceType, cmkArn string, getErr bool, defaultNote string) models.CryptoAsset {
	a := services.NewAsset("bedrock", models.CategoryDataAtRest, accountID, region, resourceID, resourceType, services.AESAtRest())
	services.StampDocFact(&a, "high", bedrockDocURL, "2026-06-15")
	posture, props := classifyBedrockKeyTier(cmkArn, getErr, defaultNote)
	services.PostureProperty(&a, posture)
	for k, v := range props {
		a.Properties[k] = v
	}
	return a
}

// scanCustomModels lists custom (fine-tuned) models and reads each model's
// ModelKmsKeyArn via GetCustomModel (the list summary does not carry the CMK).
func (s BedrockScanner) scanCustomModels(ctx context.Context, client *bedrock.Client, accountID, region string, assets []models.CryptoAsset) []models.CryptoAsset {
	var nextToken *string
	for {
		out, err := client.ListCustomModels(ctx, &bedrock.ListCustomModelsInput{NextToken: nextToken})
		if err != nil {
			fmt.Fprintf(os.Stderr, "bedrock ListCustomModels: %v\n", err)
			return assets
		}
		summaries := out.ModelSummaries
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(summaries) {
			if remaining <= 0 {
				return assets
			}
			summaries = summaries[:remaining]
		}
		page := services.MapConcurrent(ctx, services.DefaultInnerConcurrency, summaries,
			func(ctx context.Context, m bdtypes.CustomModelSummary) (models.CryptoAsset, bool) {
				if m.ModelArn == nil {
					return models.CryptoAsset{}, false
				}
				id := *m.ModelArn
				if m.ModelName != nil && *m.ModelName != "" {
					id = *m.ModelName
				}
				cmk := ""
				g, gerr := client.GetCustomModel(ctx, &bedrock.GetCustomModelInput{ModelIdentifier: m.ModelArn})
				if gerr != nil {
					fmt.Fprintf(os.Stderr, "bedrock GetCustomModel %s: %v\n", id, gerr)
				} else if g.ModelKmsKeyArn != nil {
					cmk = *g.ModelKmsKeyArn
				}
				a := newBedrockAsset(accountID, region, id, "AWS::Bedrock::CustomModel", cmk, gerr != nil, "")
				return a, true
			})
		assets = append(assets, page...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets
}

// scanAgents lists Bedrock agents and reads each agent's CustomerEncryptionKeyArn
// via GetAgent (the agent summary does not carry the CMK).
func (s BedrockScanner) scanAgents(ctx context.Context, client *bedrockagent.Client, accountID, region string, assets []models.CryptoAsset) []models.CryptoAsset {
	var nextToken *string
	for {
		out, err := client.ListAgents(ctx, &bedrockagent.ListAgentsInput{NextToken: nextToken})
		if err != nil {
			fmt.Fprintf(os.Stderr, "bedrock(agent) ListAgents: %v\n", err)
			return assets
		}
		summaries := out.AgentSummaries
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(summaries) {
			if remaining <= 0 {
				return assets
			}
			summaries = summaries[:remaining]
		}
		page := services.MapConcurrent(ctx, services.DefaultInnerConcurrency, summaries,
			func(ctx context.Context, ag batypes.AgentSummary) (models.CryptoAsset, bool) {
				if ag.AgentId == nil {
					return models.CryptoAsset{}, false
				}
				id := *ag.AgentId
				if ag.AgentName != nil && *ag.AgentName != "" {
					id = *ag.AgentName
				}
				cmk := ""
				g, gerr := client.GetAgent(ctx, &bedrockagent.GetAgentInput{AgentId: ag.AgentId})
				if gerr != nil {
					fmt.Fprintf(os.Stderr, "bedrock(agent) GetAgent %s: %v\n", id, gerr)
				} else if g.Agent != nil && g.Agent.CustomerEncryptionKeyArn != nil {
					cmk = *g.Agent.CustomerEncryptionKeyArn
				}
				a := newBedrockAsset(accountID, region, id, "AWS::Bedrock::Agent", cmk, gerr != nil, "")
				return a, true
			})
		assets = append(assets, page...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets
}

// scanKnowledgeBases lists Bedrock knowledge bases. The SDK KnowledgeBase resource
// exposes NO per-knowledge-base CMK field (a knowledge base's CMK, when any, lives
// on the downstream data-store / vector-store config, which is a separate surface).
// So a knowledge base is reported as AWS-managed-default at-rest (always AES-256),
// without fabricating a CMK ARN it does not have, and without GetKnowledgeBase —
// the list summary already provides the identity we need.
func (s BedrockScanner) scanKnowledgeBases(ctx context.Context, client *bedrockagent.Client, accountID, region string, assets []models.CryptoAsset) []models.CryptoAsset {
	var nextToken *string
	for {
		out, err := client.ListKnowledgeBases(ctx, &bedrockagent.ListKnowledgeBasesInput{NextToken: nextToken})
		if err != nil {
			fmt.Fprintf(os.Stderr, "bedrock(agent) ListKnowledgeBases: %v\n", err)
			return assets
		}
		summaries := out.KnowledgeBaseSummaries
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(summaries) {
			if remaining <= 0 {
				return assets
			}
			summaries = summaries[:remaining]
		}
		for i := range summaries {
			kb := summaries[i]
			if kb.KnowledgeBaseId == nil {
				continue
			}
			id := *kb.KnowledgeBaseId
			if kb.Name != nil && *kb.Name != "" {
				id = *kb.Name
			}
			// No per-knowledge-base CMK field in the SDK resource -> AWS-managed default,
			// with the KB-specific honesty note (CMK is not readable here, not absent).
			a := newBedrockAsset(accountID, region, id, "AWS::Bedrock::KnowledgeBase", "", false, kbNoCMKFieldNote)
			assets = append(assets, a)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets
}

// scanGuardrails lists Bedrock guardrails and reads each guardrail's KmsKeyArn via
// GetGuardrail (the guardrail summary does not carry the CMK).
func (s BedrockScanner) scanGuardrails(ctx context.Context, client *bedrock.Client, accountID, region string, assets []models.CryptoAsset) []models.CryptoAsset {
	var nextToken *string
	for {
		out, err := client.ListGuardrails(ctx, &bedrock.ListGuardrailsInput{NextToken: nextToken})
		if err != nil {
			fmt.Fprintf(os.Stderr, "bedrock ListGuardrails: %v\n", err)
			return assets
		}
		summaries := out.Guardrails
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(summaries) {
			if remaining <= 0 {
				return assets
			}
			summaries = summaries[:remaining]
		}
		page := services.MapConcurrent(ctx, services.DefaultInnerConcurrency, summaries,
			func(ctx context.Context, gs bdtypes.GuardrailSummary) (models.CryptoAsset, bool) {
				if gs.Id == nil {
					return models.CryptoAsset{}, false
				}
				id := *gs.Id
				if gs.Name != nil && *gs.Name != "" {
					id = *gs.Name
				}
				cmk := ""
				in := &bedrock.GetGuardrailInput{GuardrailIdentifier: gs.Id}
				if gs.Version != nil && *gs.Version != "" {
					in.GuardrailVersion = gs.Version
				}
				g, gerr := client.GetGuardrail(ctx, in)
				if gerr != nil {
					fmt.Fprintf(os.Stderr, "bedrock GetGuardrail %s: %v\n", id, gerr)
				} else if g.KmsKeyArn != nil {
					cmk = *g.KmsKeyArn
				}
				a := newBedrockAsset(accountID, region, id, "AWS::Bedrock::Guardrail", cmk, gerr != nil, "")
				if gs.Version != nil {
					a.Properties["guardrailVersion"] = *gs.Version
				}
				return a, true
			})
		assets = append(assets, page...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets
}
