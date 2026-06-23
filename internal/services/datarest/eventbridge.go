package datarest

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// EventBridgeScanner inspects Amazon EventBridge event buses for their at-rest
// encryption key tier.
//
// IMPORTANT (always-on, NOT opt-in): EventBridge ALWAYS encrypts event data at
// rest — there is no "encryption off" state for an event bus. The only choice is
// the KEY: a customer managed CMK, or (the default) the AWS-owned key EventBridge
// manages on the customer's behalf. So every bus is unconditionally SymmetricOnly
// (AES-256 KMS envelope); an ABSENT KmsKeyIdentifier means the AWS-owned default
// key, NOT no-encryption. Labeling the AWS-owned-key case as no-encryption would be
// a false alarm; treating it as a clean all-clear would hide that there is no
// customer key custody — so we record kmsKeyId=AWS_OWNED_KMS_KEY as evidence of the
// "no customer-managed key" tier while keeping the posture SymmetricOnly.
//
// (Events in transit are always TLS, and event-bus LOGS can be separately CMK
// encrypted; both are distinct surfaces and neither changes this at-rest verdict.)
type EventBridgeScanner struct{}

// eventBridgeAPI is the minimal slice of the eventbridge client this scanner uses.
// ListEventBuses is NextToken-paginated; defining it as an interface keeps the
// pagination + per-bus key-tier classification unit-testable with a fake (the
// concrete *eventbridge.Client satisfies it).
type eventBridgeAPI interface {
	ListEventBuses(ctx context.Context, in *eventbridge.ListEventBusesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListEventBusesOutput, error)
	DescribeEventBus(ctx context.Context, in *eventbridge.DescribeEventBusInput, optFns ...func(*eventbridge.Options)) (*eventbridge.DescribeEventBusOutput, error)
}

// Name returns the canonical service identifier.
func (EventBridgeScanner) Name() string { return "eventbridge" }

// Category returns the primary CryptaMap category.
func (EventBridgeScanner) Category() models.Category { return models.CategoryDataAtRest }

// classifyEventBus maps the at-rest KMS key tier of a single EventBridge event
// bus to a classified CryptoAsset. It is the SINGLE source of truth for the
// EventBridge classification logic and is pure (no AWS client, no context) so it
// can be table-tested directly.
//
// kmsKeyIdentifier is the bus's DescribeEventBus().KmsKeyIdentifier — a customer
// managed CMK ARN/id when present, or nil/empty for the AWS-owned default key.
//
// EventBridge ALWAYS encrypts event data at rest with AES-256 (universal AWS-doc
// guarantee; there is no per-bus disable), so posture is unconditionally
// SymmetricOnly. A populated identifier is the customer-managed-key tier; an
// absent/empty one is the AWS-owned default key tier (still AES-256) — recorded as
// kmsKeyId=AWS_OWNED_KMS_KEY with an explicit "no customer key custody" note, NEVER
// downgraded to no-encryption (false alarm) and NEVER presented as a clean
// all-clear (it hides the missing customer key custody).
func classifyEventBus(accountID, region, id string, kmsKeyIdentifier *string) models.CryptoAsset {
	a := services.NewAsset("eventbridge", models.CategoryDataAtRest, accountID, region, id, "AWS::Events::EventBus", services.AESAtRest())
	services.PostureProperty(&a, models.PostureSymmetricOnly)
	services.StampDocFact(&a, "high", "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-encryption-event-bus-cmkey-configure.html", "2026-06-15")

	kmsKey := "AWS_OWNED_KMS_KEY"
	if kmsKeyIdentifier != nil && *kmsKeyIdentifier != "" {
		kmsKey = *kmsKeyIdentifier
	} else {
		a.Properties["keyTier"] = "aws-owned-default"
		a.Properties["note"] = "EventBridge always encrypts events at rest; this bus uses the default AWS-owned key (no customer key custody), not customer-managed encryption."
	}
	a.Properties["kmsKeyId"] = kmsKey
	return a
}

// Scan lists event buses, then DescribeEventBus for each to read its at-rest
// KMS key identifier. EventBridge always encrypts event data at rest with an
// AES-256 KMS envelope (universal AWS-doc guarantee, no per-bus disable), so every
// bus is SymmetricOnly. A populated KmsKeyIdentifier is a customer managed CMK; an
// absent one is the AWS-owned default key (still AES-256) — recorded as the
// AWS_OWNED_KMS_KEY tier, never downgraded to no-encryption.
func (s EventBridgeScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := eventbridge.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListEventBuses and classifies each
// bus's at-rest key tier via DescribeEventBus. A ListEventBuses error is returned
// (not swallowed) so a denied/throttled scan stays VISIBLY incomplete.
func (s EventBridgeScanner) scan(ctx context.Context, client eventBridgeAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListEventBuses(ctx, &eventbridge.ListEventBusesInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("eventbridge ListEventBuses: %w", err)
		}
		// Cap the per-page batch to the remaining per-scanner budget BEFORE the
		// concurrent fan-out, so a pathological region never launches more than the
		// cap's worth of goroutines.
		buses := out.EventBuses
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(buses) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			buses = buses[:remaining]
		}
		page := services.MapConcurrent(ctx, services.DefaultInnerConcurrency, buses,
			func(ctx context.Context, b ebtypes.EventBus) (models.CryptoAsset, bool) {
				if b.Name == nil {
					return models.CryptoAsset{}, false
				}
				name := *b.Name
				id := name
				if b.Arn != nil && *b.Arn != "" {
					id = *b.Arn
				}

				desc, derr := client.DescribeEventBus(ctx, &eventbridge.DescribeEventBusInput{Name: &name})
				if derr != nil {
					fmt.Fprintf(os.Stderr, "eventbridge:%s DescribeEventBus: %v\n", name, derr)
					return models.CryptoAsset{}, false
				}

				// EventBridge always encrypts event data at rest with AES-256
				// (universal AWS-doc guarantee), so posture is unconditionally
				// SymmetricOnly. The KmsKeyIdentifier only distinguishes the key
				// tier; its absence is the AWS-owned default key, NOT no-encryption.
				// classifyEventBus is the single source of truth for this mapping.
				return classifyEventBus(accountID, region, id, desc.KmsKeyIdentifier), true
			})
		assets = append(assets, page...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
