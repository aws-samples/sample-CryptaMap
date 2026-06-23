package datarest

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// StepFunctionsScanner inspects AWS Step Functions state machines for their
// at-rest encryption configuration over the execution history and the state
// machine definition.
//
// ALWAYS-ON (not opt-in): Step Functions automatically enables encryption at
// rest for every state machine using an AWS owned key at no charge; there is no
// API toggle to disable it. So posture is unconditionally SymmetricOnly — never
// NoEncryption. The EncryptionConfiguration.Type distinguishes only the KEY
// TIER, not whether encryption is on:
//   - AWS_OWNED_KEY            -> AWS-owned default key (still AES-256). This is
//     "no customer key custody", recorded as kmsKeyId=AWS_OWNED_KMS_KEY — NOT a
//     clean all-clear and NOT a no-encryption finding (honesty contract).
//   - CUSTOMER_MANAGED_KMS_KEY -> a customer CMK, whose ARN/id is in KmsKeyId.
//
// When a state machine has no EncryptionConfiguration block at all, that simply
// means the AWS-owned default key is in effect (the encryption is still active),
// so the same SymmetricOnly classification applies. The KMS envelope is a
// symmetric AES-256 key — quantum-resistant, a SymmetricOnly migration class.
type StepFunctionsScanner struct{}

// stepFunctionsAPI is the minimal slice of the sfn client this scanner uses.
// ListStateMachines is NextToken-paginated; defining it as an interface keeps the
// pagination + per-state-machine encryption classification unit-testable with a
// fake (the concrete *sfn.Client satisfies it).
type stepFunctionsAPI interface {
	ListStateMachines(ctx context.Context, in *sfn.ListStateMachinesInput, optFns ...func(*sfn.Options)) (*sfn.ListStateMachinesOutput, error)
	DescribeStateMachine(ctx context.Context, in *sfn.DescribeStateMachineInput, optFns ...func(*sfn.Options)) (*sfn.DescribeStateMachineOutput, error)
}

// classifyStateMachineEncryption is the PURE classification core for a Step
// Functions state machine: it maps the (optional) EncryptionConfiguration and
// the state-machine type to a fully populated CryptoAsset. It takes no AWS
// client and no context so the table test can drive every key-tier branch
// directly.
//
// Honesty contract baked in here:
//   - Step Functions ALWAYS encrypts at rest, so the posture is unconditionally
//     models.PostureSymmetricOnly — never PostureNoEncryption, even when ec is
//     nil/empty.
//   - A nil EncryptionConfiguration, an empty Type, or an explicit
//     AWS_OWNED_KEY all degrade to the AWS-owned default key: kmsKeyId is the
//     AWS_OWNED_KMS_KEY sentinel, keyTier="aws-owned-default", and an explicit
//     "no customer key custody / not a clean all-clear" note — never a fabricated
//     customer-CMK all-clear.
//   - Only a CUSTOMER_MANAGED_KMS_KEY with a non-empty KmsKeyId records the
//     customer CMK ARN/id and omits the AWS-owned note.
func classifyStateMachineEncryption(accountID, region, name string, smType sfntypes.StateMachineType, ec *sfntypes.EncryptionConfiguration) models.CryptoAsset {
	// Always encrypted at rest (AES-256 KMS envelope), so posture is
	// unconditionally SymmetricOnly. The EncryptionConfiguration only
	// distinguishes the key tier; its absence means the AWS-owned default key is
	// in effect (still encrypted), never no-encryption.
	a := services.NewAsset("stepfunctions", models.CategoryDataAtRest, accountID, region, name, "AWS::StepFunctions::StateMachine", services.AESAtRest())
	services.PostureProperty(&a, models.PostureSymmetricOnly)
	services.StampDocFact(&a, "high", "https://docs.aws.amazon.com/step-functions/latest/apireference/API_EncryptionConfiguration.html", "2026-06-15")

	kmsKey := "AWS_OWNED_KMS_KEY"
	encType := string(sfntypes.EncryptionTypeAwsOwnedKey)
	if ec != nil {
		if ec.Type != "" {
			encType = string(ec.Type)
		}
		// A customer-managed CMK carries a key id/ARN; AWS_OWNED_KEY
		// leaves KmsKeyId nil, in which case we keep the AWS-owned
		// sentinel (no customer key custody).
		if ec.KmsKeyId != nil && *ec.KmsKeyId != "" {
			kmsKey = *ec.KmsKeyId
		}
		if ec.KmsDataKeyReusePeriodSeconds != nil {
			a.Properties["kmsDataKeyReusePeriodSeconds"] = strconv.FormatInt(int64(*ec.KmsDataKeyReusePeriodSeconds), 10)
		}
	}
	a.Properties["encryptionType"] = encType
	a.Properties["kmsKeyId"] = kmsKey
	if string(smType) != "" {
		a.Properties["stateMachineType"] = string(smType)
	}
	if encType == string(sfntypes.EncryptionTypeAwsOwnedKey) {
		a.Properties["keyTier"] = "aws-owned-default"
		a.Properties["note"] = "Step Functions always encrypts execution history at rest with AES-256; this state machine uses the AWS-owned default key (no customer key custody), not a clean all-clear and not a no-encryption finding."
	}
	return a
}

// Name returns the canonical service identifier.
func (StepFunctionsScanner) Name() string { return "stepfunctions" }

// Category returns the primary CryptaMap category.
func (StepFunctionsScanner) Category() models.Category { return models.CategoryDataAtRest }

// Scan lists state machines (NextToken cursor), then DescribeStateMachine for
// each to read its EncryptionConfiguration. Step Functions always encrypts at
// rest (universal AWS-doc guarantee), so every state machine is SymmetricOnly;
// the config only reveals whether the key is AWS-owned or a customer CMK.
func (s StepFunctionsScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := sfn.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListStateMachines and classifies
// each state machine's EncryptionConfiguration via DescribeStateMachine. A
// ListStateMachines error is returned (not swallowed) so a denied/throttled scan
// stays VISIBLY incomplete.
func (s StepFunctionsScanner) scan(ctx context.Context, client stepFunctionsAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListStateMachines(ctx, &sfn.ListStateMachinesInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("stepfunctions ListStateMachines: %w", err)
		}
		// Cap the per-page batch to the remaining per-scanner budget BEFORE the
		// concurrent fan-out so a pathological region never launches more than the
		// cap's worth of goroutines.
		items := out.StateMachines
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(items) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			items = items[:remaining]
		}
		page := services.MapConcurrent(ctx, services.DefaultInnerConcurrency, items,
			func(ctx context.Context, item sfntypes.StateMachineListItem) (models.CryptoAsset, bool) {
				if item.StateMachineArn == nil {
					return models.CryptoAsset{}, false
				}
				arn := *item.StateMachineArn
				name := arn
				if item.Name != nil && *item.Name != "" {
					name = *item.Name
				}

				desc, derr := client.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{StateMachineArn: &arn})
				if derr != nil {
					fmt.Fprintf(os.Stderr, "stepfunctions:%s DescribeStateMachine: %v\n", name, derr)
					return models.CryptoAsset{}, false
				}

				// Single source of truth for the classify path: map the
				// EncryptionConfiguration + state-machine type to the asset.
				a := classifyStateMachineEncryption(accountID, region, name, item.Type, desc.EncryptionConfiguration)
				return a, true
			})
		assets = append(assets, page...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
