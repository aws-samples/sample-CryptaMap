package datarest

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// CodeBuildScanner inspects AWS CodeBuild projects for the at-rest KMS key used to
// encrypt build output artifacts (and the project's S3-backed build cache).
//
// ALWAYS-ENCRYPTED (Type-A, doc-fact): CodeBuild always encrypts build output
// artifacts at rest with KMS — there is NO toggle to disable it. The project's
// EncryptionKey field selects WHICH key: a customer-specified CMK ARN/alias, or,
// when unset, the AWS-managed `aws/s3` key (per the AWS docs: "If you don't
// specify a value, CodeBuild uses the managed CMK for Amazon Simple Storage
// Service (Amazon S3)"). Both paths are a symmetric AES-256 KMS envelope, so
// posture is unconditionally SymmetricOnly — NEVER no-encryption. An ABSENT/default
// EncryptionKey is the AWS-managed default key tier (no customer key custody), a
// distinct evidence note, NOT a clean all-clear and NOT a no-encryption finding.
type CodeBuildScanner struct{}

// codebuildAPI is the minimal slice of the codebuild client this scanner uses.
// ListProjects is NextToken-paginated and BatchGetProjects resolves up to 100
// names per call; defining it as an interface keeps the pagination, batching, and
// classification logic unit-testable with a fake (the concrete *codebuild.Client
// satisfies it).
type codebuildAPI interface {
	ListProjects(ctx context.Context, in *codebuild.ListProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error)
	BatchGetProjects(ctx context.Context, in *codebuild.BatchGetProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error)
}

// Name returns the canonical service identifier.
func (CodeBuildScanner) Name() string { return "codebuild" }

// Category returns the primary CryptaMap category.
func (CodeBuildScanner) Category() models.Category { return models.CategoryDataAtRest }

// codebuildBatchSize is the BatchGetProjects per-call limit: the API accepts up
// to 100 project names per request.
const codebuildBatchSize = 100

// defaultS3ManagedKeyAlias is the AWS-managed S3 KMS key CodeBuild falls back to
// when a project sets no customer EncryptionKey.
const defaultS3ManagedKeyAlias = "alias/aws/s3"

// isAWSManagedS3Key reports whether a CodeBuild EncryptionKey value refers to the
// AWS-managed aws/s3 default key. AWS may return it either as the bare alias
// ("alias/aws/s3") or, as observed live, the fully-qualified ARN
// ("arn:aws:kms:<region>:<acct>:alias/aws/s3" — any partition). Matching only the
// bare alias would misread the ARN form as a customer CMK (false key-custody
// positive), so we match the alias as an ARN suffix, case-insensitively.
func isAWSManagedS3Key(k string) bool {
	k = strings.ToLower(strings.TrimSpace(k))
	return k == defaultS3ManagedKeyAlias || strings.HasSuffix(k, ":"+defaultS3ManagedKeyAlias)
}

// classifyCodeBuildProject is the PURE, SDK-client-free classification helper that
// maps a CodeBuild project's name, ARN, and EncryptionKey (the only fields the
// posture decision depends on) to a fully classified CryptoAsset. It is the SINGLE
// source of truth for CodeBuild's at-rest classification, driven both by Scan and
// by the table test.
//
// CodeBuild ALWAYS encrypts build output artifacts at rest with a symmetric
// AES-256 KMS envelope and there is NO toggle to disable it, so posture is
// unconditionally PostureSymmetricOnly — NEVER no-encryption, NEVER a fabricated
// all-clear. The EncryptionKey only selects the KEY TIER:
//   - a populated value that is NOT the AWS-managed `alias/aws/s3` default is a
//     customer-specified CMK (key custody with the customer) -> keyTier=customer-cmk
//   - an empty/nil EncryptionKey, OR the literal `alias/aws/s3`, is the AWS-managed
//     default key (no customer key custody) -> keyTier=aws-managed-default, plus a
//     note that this is NOT a clean all-clear.
//
// encryptionKey and arn are the *string SDK fields (nil/empty tolerated, never a
// crash): a nil/empty encryptionKey degrades to the AWS-managed default tier.
func classifyCodeBuildProject(accountID, region, name string, arn, encryptionKey *string) models.CryptoAsset {
	a := services.NewAsset("codebuild", models.CategoryDataAtRest, accountID, region, name, "AWS::CodeBuild::Project", services.AESAtRest())
	services.PostureProperty(&a, models.PostureSymmetricOnly)
	services.StampDocFact(&a, "high", "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codebuild-project.html", "2026-06-15")

	if arn != nil && *arn != "" {
		a.Properties["arn"] = *arn
	}

	// Distinguish the key tier from EncryptionKey. A populated value that is
	// NOT the default S3-managed alias is a customer-specified CMK (custody
	// with the customer); an empty/nil value OR the AWS-managed `alias/aws/s3`
	// default is the AWS-managed default key — still AES-256, but no customer key
	// custody, so it is recorded as the AWS-managed default tier, never an all-clear.
	//
	// IMPORTANT (live-validated 2026-06-17): DescribeProjects returns the AWS-managed
	// default key as the FULLY-QUALIFIED ARN
	// "arn:aws:kms:<region>:<acct>:alias/aws/s3", NOT the bare alias. A naive
	// equality check against "alias/aws/s3" therefore MISCLASSIFIED the real default
	// key as customer-cmk — a false positive on key CUSTODY (it would tell a
	// regulated customer "your CMK" when it is the AWS-managed default). Match the
	// alias as an ARN SUFFIX (and partition-agnostically), not by exact string.
	key := defaultS3ManagedKeyAlias
	keyTier := "aws-managed-default"
	if encryptionKey != nil && *encryptionKey != "" && !isAWSManagedS3Key(*encryptionKey) {
		key = *encryptionKey
		keyTier = "customer-cmk"
	}
	a.Properties["kmsKeyId"] = key
	a.Properties["keyTier"] = keyTier
	if keyTier == "aws-managed-default" {
		a.Properties["note"] = "CodeBuild build artifacts are always encrypted at rest; this project uses the AWS-managed aws/s3 key (no customer key custody), not a customer CMK."
	}
	return a
}

// Scan lists project names (NextToken paging), then resolves them in batches of
// up to 100 via BatchGetProjects to read each project's EncryptionKey. CodeBuild
// always encrypts build artifacts at rest with a symmetric AES-256 KMS key, so
// every project is SymmetricOnly; the EncryptionKey only distinguishes a customer
// CMK from the AWS-managed `aws/s3` default (recorded as kmsKeyId + keyTier).
func (s CodeBuildScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := codebuild.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListProjects, resolves names in
// batches of 100 via BatchGetProjects, and classifies each project's at-rest key
// tier. A ListProjects error is returned (not swallowed) so a denied/throttled
// scan stays VISIBLY incomplete.
func (s CodeBuildScanner) scan(ctx context.Context, client codebuildAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var nextToken *string
	for {
		out, err := client.ListProjects(ctx, &codebuild.ListProjectsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("codebuild ListProjects: %w", err)
		}

		// Cap the page to the remaining per-scanner budget BEFORE resolving, so a
		// pathological region never resolves more than the cap's worth of projects.
		names := out.Projects
		if remaining := services.MaxAssetsPerScanner - len(assets); remaining < len(names) {
			if remaining <= 0 {
				services.TruncationCapReached(len(assets), s.Name(), region)
				return assets, nil
			}
			names = names[:remaining]
		}

		// BatchGetProjects accepts up to 100 names per call; chunk accordingly.
		for start := 0; start < len(names); start += codebuildBatchSize {
			end := start + codebuildBatchSize
			if end > len(names) {
				end = len(names)
			}
			batch, berr := client.BatchGetProjects(ctx, &codebuild.BatchGetProjectsInput{Names: names[start:end]})
			if berr != nil {
				fmt.Fprintf(os.Stderr, "codebuild BatchGetProjects: %v\n", berr)
				continue
			}
			for _, p := range batch.Projects {
				name := ""
				if p.Name != nil {
					name = *p.Name
				}

				// CodeBuild always encrypts build artifacts at rest with a symmetric
				// AES-256 KMS envelope (universal AWS-doc guarantee, no disable toggle),
				// so posture is unconditionally SymmetricOnly. classifyCodeBuildProject is
				// the single source of truth for the posture + key-tier mapping.
				a := classifyCodeBuildProject(accountID, region, name, p.Arn, p.EncryptionKey)
				assets = append(assets, a)
			}
		}

		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}
	return assets, nil
}
