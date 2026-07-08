package datarest

// Tests for the medium-severity honesty fixes: per-resource read failures must
// never silently drop a KNOWN resource from the CBOM (all-clear by omission) and
// must never fabricate a key-custody verdict that was never observed. Each test
// here fails against the pre-fix behavior.

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	cbtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/aws/aws-sdk-go-v2/service/kendra"
	kentypes "github.com/aws/aws-sdk-go-v2/service/kendra/types"
	"github.com/aws/aws-sdk-go-v2/service/keyspaces"
	kstypes "github.com/aws/aws-sdk-go-v2/service/keyspaces/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

func hsp(s string) *string { return &s }

// --- CodeBuild: BatchGetProjects failure / ProjectsNotFound must not vanish ---

type dropfixCodeBuildClient struct {
	names    []string
	batchErr error
	notFound []string
}

func (f *dropfixCodeBuildClient) ListProjects(ctx context.Context, in *codebuild.ListProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.ListProjectsOutput, error) {
	return &codebuild.ListProjectsOutput{Projects: f.names}, nil
}

func (f *dropfixCodeBuildClient) BatchGetProjects(ctx context.Context, in *codebuild.BatchGetProjectsInput, optFns ...func(*codebuild.Options)) (*codebuild.BatchGetProjectsOutput, error) {
	if f.batchErr != nil {
		return nil, f.batchErr
	}
	out := &codebuild.BatchGetProjectsOutput{ProjectsNotFound: f.notFound}
	nf := map[string]bool{}
	for _, n := range f.notFound {
		nf[n] = true
	}
	for _, n := range in.Names {
		if !nf[n] {
			name := n
			out.Projects = append(out.Projects, cbtypes.Project{Name: &name})
		}
	}
	return out, nil
}

// TestCodeBuildBatchErrorEmitsUnresolvedProjects verifies the honesty contract:
// project names already known from ListProjects must NOT be silently dropped when
// BatchGetProjects fails — each must surface with an undetermined key tier.
func TestCodeBuildBatchErrorEmitsUnresolvedProjects(t *testing.T) {
	client := &dropfixCodeBuildClient{
		names:    []string{"proj-a", "proj-b"},
		batchErr: errors.New("throttled"),
	}
	assets, err := CodeBuildScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("expected 2 placeholder assets for the failed batch (never a silent drop), got %d", len(assets))
	}
	for _, a := range assets {
		if a.Properties["kmsKeyId"] != "UNRESOLVED" || a.Properties["keyTier"] != "unknown" {
			t.Errorf("asset %q: kmsKeyId=%q keyTier=%q, want UNRESOLVED/unknown (custody never observed)", a.Name, a.Properties["kmsKeyId"], a.Properties["keyTier"])
		}
		if a.Properties["posture"] != string(models.PostureSymmetricOnly) {
			t.Errorf("asset %q: posture=%q, want %q (always-encrypted doc-fact)", a.Name, a.Properties["posture"], models.PostureSymmetricOnly)
		}
		if a.Properties["note"] == "" {
			t.Errorf("asset %q: expected an honesty note on the batch-failure path", a.Name)
		}
	}
}

// TestCodeBuildProjectsNotFoundEmitsUnresolved verifies names ListProjects
// returned but BatchGetProjects could not resolve are emitted, not dropped.
func TestCodeBuildProjectsNotFoundEmitsUnresolved(t *testing.T) {
	client := &dropfixCodeBuildClient{
		names:    []string{"proj-a", "proj-gone"},
		notFound: []string{"proj-gone"},
	}
	assets, err := CodeBuildScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("expected 2 assets (1 resolved + 1 not-found placeholder), got %d", len(assets))
	}
	var found bool
	for _, a := range assets {
		if a.Name == "proj-gone" {
			found = true
			if a.Properties["keyTier"] != "unknown" {
				t.Errorf("not-found project keyTier=%q, want unknown", a.Properties["keyTier"])
			}
		}
	}
	if !found {
		t.Error("ProjectsNotFound name proj-gone vanished from the CBOM (silent drop)")
	}
}

// --- Keyspaces: ListTables / GetTable failures ---

type dropfixKeyspacesClient struct {
	listTablesErr error
	getTableErr   error
}

func (f *dropfixKeyspacesClient) ListKeyspaces(ctx context.Context, in *keyspaces.ListKeyspacesInput, optFns ...func(*keyspaces.Options)) (*keyspaces.ListKeyspacesOutput, error) {
	return &keyspaces.ListKeyspacesOutput{Keyspaces: []kstypes.KeyspaceSummary{{KeyspaceName: hsp("app_ks")}}}, nil
}

func (f *dropfixKeyspacesClient) ListTables(ctx context.Context, in *keyspaces.ListTablesInput, optFns ...func(*keyspaces.Options)) (*keyspaces.ListTablesOutput, error) {
	if f.listTablesErr != nil {
		return nil, f.listTablesErr
	}
	return &keyspaces.ListTablesOutput{Tables: []kstypes.TableSummary{{KeyspaceName: hsp("app_ks"), TableName: hsp("orders")}}}, nil
}

func (f *dropfixKeyspacesClient) GetTable(ctx context.Context, in *keyspaces.GetTableInput, optFns ...func(*keyspaces.Options)) (*keyspaces.GetTableOutput, error) {
	if f.getTableErr != nil {
		return nil, f.getTableErr
	}
	return &keyspaces.GetTableOutput{}, nil
}

// TestKeyspacesListTablesErrorEmitsPlaceholder verifies a denied/throttled
// ListTables no longer silently truncates: the keyspace stays visible in the CBOM
// as a PostureUnknown placeholder instead of a clean success with missing rows.
func TestKeyspacesListTablesErrorEmitsPlaceholder(t *testing.T) {
	client := &dropfixKeyspacesClient{listTablesErr: errors.New("access denied")}
	assets, err := KeyspacesScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 placeholder asset for the unreadable keyspace, got %d", len(assets))
	}
	a := assets[0]
	if a.Properties["posture"] != string(models.PostureUnknown) {
		t.Errorf("posture = %q, want %q (coverage gap must stay visible)", a.Properties["posture"], models.PostureUnknown)
	}
	if a.Properties["note"] == "" {
		t.Error("expected an honesty note on the ListTables-failure placeholder")
	}
}

// TestKeyspacesGetTableErrorRecordsUnknownCustody verifies a GetTable failure no
// longer fabricates the AWS-owned-key custody verdict: the key is recorded as
// UNRESOLVED (the table may use a customer CMK the role cannot read) while the
// doc-fact SymmetricOnly posture is retained.
func TestKeyspacesGetTableErrorRecordsUnknownCustody(t *testing.T) {
	client := &dropfixKeyspacesClient{getTableErr: errors.New("throttled")}
	assets, err := KeyspacesScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(assets))
	}
	a := assets[0]
	if a.Properties["kmsKeyId"] != "UNRESOLVED" {
		t.Errorf("kmsKeyId = %q, want UNRESOLVED (GetTable failed; custody never observed, never AWS_OWNED_KMS_KEY)", a.Properties["kmsKeyId"])
	}
	if a.Properties["keyTier"] != "unknown" {
		t.Errorf("keyTier = %q, want unknown", a.Properties["keyTier"])
	}
	if a.Properties["posture"] != string(models.PostureSymmetricOnly) {
		t.Errorf("posture = %q, want %q (doc-fact posture unaffected by the read failure)", a.Properties["posture"], models.PostureSymmetricOnly)
	}
}

// --- EventBridge: DescribeEventBus failure must not drop the bus ---

type dropfixEventBridgeClient struct {
	descErr error
}

func (f *dropfixEventBridgeClient) ListEventBuses(ctx context.Context, in *eventbridge.ListEventBusesInput, optFns ...func(*eventbridge.Options)) (*eventbridge.ListEventBusesOutput, error) {
	return &eventbridge.ListEventBusesOutput{EventBuses: []ebtypes.EventBus{{Name: hsp("orders-bus")}}}, nil
}

func (f *dropfixEventBridgeClient) DescribeEventBus(ctx context.Context, in *eventbridge.DescribeEventBusInput, optFns ...func(*eventbridge.Options)) (*eventbridge.DescribeEventBusOutput, error) {
	return nil, f.descErr
}

// TestEventBridgeDescribeErrorEmitsUnresolvedAsset verifies a DescribeEventBus
// failure no longer vanishes the bus: posture is doc-guaranteed SymmetricOnly, so
// the asset is emitted with custody honestly undetermined.
func TestEventBridgeDescribeErrorEmitsUnresolvedAsset(t *testing.T) {
	client := &dropfixEventBridgeClient{descErr: errors.New("throttled")}
	assets, err := EventBridgeScanner{}.scan(context.Background(), client, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset for the undescribable bus (never a silent drop), got %d", len(assets))
	}
	a := assets[0]
	if a.Properties["posture"] != string(models.PostureSymmetricOnly) {
		t.Errorf("posture = %q, want %q (always-encrypted doc-fact)", a.Properties["posture"], models.PostureSymmetricOnly)
	}
	if a.Properties["kmsKeyId"] != "UNRESOLVED" || a.Properties["keyTier"] != "unknown" {
		t.Errorf("kmsKeyId=%q keyTier=%q, want UNRESOLVED/unknown (custody never observed)", a.Properties["kmsKeyId"], a.Properties["keyTier"])
	}
}

// --- Kendra: DescribeIndex failure must not drop the index ---

type dropfixKendraClient struct {
	descErr error
}

func (f *dropfixKendraClient) ListIndices(ctx context.Context, in *kendra.ListIndicesInput, optFns ...func(*kendra.Options)) (*kendra.ListIndicesOutput, error) {
	return &kendra.ListIndicesOutput{IndexConfigurationSummaryItems: []kentypes.IndexConfigurationSummary{{Id: hsp("idx-1")}}}, nil
}

func (f *dropfixKendraClient) DescribeIndex(ctx context.Context, in *kendra.DescribeIndexInput, optFns ...func(*kendra.Options)) (*kendra.DescribeIndexOutput, error) {
	return nil, f.descErr
}

// TestKendraDescribeErrorEmitsUnresolvedAsset verifies a DescribeIndex failure no
// longer vanishes the index: the always-encrypted doc-fact posture is emitted with
// custody honestly undetermined.
func TestKendraDescribeErrorEmitsUnresolvedAsset(t *testing.T) {
	client := &dropfixKendraClient{descErr: errors.New("access denied")}
	assets, err := KendraScanner{}.scan(context.Background(), client, "111122223333", "ap-south-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected 1 asset for the undescribable index (never a silent drop), got %d", len(assets))
	}
	a := assets[0]
	if a.Properties["posture"] != string(models.PostureSymmetricOnly) {
		t.Errorf("posture = %q, want %q (always-encrypted doc-fact)", a.Properties["posture"], models.PostureSymmetricOnly)
	}
	if a.Properties["kmsKeyId"] != "UNRESOLVED" || a.Properties["keyTier"] != "unknown" {
		t.Errorf("kmsKeyId=%q keyTier=%q, want UNRESOLVED/unknown (custody never observed)", a.Properties["kmsKeyId"], a.Properties["keyTier"])
	}
}

// --- Bedrock: knowledge-base custody tier must not be fabricated ---

// TestBedrockKnowledgeBaseAssetUnknownCustody verifies the machine-readable
// custody fields for a knowledge base no longer assert the AWS-managed default
// (the SDK exposes no per-KB CMK field; the downstream store may be
// CMK-encrypted): keyTier must be unknown, with the KB honesty note retained.
func TestBedrockKnowledgeBaseAssetUnknownCustody(t *testing.T) {
	a := newBedrockKnowledgeBaseAsset("111122223333", "us-east-1", "kb-1")
	if a.Properties["keyTier"] != "unknown" {
		t.Errorf("keyTier = %q, want unknown (per-KB CMK not exposed by the API — never a definitive tier)", a.Properties["keyTier"])
	}
	if a.Properties["kmsKeyId"] != "UNRESOLVED" {
		t.Errorf("kmsKeyId = %q, want UNRESOLVED", a.Properties["kmsKeyId"])
	}
	if a.Properties["note"] != kbNoCMKFieldNote {
		t.Errorf("note = %q, want the KB-specific honesty note", a.Properties["note"])
	}
	if a.Properties["posture"] != string(models.PostureSymmetricOnly) {
		t.Errorf("posture = %q, want %q (always-encrypted)", a.Properties["posture"], models.PostureSymmetricOnly)
	}
}
