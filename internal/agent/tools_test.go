package agent

import (
	"encoding/json"
	"testing"

	"github.com/aws-samples/cryptamap/internal/pqc"
	"github.com/aws-samples/cryptamap/internal/roadmap"
)

// testCorpus builds a small, fixed Corpus so these tests exercise the tool
// executor's logic directly — no LLM, no network — against the exact code
// path the live agent uses to answer questions and propose UI actions. This
// is what lets ui_filter_assets/ui_select_asset/ui_view_roadmap be verified
// deterministically even when a real Gemini call isn't available (rate
// limits, no key, offline CI).
func testCorpus() *Corpus {
	assets := []AssetView{
		{
			BomRef: "crypto-kms-1", DisplayName: "AWS KMS", Service: "kms_spec",
			ResourceID: "key-1", AccountID: "111111111111", Region: "us-east-1",
			AWSCategory: "Security, Identity & Compliance", CryptoFunction: "key-management",
			Posture: "non-pqc-classical", PQCStatus: string(pqc.StatusAvailable),
		},
		{
			BomRef: "crypto-s3-1", DisplayName: "Amazon S3", Service: "s3",
			ResourceID: "bucket-1", AccountID: "111111111111", Region: "us-east-1",
			AWSCategory: "Storage", CryptoFunction: "data-at-rest",
			Posture: "symmetric-only", PQCStatus: string(pqc.StatusNotApplicable),
		},
		{
			BomRef: "crypto-alb-1", DisplayName: "Application Load Balancer", Service: "alb",
			ResourceID: "alb-1", AccountID: "222222222222", Region: "eu-west-1",
			AWSCategory: "Networking & Content Delivery", CryptoFunction: "data-in-transit",
			Posture: "legacy-tls", PQCStatus: string(pqc.StatusNotYet),
		},
	}
	rm := roadmap.Roadmap{
		AsOf:          "2026-06-03",
		GeneratedFrom: "org",
		Items: []roadmap.RoadmapItem{
			{Service: "kms_spec", DisplayName: "AWS KMS", AssetBomRef: "crypto-kms-1", PQCStatus: pqc.StatusAvailable},
			{Service: "alb", DisplayName: "Application Load Balancer", AssetBomRef: "crypto-alb-1", PQCStatus: pqc.StatusNotYet},
		},
	}
	return &Corpus{Assets: assets, Roadmap: rm}
}

func decodeResult(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode tool result: %v (raw=%s)", err, raw)
	}
	return m
}

func TestListAssetsCounts(t *testing.T) {
	ex := NewToolExecutor(testCorpus())
	raw, err := ex.Execute("list_assets", json.RawMessage(`{"posture":"legacy-tls"}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := decodeResult(t, raw)
	if got["totalMatched"] != float64(1) {
		t.Fatalf("totalMatched = %v, want 1", got["totalMatched"])
	}
}

func TestListFacetsEnumeratesRealValues(t *testing.T) {
	ex := NewToolExecutor(testCorpus())
	raw, err := ex.Execute("list_facets", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := decodeResult(t, raw)
	services, ok := got["services"].([]any)
	if !ok || len(services) != 3 {
		t.Fatalf("services = %v, want 3 entries", got["services"])
	}
}

func TestUIFilterAssetsValidatesAndSetsAction(t *testing.T) {
	ex := NewToolExecutor(testCorpus())
	raw, err := ex.Execute("ui_filter_assets", json.RawMessage(`{"tokens":[{"propertyKey":"posture","operator":"=","value":"legacy-tls"}]}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := decodeResult(t, raw)
	if got["ok"] != true {
		t.Fatalf("ok = %v, want true; result=%v", got["ok"], got)
	}
	if got["matchCount"] != float64(1) {
		t.Fatalf("matchCount = %v, want 1", got["matchCount"])
	}
	action := ex.PendingAction()
	if action == nil || action.Type != "filter_assets" {
		t.Fatalf("PendingAction = %+v, want type filter_assets", action)
	}
	if action.Query == nil || len(action.Query.Tokens) != 1 || action.Query.Tokens[0].Value != "legacy-tls" {
		t.Fatalf("Query = %+v, want one token value=legacy-tls", action.Query)
	}
	// This is the exact shape dashboard/src/pages/AssetsView.tsx's
	// parseQueryParam expects from ?q=: {"tokens":[...],"operation":"and"|"or"}.
	b, _ := json.Marshal(action.Query)
	var roundTrip struct {
		Tokens []struct {
			PropertyKey string `json:"propertyKey"`
			Operator    string `json:"operator"`
			Value       string `json:"value"`
		} `json:"tokens"`
		Operation string `json:"operation"`
	}
	if err := json.Unmarshal(b, &roundTrip); err != nil {
		t.Fatalf("Action.Query does not round-trip as AssetsView's PropertyFilterProps.Query shape: %v", err)
	}
	if roundTrip.Operation != "and" {
		t.Fatalf("Operation = %q, want default \"and\"", roundTrip.Operation)
	}
}

func TestUIFilterAssetsRejectsUnknownValue(t *testing.T) {
	ex := NewToolExecutor(testCorpus())
	raw, err := ex.Execute("ui_filter_assets", json.RawMessage(`{"tokens":[{"propertyKey":"posture","operator":"=","value":"does-not-exist"}]}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := decodeResult(t, raw)
	if got["ok"] != false {
		t.Fatalf("ok = %v, want false for an unknown facet value", got["ok"])
	}
	if ex.PendingAction() != nil {
		t.Fatalf("PendingAction should stay nil when validation fails, got %+v", ex.PendingAction())
	}
}

func TestUIFilterAssetsRejectsUnknownPropertyKey(t *testing.T) {
	ex := NewToolExecutor(testCorpus())
	raw, err := ex.Execute("ui_filter_assets", json.RawMessage(`{"tokens":[{"propertyKey":"notAFacet","operator":"=","value":"x"}]}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := decodeResult(t, raw)
	if got["ok"] != false {
		t.Fatalf("ok = %v, want false for an unknown propertyKey", got["ok"])
	}
}

func TestUISelectAssetValidatesAndSetsAction(t *testing.T) {
	ex := NewToolExecutor(testCorpus())
	raw, err := ex.Execute("ui_select_asset", json.RawMessage(`{"bomRef":"crypto-s3-1"}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := decodeResult(t, raw)
	if got["ok"] != true {
		t.Fatalf("ok = %v, want true", got["ok"])
	}
	action := ex.PendingAction()
	if action == nil || action.Type != "select_asset" || action.AssetBomRef != "crypto-s3-1" {
		t.Fatalf("PendingAction = %+v, want select_asset crypto-s3-1", action)
	}
}

func TestUISelectAssetRejectsUnknownBomRef(t *testing.T) {
	ex := NewToolExecutor(testCorpus())
	raw, err := ex.Execute("ui_select_asset", json.RawMessage(`{"bomRef":"does-not-exist"}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := decodeResult(t, raw)
	if got["ok"] != false {
		t.Fatalf("ok = %v, want false for an unknown bomRef", got["ok"])
	}
	if ex.PendingAction() != nil {
		t.Fatalf("PendingAction should stay nil, got %+v", ex.PendingAction())
	}
}

func TestUIViewRoadmapResolvesByDisplayNameOrRawID(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantSvc string
	}{
		{"raw id", `{"service":"kms_spec"}`, "kms_spec"},
		{"exact display name", `{"service":"AWS KMS"}`, "kms_spec"},
		{"case-insensitive substring", `{"service":"kms"}`, "kms_spec"},
		{"no filter", `{}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ex := NewToolExecutor(testCorpus())
			raw, err := ex.Execute("ui_view_roadmap", json.RawMessage(c.input))
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			got := decodeResult(t, raw)
			if got["ok"] != true {
				t.Fatalf("ok = %v, want true; result=%v", got["ok"], got)
			}
			action := ex.PendingAction()
			if action == nil || action.Type != "view_roadmap" || action.Service != c.wantSvc {
				t.Fatalf("PendingAction = %+v, want view_roadmap service=%q", action, c.wantSvc)
			}
		})
	}
}

func TestUIViewRoadmapRejectsUnknownService(t *testing.T) {
	ex := NewToolExecutor(testCorpus())
	raw, err := ex.Execute("ui_view_roadmap", json.RawMessage(`{"service":"Azure Front Door"}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := decodeResult(t, raw)
	if got["ok"] != false {
		t.Fatalf("ok = %v, want false for a service that isn't in this scan (the 'impossible request' case)", got["ok"])
	}
	if ex.PendingAction() != nil {
		t.Fatalf("PendingAction should stay nil, got %+v", ex.PendingAction())
	}
}

func TestExecuteMalformedArgsReturnsGoError(t *testing.T) {
	ex := NewToolExecutor(testCorpus())
	// Malformed JSON args: Execute should return a Go error (not panic, not a
	// silent no-op) — orchestrate.Run converts this into a normal tool-result
	// error the model sees, rather than aborting the request.
	if _, err := ex.Execute("ui_select_asset", json.RawMessage(`{not valid json`)); err == nil {
		t.Fatal("Execute with malformed args should return an error")
	}
}

func TestExecuteUnknownToolNameIsHandledGracefully(t *testing.T) {
	ex := NewToolExecutor(testCorpus())
	raw, err := ex.Execute("delete_everything", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := decodeResult(t, raw)
	if got["ok"] != false {
		t.Fatalf("ok = %v, want false for an unknown tool name", got["ok"])
	}
}

func TestResetClearsPendingAction(t *testing.T) {
	ex := NewToolExecutor(testCorpus())
	if _, err := ex.Execute("ui_select_asset", json.RawMessage(`{"bomRef":"crypto-s3-1"}`)); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if ex.PendingAction() == nil {
		t.Fatal("expected a pending action before Reset")
	}
	ex.Reset()
	if ex.PendingAction() != nil {
		t.Fatalf("PendingAction after Reset = %+v, want nil", ex.PendingAction())
	}
}
