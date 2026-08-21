package agent

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ToolExecutor executes the small, deterministic tool set exposed to the
// model. Read tools (list_facets, list_assets, get_roadmap) answer strictly
// from Corpus — the model can only ever repeat what a tool actually returned.
// Action tools (ui_*) validate every argument against Corpus BEFORE recording
// a pendingAction, so the model can never propose a UI action for an asset,
// service, or filter value that does not exist in this scan; an invalid
// request comes back as a structured {"ok":false,"error":...} tool result
// instead of a fabricated success.
type ToolExecutor struct {
	corpus        *Corpus
	pendingAction *Action
}

// NewToolExecutor builds a ToolExecutor over corpus.
func NewToolExecutor(corpus *Corpus) *ToolExecutor {
	return &ToolExecutor{corpus: corpus}
}

// PendingAction returns the action set by the most recent successful ui_*
// tool call since the last Reset, or nil if none was set.
func (t *ToolExecutor) PendingAction() *Action {
	return t.pendingAction
}

// Reset clears any pending action. Called once per incoming chat request
// (orchestrate.Run) so a stale action from a previous turn's history can never
// leak into a new reply.
func (t *ToolExecutor) Reset() {
	t.pendingAction = nil
}

// Specs returns the tool declarations advertised to the model.
func (t *ToolExecutor) Specs() []ToolSpec {
	return []ToolSpec{
		{
			Name: "list_facets",
			Description: "List every distinct service, account, region, posture, and PQC status that actually exists in this scan, with counts. " +
				"Call this before referring to any specific service/account/region name to confirm it exists — never assume a name is valid.",
			Parameters: json.RawMessage(`{"type":"object","properties":{}}`),
		},
		{
			Name: "list_assets",
			Description: "List and count crypto assets matching optional filters. The returned totalMatched is always the true count even when " +
				"the sample items list is capped — use this tool (not counting items yourself) to answer any 'how many' question.",
			Parameters: json.RawMessage(`{
				"type":"object",
				"properties":{
					"posture":{"type":"string","description":"e.g. no-encryption, legacy-tls, non-pqc-classical, pqc-hybrid, symmetric-only, pqc-ready, unknown"},
					"pqcStatus":{"type":"string","description":"e.g. available, hybrid-tls-only, not-yet, not-applicable, not-encrypted"},
					"service":{"type":"string","description":"raw service id, from list_facets"},
					"accountId":{"type":"string"},
					"region":{"type":"string"},
					"limit":{"type":"integer","description":"max sample items to return (default 15, max 50); totalMatched is unaffected"}
				}
			}`),
		},
		{
			Name: "get_roadmap",
			Description: "Get PQC migration roadmap items (priority-ranked recommendations with the verified AWS action and source citation), " +
				"optionally scoped to one service. With no service filter, also returns the byService/byAccount rollups.",
			Parameters: json.RawMessage(`{
				"type":"object",
				"properties":{
					"service":{"type":"string","description":"a raw service id or display name, e.g. kms_spec or 'AWS KMS'"},
					"limit":{"type":"integer","description":"max items to return (default 15, max 50)"}
				}
			}`),
		},
		{
			Name: "ui_filter_assets",
			Description: "Apply a filter to the dashboard's Assets page. Every propertyKey/value pair is validated against this scan's real data " +
				"before the filter is proposed — call list_facets first if you are not sure a value exists.",
			Parameters: json.RawMessage(`{
				"type":"object",
				"properties":{
					"operation":{"type":"string","enum":["and","or"],"description":"default and"},
					"tokens":{
						"type":"array",
						"items":{
							"type":"object",
							"properties":{
								"propertyKey":{"type":"string","enum":["accountId","region","awsCategory","cryptoFunction","posture","pqcStatus"]},
								"operator":{"type":"string","enum":["=","!="]},
								"value":{"type":"string"}
							},
							"required":["propertyKey","operator","value"]
						}
					}
				},
				"required":["tokens"]
			}`),
		},
		{
			Name:        "ui_select_asset",
			Description: "Open the detail panel for one specific asset in the dashboard, by its bomRef (from list_assets/get_roadmap results).",
			Parameters: json.RawMessage(`{
				"type":"object",
				"properties":{"bomRef":{"type":"string"}},
				"required":["bomRef"]
			}`),
		},
		{
			Name:        "ui_view_roadmap",
			Description: "Navigate the dashboard to the PQC migration roadmap, optionally scoped to one service.",
			Parameters: json.RawMessage(`{
				"type":"object",
				"properties":{"service":{"type":"string","description":"a raw service id or display name to scope to, e.g. kms_spec or 'AWS KMS'"}}
			}`),
		},
	}
}

// Execute dispatches one tool call by name. A non-nil error means the call
// itself was malformed (e.g. invalid JSON args) and is converted by
// orchestrate.Run into a structured tool-result error fed back to the model.
// A semantically invalid but well-formed call (unknown value, unknown asset,
// unresolvable service) is NOT a Go error — it is a normal
// {"ok":false,"error":...} result, so the model sees it as part of the
// conversation and can retry or explain rather than the request aborting.
func (t *ToolExecutor) Execute(name string, args json.RawMessage) (json.RawMessage, error) {
	switch name {
	case "list_facets":
		return t.listFacets()
	case "list_assets":
		return t.listAssets(args)
	case "get_roadmap":
		return t.getRoadmap(args)
	case "ui_filter_assets":
		return t.uiFilterAssets(args)
	case "ui_select_asset":
		return t.uiSelectAsset(args)
	case "ui_view_roadmap":
		return t.uiViewRoadmap(args)
	default:
		return errResult(fmt.Sprintf("unknown tool %q", name)), nil
	}
}

func okResult(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return errResult(fmt.Sprintf("internal error encoding result: %v", err)), nil
	}
	return b, nil
}

func errResult(msg string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"ok": false, "error": msg})
	return b
}

// --- read tools ---

type assetFilters struct {
	Posture   string `json:"posture"`
	PQCStatus string `json:"pqcStatus"`
	Service   string `json:"service"`
	AccountID string `json:"accountId"`
	Region    string `json:"region"`
	Limit     int    `json:"limit"`
}

func clampLimit(n int) int {
	if n <= 0 {
		return 15
	}
	if n > 50 {
		return 50
	}
	return n
}

func (t *ToolExecutor) listAssets(args json.RawMessage) (json.RawMessage, error) {
	var f assetFilters
	if len(args) > 0 {
		if err := json.Unmarshal(args, &f); err != nil {
			return nil, fmt.Errorf("invalid list_assets arguments: %w", err)
		}
	}
	limit := clampLimit(f.Limit)

	var matched []AssetView
	countsByPosture := map[string]int{}
	for _, a := range t.corpus.Assets {
		if f.Posture != "" && a.Posture != f.Posture {
			continue
		}
		if f.PQCStatus != "" && a.PQCStatus != f.PQCStatus {
			continue
		}
		if f.Service != "" && a.Service != f.Service {
			continue
		}
		if f.AccountID != "" && a.AccountID != f.AccountID {
			continue
		}
		if f.Region != "" && a.Region != f.Region {
			continue
		}
		matched = append(matched, a)
		countsByPosture[a.Posture]++
	}

	sample := matched
	if len(sample) > limit {
		sample = sample[:limit]
	}

	return okResult(map[string]any{
		"ok":              true,
		"totalMatched":    len(matched),
		"countsByPosture": countsByPosture,
		"items":           sample,
	})
}

func (t *ToolExecutor) listFacets() (json.RawMessage, error) {
	type facetCount struct {
		ID    string `json:"id"`
		Label string `json:"label,omitempty"`
		Count int    `json:"count"`
	}
	services := map[string]*facetCount{}
	accounts := map[string]int{}
	regions := map[string]int{}
	postures := map[string]int{}
	pqcStatuses := map[string]int{}

	for _, a := range t.corpus.Assets {
		if a.Service != "" {
			e, ok := services[a.Service]
			if !ok {
				e = &facetCount{ID: a.Service, Label: a.DisplayName}
				services[a.Service] = e
			}
			e.Count++
		}
		if a.AccountID != "" {
			accounts[a.AccountID]++
		}
		if a.Region != "" {
			regions[a.Region]++
		}
		postures[a.Posture]++
		if a.PQCStatus != "" {
			pqcStatuses[a.PQCStatus]++
		}
	}

	svcList := make([]facetCount, 0, len(services))
	for _, e := range services {
		svcList = append(svcList, *e)
	}
	sort.Slice(svcList, func(i, j int) bool { return svcList[i].ID < svcList[j].ID })

	toList := func(m map[string]int) []facetCount {
		out := make([]facetCount, 0, len(m))
		for k, v := range m {
			out = append(out, facetCount{ID: k, Count: v})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		return out
	}

	return okResult(map[string]any{
		"ok":          true,
		"services":    svcList,
		"accounts":    toList(accounts),
		"regions":     toList(regions),
		"postures":    toList(postures),
		"pqcStatuses": toList(pqcStatuses),
	})
}

type roadmapFilters struct {
	Service string `json:"service"`
	Limit   int    `json:"limit"`
}

func (t *ToolExecutor) getRoadmap(args json.RawMessage) (json.RawMessage, error) {
	var f roadmapFilters
	if len(args) > 0 {
		if err := json.Unmarshal(args, &f); err != nil {
			return nil, fmt.Errorf("invalid get_roadmap arguments: %w", err)
		}
	}
	limit := clampLimit(f.Limit)

	items := t.corpus.Roadmap.Items
	if f.Service != "" {
		resolved, ok := t.resolveService(f.Service)
		if !ok {
			return errResult(fmt.Sprintf("no service matching %q in this scan; call list_facets to see valid services", f.Service)), nil
		}
		filtered := make([]any, 0)
		var count int
		for _, it := range items {
			if it.Service == resolved {
				count++
				if len(filtered) < limit {
					filtered = append(filtered, it)
				}
			}
		}
		return okResult(map[string]any{
			"ok":              true,
			"resolvedService": resolved,
			"totalMatched":    count,
			"items":           filtered,
		})
	}

	sample := make([]any, 0, limit)
	for i, it := range items {
		if i >= limit {
			break
		}
		sample = append(sample, it)
	}

	return okResult(map[string]any{
		"ok":           true,
		"totalMatched": len(items),
		"items":        sample,
		"byService":    t.corpus.Roadmap.ByService,
		"byAccount":    t.corpus.Roadmap.ByAccount,
	})
}

// resolveService resolves a user-supplied service string (raw scanner id, or
// a display name — exact or substring, case-insensitive) against the assets
// actually present in this scan. Returns ok=false when nothing matches, which
// callers turn into a structured refusal rather than guessing.
func (t *ToolExecutor) resolveService(input string) (string, bool) {
	if input == "" {
		return "", false
	}
	for _, a := range t.corpus.Assets {
		if a.Service == input {
			return a.Service, true
		}
	}
	lower := strings.ToLower(input)
	for _, a := range t.corpus.Assets {
		if strings.ToLower(a.DisplayName) == lower {
			return a.Service, true
		}
	}
	for _, a := range t.corpus.Assets {
		if strings.Contains(strings.ToLower(a.DisplayName), lower) {
			return a.Service, true
		}
	}
	return "", false
}

// --- action tools (validate, then propose) ---

var validFacetKeys = map[string]bool{
	"accountId": true, "region": true, "awsCategory": true,
	"cryptoFunction": true, "posture": true, "pqcStatus": true,
}

func (t *ToolExecutor) facetValueOf(a AssetView, key string) string {
	switch key {
	case "accountId":
		return a.AccountID
	case "region":
		return a.Region
	case "awsCategory":
		return a.AWSCategory
	case "cryptoFunction":
		return a.CryptoFunction
	case "posture":
		return a.Posture
	case "pqcStatus":
		return a.PQCStatus
	default:
		return ""
	}
}

// facetValueSet builds, in one pass over the corpus, the set of values
// actually present for each of the six known facet keys — used to validate a
// whole ui_filter_assets token list in O(assets + tokens) rather than
// rescanning the corpus once per token.
func (t *ToolExecutor) facetValueSet() map[string]map[string]bool {
	out := map[string]map[string]bool{
		"accountId": {}, "region": {}, "awsCategory": {}, "cryptoFunction": {}, "posture": {}, "pqcStatus": {},
	}
	for _, a := range t.corpus.Assets {
		for key := range out {
			out[key][t.facetValueOf(a, key)] = true
		}
	}
	return out
}

func (t *ToolExecutor) uiFilterAssets(args json.RawMessage) (json.RawMessage, error) {
	var req struct {
		Operation string `json:"operation"`
		Tokens    []struct {
			PropertyKey string `json:"propertyKey"`
			Operator    string `json:"operator"`
			Value       string `json:"value"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return nil, fmt.Errorf("invalid ui_filter_assets arguments: %w", err)
	}
	if len(req.Tokens) == 0 {
		return errResult("ui_filter_assets requires at least one token"), nil
	}
	op := req.Operation
	if op != "and" && op != "or" {
		op = "and"
	}

	values := t.facetValueSet()
	tokens := make([]PropertyFilterToken, 0, len(req.Tokens))
	for _, tk := range req.Tokens {
		if !validFacetKeys[tk.PropertyKey] {
			return errResult(fmt.Sprintf("unknown propertyKey %q; valid keys are accountId, region, awsCategory, cryptoFunction, posture, pqcStatus", tk.PropertyKey)), nil
		}
		if tk.Operator != "=" && tk.Operator != "!=" {
			return errResult(fmt.Sprintf("unsupported operator %q; use = or !=", tk.Operator)), nil
		}
		if !values[tk.PropertyKey][tk.Value] {
			return errResult(fmt.Sprintf("no asset has %s = %q in this scan; call list_facets to see valid values", tk.PropertyKey, tk.Value)), nil
		}
		tokens = append(tokens, PropertyFilterToken{PropertyKey: tk.PropertyKey, Operator: tk.Operator, Value: tk.Value})
	}

	matchCount := 0
	for _, a := range t.corpus.Assets {
		if matchesTokens(t, a, tokens, op) {
			matchCount++
		}
	}

	t.pendingAction = &Action{Type: "filter_assets", Query: &PropertyFilterQuery{Tokens: tokens, Operation: op}}
	return okResult(map[string]any{"ok": true, "matchCount": matchCount})
}

func matchesTokens(t *ToolExecutor, a AssetView, tokens []PropertyFilterToken, operation string) bool {
	if operation == "or" {
		for _, tk := range tokens {
			v := t.facetValueOf(a, tk.PropertyKey)
			if (tk.Operator == "=" && v == tk.Value) || (tk.Operator == "!=" && v != tk.Value) {
				return true
			}
		}
		return false
	}
	for _, tk := range tokens {
		v := t.facetValueOf(a, tk.PropertyKey)
		if tk.Operator == "=" && v != tk.Value {
			return false
		}
		if tk.Operator == "!=" && v == tk.Value {
			return false
		}
	}
	return true
}

func (t *ToolExecutor) uiSelectAsset(args json.RawMessage) (json.RawMessage, error) {
	var req struct {
		BomRef string `json:"bomRef"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return nil, fmt.Errorf("invalid ui_select_asset arguments: %w", err)
	}
	if req.BomRef == "" {
		return errResult("bomRef is required"), nil
	}
	for _, a := range t.corpus.Assets {
		if a.BomRef == req.BomRef {
			t.pendingAction = &Action{Type: "select_asset", AssetBomRef: req.BomRef}
			return okResult(map[string]any{"ok": true, "asset": a})
		}
	}
	return errResult(fmt.Sprintf("no asset with bomRef %q in this scan", req.BomRef)), nil
}

func (t *ToolExecutor) uiViewRoadmap(args json.RawMessage) (json.RawMessage, error) {
	var req struct {
		Service string `json:"service"`
	}
	if len(args) > 0 {
		if err := json.Unmarshal(args, &req); err != nil {
			return nil, fmt.Errorf("invalid ui_view_roadmap arguments: %w", err)
		}
	}
	if req.Service == "" {
		t.pendingAction = &Action{Type: "view_roadmap"}
		return okResult(map[string]any{"ok": true})
	}
	resolved, ok := t.resolveService(req.Service)
	if !ok {
		return errResult(fmt.Sprintf("no service matching %q in this scan; call list_facets to see valid services", req.Service)), nil
	}
	t.pendingAction = &Action{Type: "view_roadmap", Service: resolved}
	return okResult(map[string]any{"ok": true, "resolvedService": resolved})
}
