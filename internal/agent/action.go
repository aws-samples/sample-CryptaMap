package agent

// Action is an optional, deterministic in-app action the frontend executes
// after a chat turn. Only one is honored per turn — the last successful ui_*
// tool call in that turn wins (see ToolExecutor.pendingAction) — and the
// frontend maps it 1:1 onto the dashboard's EXISTING navigation contracts
// (dashboard/src/lib/agentActions.ts), so no new client-side state machine is
// needed and the agent can never drive the UI into a state the rest of the
// app doesn't already support.
type Action struct {
	Type        string               `json:"type"` // "filter_assets" | "select_asset" | "view_roadmap"
	Query       *PropertyFilterQuery `json:"query,omitempty"`
	AssetBomRef string               `json:"assetBomRef,omitempty"`
	Service     string               `json:"service,omitempty"`
}

// PropertyFilterQuery mirrors, field for field, the shape
// dashboard/src/pages/AssetsView.tsx's parseQueryParam expects from the
// ?q= URL parameter (Cloudscape's PropertyFilterProps.Query). Keeping this
// struct in lockstep with that TypeScript shape is what lets ui_filter_assets
// produce a query the existing Assets page already knows how to render —
// no new frontend filtering logic required.
type PropertyFilterQuery struct {
	Tokens    []PropertyFilterToken `json:"tokens"`
	Operation string                `json:"operation"` // "and" | "or"
}

// PropertyFilterToken is one filter clause: propertyKey OPERATOR value.
type PropertyFilterToken struct {
	PropertyKey string `json:"propertyKey"`
	Operator    string `json:"operator"` // "=" | "!="
	Value       string `json:"value"`
}
