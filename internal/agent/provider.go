// Package agent implements the CryptaMap dashboard's AI Agent: a small,
// tool-calling chat backend that answers questions and drives in-app actions
// strictly from the current scan's data (never inventing assets, counts, or
// findings). It is mounted as a local, loopback-only HTTP endpoint by
// cmd/cryptamap/serve.go and never runs with network access beyond the one
// configured LLM API.
package agent

import (
	"context"
	"encoding/json"
)

// Role identifies who produced one Message in a conversation.
type Role string

const (
	RoleUser  Role = "user"  // a human turn, or (for RoleTool-adjacent bookkeeping) a tool-result turn
	RoleModel Role = "model" // a model turn: Text, or ToolCalls if it chose to call tools instead
	RoleTool  Role = "tool"  // one tool's result, relayed back to the model
)

// Message is one turn in a conversation passed to a Provider. Which fields are
// meaningful depends on Role:
//   - RoleUser:  Text is the human's message.
//   - RoleModel: Text is the model's reply, OR ToolCalls is set instead when
//     the model chose to call tools rather than reply directly.
//   - RoleTool:  ToolName/ToolCallID/ToolResult carry one tool's result back to
//     the model, answering one of its ToolCalls.
type Message struct {
	Role       Role
	Text       string
	ToolCalls  []ToolCall
	ToolName   string
	ToolCallID string
	ToolResult json.RawMessage
}

// ToolCall is one function call the model requested.
type ToolCall struct {
	ID   string
	Name string
	Args json.RawMessage
	// Meta is opaque, provider-specific passthrough data associated with this
	// call that MUST be echoed back verbatim on the next turn (e.g. Gemini's
	// "thoughtSignature", which Gemini 3+ models require on a replayed
	// functionCall or the request is rejected). Empty for providers that
	// don't need this; orchestrate.go never inspects it, just carries it.
	Meta string
}

// ToolSpec describes one callable tool to the model: its name, a description
// the model uses to decide when to call it, and a JSON Schema for its
// arguments.
type ToolSpec struct {
	Name        string
	Description string
	Parameters  json.RawMessage
}

// Response is one model turn: either a final Text reply (ToolCalls empty) or a
// request to call one or more tools (Text typically empty, ToolCalls set).
type Response struct {
	Text      string
	ToolCalls []ToolCall
}

// Provider abstracts one LLM's chat/tool-calling API so the orchestration loop
// (orchestrate.go) and the rest of this package do not depend on any single
// vendor. Only a Gemini-backed implementation exists today (gemini.go); adding
// a second provider is a new file implementing this interface, with no change
// to tools.go, orchestrate.go, or handler.go.
type Provider interface {
	// Chat sends the full conversation so far (system prompt + history) plus
	// the available tools, and returns the model's next turn.
	Chat(ctx context.Context, system string, history []Message, tools []ToolSpec) (Response, error)
}
