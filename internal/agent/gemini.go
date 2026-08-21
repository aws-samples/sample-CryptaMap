package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	// defaultGeminiModel is a stable alias for the latest free-tier-eligible
	// Gemini Flash-Lite model, so this adapter does not need a code change
	// when Google ships a new Flash-Lite generation. Chosen over the plain
	// "gemini-flash-latest" alias after live testing: the heavier
	// thinking-capable Flash models (flash-latest and pinned 3.x releases)
	// hit real free-tier 503 "high demand" responses and, on newer releases,
	// a very tight daily request quota (as low as 20/day observed), while
	// Flash-Lite answered the same queries correctly in 1-3s with no rate
	// limiting during equivalent testing. Override with GEMINI_MODEL if a
	// pinned model name is preferred (e.g. the alias is unavailable for a
	// given account/region) or a heavier model's reasoning is worth the
	// latency/quota tradeoff for a specific deployment.
	defaultGeminiModel = "gemini-flash-lite-latest"
	geminiAPIBase      = "https://generativelanguage.googleapis.com/v1beta/models"
)

// GeminiProvider is a Provider backed by the Google Gemini API, called via a
// plain net/http REST request rather than a generated SDK — consistent with
// the rest of this repo's dependency-light internal/ packages, and it avoids
// pulling a large client library in for one endpoint.
//
// The API key never leaves this process: it is supplied by
// cmd/cryptamap/serve.go from the server-side GEMINI_API_KEY environment
// variable and is used only in the outbound request to Google here. The
// browser never sees it.
type GeminiProvider struct {
	apiKey string
	model  string
	client *http.Client
}

// NewGeminiProvider builds a Gemini-backed Provider for apiKey.
func NewGeminiProvider(apiKey string) *GeminiProvider {
	model := os.Getenv("GEMINI_MODEL")
	if model == "" {
		model = defaultGeminiModel
	}
	return &GeminiProvider{
		apiKey: apiKey,
		model:  model,
		// Thinking-capable Gemini models (3.x+) can take noticeably longer than
		// a plain chat completion before the first token, especially on a tool
		// -calling turn where the model reasons about which function to call.
		// 45s gives that room without letting a truly stuck request hang the
		// server indefinitely (bounded again by requestTimeout in handler.go,
		// which covers the whole multi-turn tool-call loop).
		client: &http.Client{Timeout: 45 * time.Second},
	}
}

// --- Gemini v1beta generateContent wire types (only the fields this adapter
// uses; see https://ai.google.dev/api/generate-content). ---

type geminiPart struct {
	Text             string                `json:"text,omitempty"`
	FunctionCall     *geminiFunctionCall   `json:"functionCall,omitempty"`
	FunctionResponse *geminiFunctionResult `json:"functionResponse,omitempty"`
	// ThoughtSignature is Gemini 3+'s opaque reasoning-state token attached to
	// (typically the first) functionCall part in a turn. It MUST be echoed
	// back verbatim on the exact same part when that functionCall is replayed
	// in a later request's history, or the API rejects the request with a 400
	// ("Function call is missing a thought_signature"). See
	// https://ai.google.dev/gemini-api/docs/generate-content/thought-signatures.
	ThoughtSignature string `json:"thoughtSignature,omitempty"`
}

type geminiFunctionCall struct {
	ID   string          `json:"id,omitempty"`
	Name string          `json:"name"`
	Args json.RawMessage `json:"args,omitempty"`
}

type geminiFunctionResult struct {
	ID       string          `json:"id,omitempty"`
	Name     string          `json:"name"`
	Response json.RawMessage `json:"response"`
}

type geminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []geminiPart `json:"parts"`
}

type geminiFunctionDecl struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

type geminiTool struct {
	FunctionDeclarations []geminiFunctionDecl `json:"functionDeclarations"`
}

type geminiRequest struct {
	Contents          []geminiContent `json:"contents"`
	Tools             []geminiTool    `json:"tools,omitempty"`
	SystemInstruction *geminiContent  `json:"systemInstruction,omitempty"`
}

type geminiCandidate struct {
	Content      geminiContent `json:"content"`
	FinishReason string        `json:"finishReason,omitempty"`
}

type geminiResponse struct {
	Candidates []geminiCandidate `json:"candidates"`
	Error      *geminiError      `json:"error,omitempty"`
}

type geminiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

// Chat implements Provider.
func (g *GeminiProvider) Chat(ctx context.Context, system string, history []Message, tools []ToolSpec) (Response, error) {
	req := geminiRequest{Contents: toGeminiContents(history)}
	if system != "" {
		req.SystemInstruction = &geminiContent{Parts: []geminiPart{{Text: system}}}
	}
	if len(tools) > 0 {
		decls := make([]geminiFunctionDecl, 0, len(tools))
		for _, t := range tools {
			params := t.Parameters
			if len(params) == 0 {
				params = json.RawMessage(`{"type":"object","properties":{}}`)
			}
			decls = append(decls, geminiFunctionDecl{Name: t.Name, Description: t.Description, Parameters: params})
		}
		req.Tools = []geminiTool{{FunctionDeclarations: decls}}
	}

	body, err := json.Marshal(req)
	if err != nil {
		return Response{}, fmt.Errorf("gemini: encode request: %w", err)
	}

	url := fmt.Sprintf("%s/%s:generateContent?key=%s", geminiAPIBase, g.model, g.apiKey)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("gemini: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := g.client.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("gemini: request failed: %w", err)
	}
	defer httpResp.Body.Close()

	// Cap the read: a misbehaving/compromised endpoint should not be able to
	// exhaust memory via an unbounded response body.
	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, 4<<20))
	if err != nil {
		return Response{}, fmt.Errorf("gemini: read response: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		var errBody geminiResponse
		if json.Unmarshal(respBody, &errBody) == nil && errBody.Error != nil {
			return Response{}, fmt.Errorf("gemini: API error (%d %s): %s", httpResp.StatusCode, errBody.Error.Status, errBody.Error.Message)
		}
		return Response{}, fmt.Errorf("gemini: API returned status %d", httpResp.StatusCode)
	}

	var gr geminiResponse
	if err := json.Unmarshal(respBody, &gr); err != nil {
		return Response{}, fmt.Errorf("gemini: decode response: %w", err)
	}
	if len(gr.Candidates) == 0 {
		return Response{}, fmt.Errorf("gemini: no candidates in response (the request may have been blocked)")
	}

	cand := gr.Candidates[0]
	var out Response
	for i, part := range cand.Content.Parts {
		switch {
		case part.FunctionCall != nil:
			id := part.FunctionCall.ID
			if id == "" {
				id = fmt.Sprintf("call-%d", i)
			}
			args := part.FunctionCall.Args
			if len(args) == 0 {
				args = json.RawMessage(`{}`)
			}
			out.ToolCalls = append(out.ToolCalls, ToolCall{ID: id, Name: part.FunctionCall.Name, Args: args, Meta: part.ThoughtSignature})
		case part.Text != "":
			out.Text += part.Text
		}
	}
	return out, nil
}

// toGeminiContents maps the provider-agnostic Message history onto Gemini's
// contents[] wire shape. Consecutive RoleTool messages (all the tool results
// answering one model turn's tool calls) are grouped into a single "user"
// content carrying one functionResponse part per result, matching how Gemini
// expects a multi-call turn to be answered.
func toGeminiContents(history []Message) []geminiContent {
	var out []geminiContent
	i := 0
	for i < len(history) {
		m := history[i]
		switch m.Role {
		case RoleModel:
			if len(m.ToolCalls) > 0 {
				parts := make([]geminiPart, 0, len(m.ToolCalls)+1)
				if m.Text != "" {
					// Some models emit a text aside in the same turn as a
					// functionCall (e.g. "let me check that..."); preserve it
					// alongside the calls rather than dropping it.
					parts = append(parts, geminiPart{Text: m.Text})
				}
				for _, c := range m.ToolCalls {
					parts = append(parts, geminiPart{
						FunctionCall:     &geminiFunctionCall{ID: c.ID, Name: c.Name, Args: c.Args},
						ThoughtSignature: c.Meta,
					})
				}
				out = append(out, geminiContent{Role: "model", Parts: parts})
			} else {
				out = append(out, geminiContent{Role: "model", Parts: []geminiPart{{Text: m.Text}}})
			}
			i++
		case RoleTool:
			var parts []geminiPart
			for i < len(history) && history[i].Role == RoleTool {
				t := history[i]
				result := t.ToolResult
				if len(result) == 0 {
					result = json.RawMessage(`{}`)
				}
				parts = append(parts, geminiPart{FunctionResponse: &geminiFunctionResult{ID: t.ToolCallID, Name: t.ToolName, Response: result}})
				i++
			}
			out = append(out, geminiContent{Role: "user", Parts: parts})
		default: // RoleUser
			out = append(out, geminiContent{Role: "user", Parts: []geminiPart{{Text: m.Text}}})
			i++
		}
	}
	return out
}
