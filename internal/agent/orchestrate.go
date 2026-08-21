package agent

import (
	"context"
	"encoding/json"
	"fmt"
)

// maxTurns caps the tool-call loop so a model that keeps calling tools
// without ever producing a final answer cannot hang a request indefinitely.
const maxTurns = 5

// systemPrompt grounds every conversation: answer only from tool results,
// confirm any service/account/region name via list_facets before relying on
// it, use the ui_* tools to perform actions instead of just describing them,
// and relay a tool failure honestly instead of pretending it succeeded. This
// is the core anti-hallucination control — everything else (validate-before-
// propose tools, capped totals) backs it up structurally, but the model still
// has to be told the rule.
const systemPrompt = `You are the CryptaMap inventory assistant, embedded in a dashboard that shows a cryptographic asset inventory and PQC migration roadmap for one AWS scan.

Rules:
- Answer ONLY using tool results from this conversation. Never state a count, asset, service, or finding you have not just retrieved via a tool call. If you have not called a tool yet, call one before answering a factual question.
- Before referring to a specific service, account, or region name, call list_facets to confirm it actually exists in this scan. If it does not, say so plainly and, only if there is an obvious close match, suggest it — never silently substitute it yourself.
- To perform an in-app action (filter the asset list, open one asset's detail, or jump to the PQC roadmap for a service), call the matching ui_* tool. Do not just describe the action in text — call the tool.
- If a ui_* tool call returns ok:false, tell the user why in one plain sentence. Never claim an action succeeded when the tool reported failure.
- Keep answers concise: lead with the number or fact, then at most one or two sentences of context.
- You only know about the AWS resources in this scan. Decline politely, without guessing, if asked about something outside that scope (other clouds, other scans, general advice unrelated to this inventory).`

// Run drives the tool-calling loop for one user turn: it asks the provider
// for a turn, executes any requested tool calls deterministically against ex,
// feeds the results back, and repeats until the model produces a final text
// reply or maxTurns is exceeded. The returned action, if any, is the last
// successful ui_* tool call made during the loop.
func Run(ctx context.Context, p Provider, ex *ToolExecutor, history []Message) (reply string, action *Action, err error) {
	ex.Reset()
	tools := ex.Specs()

	for i := 0; i < maxTurns; i++ {
		resp, err := p.Chat(ctx, systemPrompt, history, tools)
		if err != nil {
			return "", nil, fmt.Errorf("provider chat: %w", err)
		}
		if len(resp.ToolCalls) == 0 {
			return resp.Text, ex.PendingAction(), nil
		}

		// Preserve any text the model returned alongside its tool calls (e.g. a
		// "let me check..." aside some models emit in the same turn as a
		// functionCall) rather than silently dropping it — gemini.go echoes
		// this back verbatim on the next turn.
		history = append(history, Message{Role: RoleModel, Text: resp.Text, ToolCalls: resp.ToolCalls})
		for _, call := range resp.ToolCalls {
			result, execErr := ex.Execute(call.Name, call.Args)
			if execErr != nil {
				// A malformed call (bad JSON args, etc.) becomes a normal tool
				// result the model sees and can react to, not a request-aborting
				// Go error.
				result = json.RawMessage(fmt.Sprintf(`{"ok":false,"error":%q}`, execErr.Error()))
			}
			history = append(history, Message{
				Role:       RoleTool,
				ToolName:   call.Name,
				ToolCallID: call.ID,
				ToolResult: result,
			})
		}
	}
	// The model never produced a final text reply within maxTurns. If one of
	// its tool calls along the way already validated and set a UI action,
	// that action is real work the backend completed correctly — surface it
	// with a generic acknowledgement instead of discarding it behind a hard
	// error the user can't act on.
	if action := ex.PendingAction(); action != nil {
		return "Done.", action, nil
	}
	return "", nil, fmt.Errorf("tool-call loop exceeded %d turns without a final answer", maxTurns)
}
