package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

// scriptedProvider replays a fixed sequence of Response turns, one per Chat
// call, so orchestrate.Run's multi-turn mechanics (history threading, tool
// execution, final-reply/action assembly, maxTurns handling) can be tested
// deterministically without any network call or real LLM. It does NOT test
// whether a real model chooses the right tool for a given phrasing — that is
// inherently only verifiable live (see SUBMISSION.md's Testing/validation
// section for that evidence) — only that Run drives whatever the provider
// returns correctly.
type scriptedProvider struct {
	steps []Response
	turn  int
}

func (s *scriptedProvider) Chat(_ context.Context, _ string, _ []Message, _ []ToolSpec) (Response, error) {
	if s.turn >= len(s.steps) {
		return Response{}, fmt.Errorf("scriptedProvider: no scripted response for turn %d", s.turn)
	}
	r := s.steps[s.turn]
	s.turn++
	return r, nil
}

func toolCallStep(id, name string, args string) Response {
	return Response{ToolCalls: []ToolCall{{ID: id, Name: name, Args: json.RawMessage(args)}}}
}

// TestRunGroundedQALoop exercises the shape of a real grounded Q&A turn: the
// model calls a couple of read tools before answering, and Run must thread
// their results back correctly and return the model's final text with no
// action (a pure question implies no UI change).
func TestRunGroundedQALoop(t *testing.T) {
	ex := NewToolExecutor(testCorpus())
	provider := &scriptedProvider{steps: []Response{
		toolCallStep("1", "list_facets", `{}`),
		toolCallStep("2", "list_assets", `{"posture":"legacy-tls"}`),
		{Text: "There is 1 asset on legacy TLS in this scan."},
	}}

	reply, action, err := Run(context.Background(), provider, ex, []Message{{Role: RoleUser, Text: "how many legacy tls assets?"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if reply != "There is 1 asset on legacy TLS in this scan." {
		t.Errorf("reply = %q", reply)
	}
	if action != nil {
		t.Errorf("action = %+v, want nil for a pure Q&A loop", action)
	}
}

// TestRunActionLoop exercises the shape of a real "show me / open X" turn:
// the model calls one ui_* tool then gives a final acknowledgement, and Run
// must surface both the reply AND the action the tool validated.
func TestRunActionLoop(t *testing.T) {
	ex := NewToolExecutor(testCorpus())
	provider := &scriptedProvider{steps: []Response{
		toolCallStep("1", "ui_select_asset", `{"bomRef":"crypto-s3-1"}`),
		{Text: "Opened the details for crypto-s3-1."},
	}}

	reply, action, err := Run(context.Background(), provider, ex, []Message{{Role: RoleUser, Text: "open crypto-s3-1"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if reply != "Opened the details for crypto-s3-1." {
		t.Errorf("reply = %q", reply)
	}
	if action == nil || action.Type != "select_asset" || action.AssetBomRef != "crypto-s3-1" {
		t.Errorf("action = %+v, want select_asset crypto-s3-1", action)
	}
}

// TestRunToolFailureIsRelayedNotFatal exercises the "malformed/invalid
// output" edge case end to end through Run: a tool call that fails
// validation must come back as a normal tool result the model can react to
// (here, it apologizes) — not abort the request.
func TestRunToolFailureIsRelayedNotFatal(t *testing.T) {
	ex := NewToolExecutor(testCorpus())
	provider := &scriptedProvider{steps: []Response{
		toolCallStep("1", "ui_select_asset", `{"bomRef":"does-not-exist"}`),
		{Text: "Sorry, I couldn't find that asset in this scan."},
	}}

	reply, action, err := Run(context.Background(), provider, ex, []Message{{Role: RoleUser, Text: "open does-not-exist"}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if reply == "" {
		t.Error("expected the model's apology text, got empty reply")
	}
	if action != nil {
		t.Errorf("action = %+v, want nil — the tool call was rejected, nothing should be proposed", action)
	}
}

// TestRunMaxTurnsWithoutFinalReturnsError exercises the runaway-loop guard: a
// model that keeps calling read tools and never finalizes must produce an
// error after maxTurns, not hang forever.
func TestRunMaxTurnsWithoutFinalReturnsError(t *testing.T) {
	ex := NewToolExecutor(testCorpus())
	steps := make([]Response, 0, maxTurns)
	for i := 0; i < maxTurns; i++ {
		steps = append(steps, toolCallStep(fmt.Sprintf("c%d", i), "list_facets", `{}`))
	}
	provider := &scriptedProvider{steps: steps}

	_, action, err := Run(context.Background(), provider, ex, []Message{{Role: RoleUser, Text: "x"}})
	if err == nil {
		t.Fatal("expected an error when the model never finalizes within maxTurns")
	}
	if action != nil {
		t.Errorf("action = %+v, want nil", action)
	}
}

// TestRunMaxTurnsWithPendingActionReturnsActionNotError is a regression test
// for a real code-review finding: if a ui_* tool already validated and set an
// action on an earlier turn, hitting maxTurns without a final reply used to
// discard that action behind a hard error. Run must now surface the
// already-completed action with a generic acknowledgement instead.
func TestRunMaxTurnsWithPendingActionReturnsActionNotError(t *testing.T) {
	ex := NewToolExecutor(testCorpus())
	steps := []Response{toolCallStep("1", "ui_select_asset", `{"bomRef":"crypto-s3-1"}`)}
	for i := 1; i < maxTurns; i++ {
		steps = append(steps, toolCallStep(fmt.Sprintf("c%d", i), "list_facets", `{}`))
	}
	provider := &scriptedProvider{steps: steps}

	reply, action, err := Run(context.Background(), provider, ex, []Message{{Role: RoleUser, Text: "open crypto-s3-1"}})
	if err != nil {
		t.Fatalf("Run: %v, want the pending action surfaced instead of an error", err)
	}
	if reply == "" {
		t.Error("expected a non-empty acknowledgement reply")
	}
	if action == nil || action.AssetBomRef != "crypto-s3-1" {
		t.Errorf("action = %+v, want select_asset crypto-s3-1", action)
	}
}
