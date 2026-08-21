package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeProvider is a Provider stub whose Chat implementation calls one ui_*
// action tool (selecting a different, caller-chosen bomRef per goroutine)
// then returns a final text reply. It lets handler_test.go fire real
// concurrent HTTP requests through NewChatHandler without any network/LLM
// dependency.
type fakeProvider struct{}

func (fakeProvider) Chat(_ context.Context, _ string, history []Message, _ []ToolSpec) (Response, error) {
	// First call in a turn: history ends in a user message (the request) ->
	// call ui_select_asset for the bomRef embedded in that message's text.
	last := history[len(history)-1]
	if last.Role == RoleUser {
		bomRef := strings.TrimPrefix(last.Text, "select ")
		args, _ := json.Marshal(map[string]string{"bomRef": bomRef})
		return Response{ToolCalls: []ToolCall{{ID: "1", Name: "ui_select_asset", Args: args}}}, nil
	}
	// Second call: the tool result is in history -> produce the final reply.
	return Response{Text: "done"}, nil
}

// TestConcurrentChatRequestsDoNotShareAction is a regression test for a real
// data race: NewChatHandler used to be built around one ToolExecutor shared
// for the server's whole lifetime, so ToolExecutor.pendingAction (a plain,
// unsynchronized field) could leak one concurrent request's action into
// another's response. NewChatHandler now takes the read-only *Corpus and
// builds a fresh ToolExecutor per request; this test fires many concurrent
// requests, each selecting a DIFFERENT asset, and asserts every response's
// action matches the asset THAT request asked for. Run with -race to also
// catch the underlying race directly.
func TestConcurrentChatRequestsDoNotShareAction(t *testing.T) {
	const n = 20
	assets := make([]AssetView, n)
	for i := range assets {
		assets[i] = AssetView{BomRef: fmt.Sprintf("crypto-%d", i), DisplayName: "Test", Service: "s3", Posture: "unknown"}
	}
	corpus := &Corpus{Assets: assets}

	handler := NewChatHandler(fakeProvider{}, corpus)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			bomRef := fmt.Sprintf("crypto-%d", i)
			body, _ := json.Marshal(ChatRequest{Message: "select " + bomRef})
			resp, err := http.Post(srv.URL, "application/json", strings.NewReader(string(body)))
			if err != nil {
				errs <- fmt.Errorf("request %d: %w", i, err)
				return
			}
			defer resp.Body.Close()
			var cr ChatResponse
			if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
				errs <- fmt.Errorf("request %d: decode: %w", i, err)
				return
			}
			if cr.Action == nil || cr.Action.AssetBomRef != bomRef {
				errs <- fmt.Errorf("request %d: got action %+v, want select_asset %s", i, cr.Action, bomRef)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
