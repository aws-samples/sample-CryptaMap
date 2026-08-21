package agent

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

// maxHistoryTurns bounds the prior-turn history accepted from a request, so a
// crafted/looping client can't grow one request into an unbounded prompt.
const maxHistoryTurns = 20

// maxRequestBytes bounds the raw POST body size (message + history), so a
// single oversized request can't be decoded fully into memory and forwarded
// to the provider on nothing but the 10s server ReadTimeout as a backstop.
// Generous for real chat use — 20 turns of ordinary conversational text is a
// small fraction of this.
const maxRequestBytes = 64 * 1024

// requestTimeout bounds how long one /api/agent/chat request may run — the
// whole multi-turn tool-call loop, not just one provider call — so a
// slow/stuck provider cannot hang the local server past a reasonable wait.
// Generous enough for a thinking-capable model to take a few tool-call turns
// (each up to the provider's own per-call timeout, see gemini.go) inside one
// user-facing request.
const requestTimeout = 90 * time.Second

// ChatTurn is one prior turn in the request body's history array.
type ChatTurn struct {
	Role string `json:"role"` // "user" | "assistant"
	Text string `json:"text"`
}

// ChatRequest is the POST /api/agent/chat request body.
type ChatRequest struct {
	Message string     `json:"message"`
	History []ChatTurn `json:"history"`
}

// ChatResponse is the POST /api/agent/chat response body. Action is present
// only when the model successfully invoked a ui_* tool during this turn.
// Error is present only on failure; Reply/Action are the zero value in that
// case.
type ChatResponse struct {
	Reply  string  `json:"reply"`
	Action *Action `json:"action,omitempty"`
	Error  string  `json:"error,omitempty"`
}

// NewChatHandler builds the POST /api/agent/chat handler for a configured
// provider over corpus. A fresh ToolExecutor is built for EACH request rather
// than shared across the handler's lifetime: ToolExecutor.pendingAction is a
// plain, unsynchronized field, and cryptamap serve's http.Server handles
// requests concurrently — sharing one executor would let two simultaneous
// chats race on it (one request could see, or clobber, another's action).
// Corpus itself is safe to share: it is read-only after LoadCorpus/
// LoadCorpusFS returns.
func NewChatHandler(p Provider, corpus *Corpus) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, ChatResponse{Error: "POST only"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
		var req ChatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, ChatResponse{Error: "malformed or oversized request body"})
			return
		}
		if strings.TrimSpace(req.Message) == "" {
			writeJSON(w, http.StatusBadRequest, ChatResponse{Error: "message is required"})
			return
		}

		history := toMessages(req.History, req.Message)
		ex := NewToolExecutor(corpus)

		ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
		defer cancel()

		reply, action, err := Run(ctx, p, ex, history)
		if err != nil {
			// Never leak the raw provider error (which may echo request
			// internals) to the browser; log it locally and return a stable,
			// friendly message instead. This is the "Gemini API error/timeout"
			// edge case: the server stays up and the chat surfaces a clear
			// failure rather than hanging or crashing.
			log.Printf("cryptamap: agent chat error: %v", err)
			writeJSON(w, http.StatusBadGateway, ChatResponse{Error: "the AI agent is temporarily unavailable — please try again"})
			return
		}
		writeJSON(w, http.StatusOK, ChatResponse{Reply: reply, Action: action})
	}
}

// toMessages converts the request's flat prior-turn history plus the new user
// message into the Provider message list. History is capped to the most
// recent maxHistoryTurns to bound request size.
func toMessages(history []ChatTurn, newMessage string) []Message {
	if len(history) > maxHistoryTurns {
		history = history[len(history)-maxHistoryTurns:]
	}
	msgs := make([]Message, 0, len(history)+1)
	for _, h := range history {
		role := RoleUser
		if h.Role == "assistant" {
			role = RoleModel
		}
		msgs = append(msgs, Message{Role: role, Text: h.Text})
	}
	msgs = append(msgs, Message{Role: RoleUser, Text: newMessage})
	return msgs
}

// DisabledHandler answers /api/agent/chat when the agent is not configured
// (no GEMINI_API_KEY, or the corpus failed to load) with a clear, structured
// 503 rather than a bare 404 the frontend would have to guess about.
func DisabledHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusServiceUnavailable, ChatResponse{
		Error: "AI agent not configured: set GEMINI_API_KEY and restart `cryptamap serve`",
	})
}

// StatusHandler serves GET /api/agent/status so the frontend can disable its
// chat launcher proactively instead of only discovering the agent is
// unavailable on first send.
func StatusHandler(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"enabled": enabled})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
