// Client for the local AI Agent endpoints served by `cryptamap serve`
// (see cmd/cryptamap/serve.go's mountAgentRoutes / internal/agent). Mirrors
// the fetch-and-fail-closed style of services/api.ts: every function here
// resolves to a typed value or a typed { error } rather than throwing, so a
// disabled agent, an offline server, or a malformed response degrades the
// chat panel gracefully instead of crashing it.
//
// The request/response wire shapes (ChatTurn, AgentAction, AgentChatResponse,
// PropertyFilterQuery/Token) are GENERATED from the Go structs that actually
// produce them (internal/agent/{handler,action}.go via cmd/gen-ts) rather than
// hand-mirrored here, so this contract can't silently drift from the backend.

export type {
  ChatTurn,
  AgentAction,
  AgentChatResponse,
  PropertyFilterQuery,
  PropertyFilterToken,
} from '../types';

import type { AgentChatResponse, ChatTurn } from '../types';

export interface AgentStatus {
  enabled: boolean;
}

/** Whether the AI Agent is configured server-side (GEMINI_API_KEY set). */
export async function fetchAgentStatus(): Promise<AgentStatus> {
  try {
    const res = await fetch('/api/agent/status');
    if (!res.ok) return { enabled: false };
    return (await res.json()) as AgentStatus;
  } catch {
    return { enabled: false };
  }
}

/**
 * Send one chat message (with prior-turn history for context) to the agent.
 * Always resolves — network failures, a disabled agent, and malformed
 * responses all come back as { reply: '', error } rather than a thrown
 * exception, so callers can render the error inline without a try/catch.
 */
export async function sendAgentMessage(
  message: string,
  history: ChatTurn[],
): Promise<AgentChatResponse> {
  try {
    const res = await fetch('/api/agent/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message, history }),
    });
    const body = await res.json().catch(() => ({}) as Partial<AgentChatResponse>);
    if (!res.ok) {
      return { reply: '', error: body.error ?? `Agent request failed (${res.status}).` };
    }
    return {
      reply: body.reply ?? '',
      action: body.action,
      error: body.error,
    };
  } catch {
    return { reply: '', error: 'Could not reach the local CryptaMap server.' };
  }
}
