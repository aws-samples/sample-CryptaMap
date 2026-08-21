// Floating chat panel for the AI Agent. Deliberately NOT the per-page
// SplitPanel (layout/SplitPanelContext.tsx) — that slot is already used by
// AssetsView/RoadmapView for per-asset detail, and the agent needs to work
// identically from every route, including ones with no split panel at all. A
// small fixed-position overlay, rendered as a sibling of <AppLayout> in
// AppShell.tsx, keeps it fully independent of the page underneath.
import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Box from '@cloudscape-design/components/box';
import Button from '@cloudscape-design/components/button';
import Container from '@cloudscape-design/components/container';
import Header from '@cloudscape-design/components/header';
import SpaceBetween from '@cloudscape-design/components/space-between';
import Textarea from '@cloudscape-design/components/textarea';
import Spinner from '@cloudscape-design/components/spinner';
import Alert from '@cloudscape-design/components/alert';
import { sendAgentMessage } from '../services/agentApi';
import type { ChatTurn } from '../services/agentApi';
import { dispatchAgentAction } from '../lib/agentActions';

interface Props {
  open: boolean;
  onClose: () => void;
  /**
   * Whether the backend has GEMINI_API_KEY configured (from GET
   * /api/agent/status, checked by AppShell on load). Cloudscape's
   * TopNavigation utility buttons have no built-in disabled/tooltip affordance,
   * so rather than a disabled launcher we surface this proactively INSIDE the
   * panel the moment it opens — before the user wastes a round trip typing a
   * question that would just come back as the same "not configured" error.
   */
  agentEnabled: boolean;
}

const EXAMPLE_PROMPTS = [
  'How many assets are quantum-vulnerable?',
  'Which assets use RSA?',
  'Take me to the migration roadmap for KMS.',
];

export default function AgentChatPanel({ open, onClose, agentEnabled }: Props) {
  const navigate = useNavigate();
  const [messages, setMessages] = useState<ChatTurn[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (open) bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, busy, open]);

  if (!open) return null;

  const send = async (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || busy) return;
    setError(null);
    const priorHistory = messages;
    setMessages((prev) => [...prev, { role: 'user', text: trimmed }]);
    setInput('');
    setBusy(true);
    const res = await sendAgentMessage(trimmed, priorHistory);
    setBusy(false);
    if (res.error) {
      // Surfaced inline (not thrown) so a Gemini failure, a disabled agent, or
      // a network hiccup never breaks the chat panel itself — the required
      // "sensible failure handling" edge case, visible right where the user
      // is looking.
      setError(res.error);
      return;
    }
    setMessages((prev) => [...prev, { role: 'assistant', text: res.reply }]);
    if (res.action) {
      dispatchAgentAction(res.action, navigate);
    }
  };

  return (
    <div
      role="complementary"
      aria-label="AI Agent chat"
      style={{
        position: 'fixed',
        right: 24,
        bottom: 24,
        width: 400,
        maxWidth: 'calc(100vw - 48px)',
        maxHeight: '70vh',
        zIndex: 2000,
        boxShadow: '0 4px 24px rgba(0, 0, 0, 0.3)',
        borderRadius: 8,
      }}
    >
      <Container
        header={
          <Header
            variant="h3"
            actions={
              <Button iconName="close" variant="icon" ariaLabel="Close AI Agent" onClick={onClose} />
            }
          >
            Ask AI
          </Header>
        }
      >
        <SpaceBetween size="s">
          {!agentEnabled && (
            <Alert type="warning" header="AI Agent not configured">
              Set the <code>GEMINI_API_KEY</code> environment variable and restart <code>cryptamap serve</code> to
              enable it.
            </Alert>
          )}
          <div style={{ maxHeight: '42vh', overflowY: 'auto' }}>
            <SpaceBetween size="s">
              {messages.length === 0 && (
                <Box color="text-body-secondary" fontSize="body-s">
                  <Box padding={{ bottom: 'xs' }}>
                    Ask about your crypto inventory — grounded in this scan's actual data, e.g.:
                  </Box>
                  <SpaceBetween size="xxs">
                    {EXAMPLE_PROMPTS.map((ex) => (
                      <Button key={ex} variant="inline-link" onClick={() => send(ex)}>
                        {ex}
                      </Button>
                    ))}
                  </SpaceBetween>
                </Box>
              )}
              {messages.map((m, i) => (
                <Box key={i} padding={{ vertical: 'xs' }}>
                  <Box variant="span" fontWeight="bold">
                    {m.role === 'user' ? 'You' : 'Agent'}:
                  </Box>{' '}
                  <Box variant="span">{m.text}</Box>
                </Box>
              ))}
              {busy && (
                <Box padding={{ vertical: 'xs' }}>
                  <Spinner size="normal" /> Thinking…
                </Box>
              )}
              {error && (
                <Alert type="error" header="Agent unavailable">
                  {error}
                </Alert>
              )}
              <div ref={bottomRef} />
            </SpaceBetween>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end' }}>
            <div style={{ flexGrow: 1 }}>
              <Textarea
                value={input}
                onChange={({ detail }) => setInput(detail.value)}
                placeholder="Ask about assets, findings, or the roadmap…"
                rows={2}
                disabled={busy || !agentEnabled}
              />
            </div>
            <Button
              variant="primary"
              onClick={() => send(input)}
              disabled={busy || !agentEnabled || !input.trim()}
            >
              Send
            </Button>
          </div>
        </SpaceBetween>
      </Container>
    </div>
  );
}
