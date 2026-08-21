// Floating chat panel for the AI Agent. Deliberately NOT the per-page
// SplitPanel (layout/SplitPanelContext.tsx) — that slot is already used by
// AssetsView/RoadmapView for per-asset detail, and the agent needs to work
// identically from every route, including ones with no split panel at all. A
// small fixed-position overlay, rendered as a sibling of <AppLayout> in
// AppShell.tsx, keeps it fully independent of the page underneath.
import { useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
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

// Minimal, dependency-free **bold** renderer for the model's markdown-flavored
// replies (Gemini reliably emits **word** for emphasis). Splits on the
// delimiter and builds plain React elements — no HTML parsing, so there is no
// injection surface — rather than pulling in a full markdown library for one
// inline style.
function renderInlineMarkdown(text: string): ReactNode[] {
  return text.split(/(\*\*[^*]+\*\*)/g).map((part, i) =>
    part.startsWith('**') && part.endsWith('**') && part.length > 4 ? (
      <strong key={i}>{part.slice(2, -2)}</strong>
    ) : (
      <span key={i}>{part}</span>
    ),
  );
}

// One chat bubble. Role is communicated entirely through alignment + color
// (right/blue for the user, left/neutral for the agent) rather than a "You:"/
// "Agent:" text prefix, matching a conventional chat-app look.
function MessageBubble({ role, text }: { role: 'user' | 'assistant'; text: string }) {
  const isUser = role === 'user';
  return (
    <div style={{ display: 'flex', justifyContent: isUser ? 'flex-end' : 'flex-start' }}>
      <div
        style={{
          maxWidth: '85%',
          padding: '8px 14px',
          borderRadius: 16,
          borderBottomRightRadius: isUser ? 4 : 16,
          borderBottomLeftRadius: isUser ? 16 : 4,
          background: isUser ? '#0972d3' : '#f2f3f3',
          color: isUser ? '#ffffff' : '#0f141a',
          fontSize: 14,
          lineHeight: '20px',
          wordBreak: 'break-word',
          whiteSpace: 'pre-wrap',
        }}
      >
        {renderInlineMarkdown(text)}
      </div>
    </div>
  );
}

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
        boxShadow: '0 8px 32px rgba(0, 0, 0, 0.28)',
        borderRadius: 16,
      }}
    >
      <Container
        disableContentPaddings
        header={
          <Header
            variant="h3"
            actions={
              <Button iconName="close" variant="icon" ariaLabel="Close AI Agent" onClick={onClose} />
            }
          >
            <SpaceBetween size="xs" direction="horizontal">
              <span
                aria-hidden="true"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  width: 24,
                  height: 24,
                  borderRadius: '50%',
                  background: 'linear-gradient(135deg, #0972d3, #0aa196)',
                  color: '#fff',
                  fontSize: 13,
                }}
              >
                ✦
              </span>
              <span>Ask AI</span>
            </SpaceBetween>
          </Header>
        }
      >
        <div style={{ display: 'flex', flexDirection: 'column', maxHeight: 'calc(70vh - 52px)' }}>
          {!agentEnabled && (
            <Box padding={{ horizontal: 'l', top: 's' }}>
              <Alert type="warning" header="AI Agent not configured">
                Set the <code>GEMINI_API_KEY</code> environment variable and restart{' '}
                <code>cryptamap serve</code> to enable it.
              </Alert>
            </Box>
          )}
          <div style={{ overflowY: 'auto', padding: '12px 16px', flexGrow: 1 }}>
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
                <MessageBubble key={i} role={m.role} text={m.text} />
              ))}
              {busy && (
                <div style={{ display: 'flex', justifyContent: 'flex-start' }}>
                  <div
                    style={{
                      padding: '8px 14px',
                      borderRadius: 16,
                      borderBottomLeftRadius: 4,
                      background: '#f2f3f3',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 8,
                    }}
                  >
                    <Spinner size="normal" />
                    <Box variant="span" color="text-body-secondary" fontSize="body-s">
                      Thinking…
                    </Box>
                  </div>
                </div>
              )}
              {error && (
                <Alert type="error" header="Agent unavailable">
                  {error}
                </Alert>
              )}
              <div ref={bottomRef} />
            </SpaceBetween>
          </div>
          <div
            style={{
              display: 'flex',
              gap: 8,
              alignItems: 'flex-end',
              padding: '10px 16px 14px',
              borderTop: '1px solid #e9ebed',
            }}
          >
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
              iconName="send"
              ariaLabel="Send"
              onClick={() => send(input)}
              disabled={busy || !agentEnabled || !input.trim()}
            />
          </div>
        </div>
      </Container>
    </div>
  );
}
