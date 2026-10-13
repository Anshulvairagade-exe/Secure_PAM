import { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import SessionWatermark from '@/components/SessionWatermark';

export type TerminalState = 'connecting' | 'connected' | 'closed' | 'error';

interface Props {
  sessionId: string;
  sessionNumber: string;
  /** One-time ticket from the launch response; sent in the first frame, never in a URL. */
  ticket: string;
  username: string;
  onStateChange?: (state: TerminalState, message?: string) => void;
}

/**
 * Embedded SSH terminal. The browser only ever talks to the SecurePAM
 * backend over this WebSocket; the backend holds the real SSH connection,
 * the credential and the recording. Nothing typed here is stored by the page.
 */
export default function SshTerminal({ sessionId, sessionNumber, ticket, username, onStateChange }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<TerminalState>('connecting');
  const [message, setMessage] = useState<string>('Connecting through the SecurePAM gateway...');

  useEffect(() => {
    const report = (next: TerminalState, text: string) => {
      setState(next);
      setMessage(text);
      onStateChange?.(next, text);
    };

    const term = new Terminal({
      cursorBlink: true,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
      fontSize: 13,
      theme: { background: '#020617' },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(containerRef.current!);
    fit.fit();

    const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const socket = new WebSocket(`${scheme}://${window.location.host}/api/v1/sessions/ssh/${sessionId}/ws`);
    let closedByServerMessage = false;
    let connected = false;

    const send = (payload: object) => {
      if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(payload));
    };
    const sendSize = () => {
      fit.fit();
      send({ type: 'resize', cols: term.cols, rows: term.rows });
    };

    socket.onopen = () => {
      socket.send(JSON.stringify({ type: 'auth', ticket }));
    };
    socket.onmessage = (event) => {
      let frame: { type?: string; data?: string; message?: string; reason?: string };
      try {
        frame = JSON.parse(event.data);
      } catch {
        return;
      }
      if (frame.type === 'output' && typeof frame.data === 'string') {
        if (!connected) {
          connected = true;
          report('connected', 'Connected through the SecurePAM gateway. Recorded server-side when policy requires it.');
        }
        term.write(frame.data);
      } else if (frame.type === 'error') {
        closedByServerMessage = true;
        report('closed', frame.message ?? 'The session was ended by SecurePAM.');
      } else if (frame.type === 'closed') {
        closedByServerMessage = true;
        report('closed', frame.reason ?? 'The remote session ended.');
      }
    };
    socket.onerror = () => report('error', 'Could not reach the SecurePAM SSH gateway.');
    socket.onclose = (event) => {
      if (!closedByServerMessage) {
        report(
          event.code === 1000 ? 'closed' : 'error',
          event.reason || (event.code === 1000 ? 'Session closed.' : `Connection closed (code ${event.code}).`),
        );
      }
      term.options.disableStdin = true;
    };

    const input = term.onData((data) => send({ type: 'input', data }));
    const observer = new ResizeObserver(() => sendSize());
    observer.observe(containerRef.current!);
    term.focus();

    return () => {
      observer.disconnect();
      input.dispose();
      socket.close(1000);
      term.dispose();
    };
    // The ticket is single-use: connect exactly once per mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId, ticket]);

  const banner =
    state === 'connected' ? 'border-green-500/30 text-green-300'
      : state === 'connecting' ? 'border-blue-500/30 text-blue-300'
        : state === 'closed' ? 'border-gray-500/30 text-gray-300'
          : 'border-red-500/30 text-red-300';

  return (
    <div className="space-y-2">
      <div className={`rounded-md border px-3 py-2 text-xs ${banner}`} role="status">
        {message}
      </div>
      <div className="relative h-[460px] overflow-hidden rounded-lg border border-navy-700 bg-[#020617] p-2">
        <div ref={containerRef} className="h-full w-full" data-testid="ssh-terminal" />
        <SessionWatermark username={username} sessionNumber={sessionNumber} />
      </div>
      <p className="text-xs text-gray-500">
        The watermark identifies who opened this session. It deters and attributes screenshots but cannot
        prevent screenshots or external capture.
      </p>
    </div>
  );
}
