import { useEffect, useRef, useState } from 'react';
import SessionWatermark from '@/components/SessionWatermark';
import { RFB, type RFBClient } from '@/lib/novnc';

export type WebClientState = 'connecting' | 'connected' | 'closed' | 'error';

interface Props {
  sessionId: string;
  sessionNumber: string;
  /** One-time ticket from the launch response; sent in the first frame, never in a URL. */
  ticket: string;
  username: string;
  applicationName?: string;
  onStateChange?: (state: WebClientState, message?: string) => void;
}

const REASONS: Record<string, string> = {
  TICKET_REQUIRED: 'A connection ticket is required.',
  TICKET_INVALID: 'The connection ticket is invalid or has expired.',
  SESSION_NOT_CONNECTABLE: 'This session can no longer be connected.',
  NOT_AUTHORIZED: 'Access is no longer authorized.',
};

/**
 * The isolated browser, viewed through noVNC. The application runs in a disposable Chromium inside
 * SecurePAM's isolation service; this page only receives pixels and sends keyboard/mouse input.
 * Nothing from the application (cookies, storage, downloads) reaches this browser.
 */
export default function WebClient({ sessionId, sessionNumber, ticket, username, applicationName, onStateChange }: Props) {
  const screenRef = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<WebClientState>('connecting');
  const [message, setMessage] = useState('Opening the isolated browser…');

  useEffect(() => {
    const report = (next: WebClientState, text: string) => { setState(next); setMessage(text); onStateChange?.(next, text); };
    const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const socket = new WebSocket(`${scheme}://${window.location.host}/api/v1/sessions/web/${sessionId}/ws`);
    socket.binaryType = 'arraybuffer';
    let rfb: RFBClient | null = null;
    let handedOver = false;

    socket.onopen = () => socket.send(JSON.stringify({ type: 'auth', ticket }));
    socket.onmessage = (event) => {
      if (handedOver || typeof event.data !== 'string') return;
      const msg = JSON.parse(event.data);
      if (msg.type === 'error') { report('error', REASONS[msg.reason] ?? 'The isolated browser could not be opened.'); return; }
      if (msg.type !== 'ready') return;
      // From here the socket carries the (already authenticated) VNC stream; noVNC takes it over.
      handedOver = true;
      socket.onmessage = null;
      rfb = new RFB(screenRef.current!, socket);
      rfb.scaleViewport = true;       // fit the remote 1280x800 screen into the panel
      rfb.resizeSession = false;
      rfb.focusOnClick = true;
      rfb.showDotCursor = true;
      rfb.viewOnly = false;
      rfb.addEventListener('connect', () => report('connected', `Connected to ${applicationName ?? 'the application'} in an isolated browser.`));
      rfb.addEventListener('disconnect', () => report('closed', 'The isolated browser session has ended.'));
      rfb.addEventListener('securityfailure', () => report('error', 'The isolated browser could not be opened.'));
      socket.send(JSON.stringify({ type: 'go' }));
    };
    socket.onclose = () => { if (!handedOver) report('closed', 'The isolated browser session has ended.'); };
    return () => {
      try { rfb?.disconnect(); } catch { /* already closed */ }
      try { socket.close(); } catch { /* already closed */ }
    };
    // One connection per session; a new launch mounts a new component (keyed by session).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="space-y-2">
      <div className="relative h-[640px] overflow-hidden rounded-lg border border-navy-700 bg-[#020617]" data-testid="web-stage">
        <div ref={screenRef} className="h-full w-full" />
        {state !== 'connected' && (
          <div className={`absolute inset-0 z-20 flex items-center justify-center bg-navy-950/80 p-6 text-center text-sm ${state === 'error' ? 'text-red-400' : 'text-gray-300'}`}>
            {message}
          </div>
        )}
        <SessionWatermark username={username} sessionNumber={sessionNumber} />
      </div>
      <p className="text-xs text-gray-500">
        The application runs in a disposable browser inside SecurePAM, limited to its registered address. Sign in to it
        yourself; SecurePAM never sees or stores your application credentials. The watermark deters but cannot prevent
        screenshots.
      </p>
    </div>
  );
}
