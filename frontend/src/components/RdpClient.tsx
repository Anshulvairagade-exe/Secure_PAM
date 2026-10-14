import { useEffect, useRef, useState } from 'react';
import SessionWatermark from '@/components/SessionWatermark';
import { attachPointer, createSecurePamTunnel, Guacamole, remoteCursorCss } from '@/lib/guacamole';

export type RdpState = 'connecting' | 'connected' | 'closed' | 'error';

interface Props {
  sessionId: string;
  sessionNumber: string;
  /** One-time ticket from the launch response; sent in the first frame, never in a URL. */
  ticket: string;
  username: string;
  onStateChange?: (state: RdpState, message?: string) => void;
}

/**
 * Embedded Windows desktop. The browser talks only to the SecurePAM backend; the backend holds the
 * RDP connection (through guacd), the Windows credential and the screen recording. Pixels in,
 * keyboard/mouse out.
 */
export default function RdpClient({ sessionId, sessionNumber, ticket, username, onStateChange }: Props) {
  const stageRef = useRef<HTMLDivElement>(null);
  const hostRef = useRef<HTMLDivElement>(null);
  const [state, setState] = useState<RdpState>('connecting');
  const [message, setMessage] = useState('Connecting through the SecurePAM gateway…');

  useEffect(() => {
    const stage = stageRef.current!;
    const host = hostRef.current!;
    const report = (next: RdpState, text: string) => { setState(next); setMessage(text); onStateChange?.(next, text); };

    const tunnel = createSecurePamTunnel(`/api/v1/sessions/rdp/${sessionId}/ws`, ticket, {
      width: Math.max(640, Math.min(2560, Math.floor(stage.clientWidth))),
      height: Math.max(480, Math.min(1440, Math.floor(stage.clientWidth * 0.6))),
      dpi: 96,
    });
    const client = new Guacamole.Client(tunnel);
    const display = client.getDisplay();
    const element = display.getElement();
    host.appendChild(element);

    const fit = () => {
      const w = display.getWidth();
      if (w > 0) display.scale(Math.min(1, stage.clientWidth / w));
    };
    display.onresize = fit;

    let lastError: string | null = null;
    client.onstatechange = (s: number) => {
      if (s === 3) report('connected', 'Connected. The session is recorded.');
      else if (s === 5) report(lastError ? 'error' : 'closed', lastError ?? 'The session has ended.');
    };
    client.onerror = (status: { message?: string }) => {
      lastError = status.message || 'The session failed.';
      report('error', lastError);
    };

    // Pointer positions come from getBoundingClientRect() (see attachPointer); Guacamole's own display
    // scale is then applied once by sendMouseState(state, true).
    const detachPointer = attachPointer(element, stage, {
      send: (s) => client.sendMouseState(new Guacamole.Mouse.State(s.x, s.y, s.left, s.middle, s.right, s.up, s.down), true),
    });
    // Show the remote cursor image as the local CSS cursor and hide Guacamole's software cursor layer,
    // so there is exactly one cursor and it never lags behind the pointer.
    element.style.cursor = 'default';
    display.oncursor = (canvas: HTMLCanvasElement, x: number, y: number) => {
      if (canvas.width > 0 && canvas.height > 0) {
        element.style.cursor = remoteCursorCss(canvas.toDataURL('image/png'), x, y);
        display.showCursor(false);
      } else {
        element.style.cursor = 'none';  // the remote cursor is hidden (e.g. while typing in some apps)
      }
    };

    const keyboard = new Guacamole.Keyboard(stage);
    keyboard.onkeydown = (keysym: number) => { client.sendKeyEvent(1, keysym); return false; };
    keyboard.onkeyup = (keysym: number) => { client.sendKeyEvent(0, keysym); };
    stage.focus();

    client.connect();
    const observer = new ResizeObserver(fit);
    observer.observe(stage);
    return () => {
      detachPointer();
      observer.disconnect();
      keyboard.onkeydown = keyboard.onkeyup = null;
      keyboard.reset();
      try { client.disconnect(); } catch { /* already closed */ }
      host.replaceChildren();
    };
    // The connection is made once per session; a new launch mounts a new component (keyed by session).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="space-y-2">
      <div
        ref={stageRef} tabIndex={0} data-testid="rdp-stage"
        className="relative min-h-[420px] overflow-hidden rounded-lg border border-navy-700 bg-[#020617] outline-none focus:ring-1 focus:ring-blue-500"
      >
        <div ref={hostRef} />
        {state !== 'connected' && (
          <div className={`absolute inset-0 z-20 flex items-center justify-center bg-navy-950/80 p-6 text-center text-sm ${state === 'error' ? 'text-red-400' : 'text-gray-300'}`}>
            {message}
          </div>
        )}
        <SessionWatermark username={username} sessionNumber={sessionNumber} />
      </div>
      <p className="text-xs text-gray-500">
        The watermark identifies who opened this session. It deters and attributes screenshots but cannot prevent
        screenshots or external capture. Click the desktop to give it keyboard focus.
      </p>
    </div>
  );
}
