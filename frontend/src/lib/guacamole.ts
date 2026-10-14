// The npm package ships only a default export at runtime, while @types describes the global
// namespace. Re-expose the runtime object under the type namespace.
import GuacamoleRuntime from 'guacamole-common-js';
import type * as GuacamoleTypes from 'guacamole-common-js';

export const Guacamole = GuacamoleRuntime as unknown as typeof GuacamoleTypes;

/** Encode one Guacamole instruction: `LEN.value,LEN.value;` (lengths in Unicode characters). */
export function encodeInstruction(...elements: unknown[]): string {
  return elements.map((e) => { const s = String(e); return `${[...s].length}.${s}`; }).join(',') + ';';
}

export interface TunnelSize { width: number; height: number; dpi: number }

/**
 * A Guacamole tunnel over the SecurePAM RDP WebSocket. The one-time ticket and the display size go
 * in the first frame (never the URL); the backend does the guacd handshake, so no credential, token
 * or Guacamole API is ever involved in the browser.
 */
export function createSecurePamTunnel(wsPath: string, ticket: string, size: TunnelSize) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const tunnel: any = new (Guacamole.Tunnel as any)();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const parser: any = new (Guacamole as any).Parser();
  let socket: WebSocket | null = null;

  parser.oninstruction = (opcode: string, args: string[]) => {
    if (opcode === '') return; // internal keep-alive
    tunnel.oninstruction?.(opcode, args);
  };

  tunnel.connect = () => {
    tunnel.setState(0);
    const scheme = window.location.protocol === 'https:' ? 'wss' : 'ws';
    socket = new WebSocket(`${scheme}://${window.location.host}${wsPath}`);
    socket.onopen = () => {
      socket!.send(JSON.stringify({ type: 'auth', ticket, ...size }));
      tunnel.setState(1);
    };
    socket.onmessage = (event) => { if (typeof event.data === 'string') parser.receive(event.data); };
    socket.onerror = () => tunnel.onerror?.(new Guacamole.Status(Guacamole.Status.Code.UPSTREAM_ERROR, 'The gateway connection failed.'));
    socket.onclose = () => tunnel.setState(2);
  };
  tunnel.sendMessage = (...elements: unknown[]) => {
    if (socket && socket.readyState === WebSocket.OPEN) socket.send(encodeInstruction(...elements));
  };
  tunnel.disconnect = () => { socket?.close(); };
  return tunnel;
}

/**
 * A replay-only tunnel over an already-downloaded recording. guacamole-common-js 1.5.0's
 * SessionRecording(Blob) path is broken (it parses an unassigned variable and throws on `.size`),
 * so recordings are always handed over in its working tunnel mode: every instruction is delivered,
 * then the tunnel closes, which is what marks the recording as loaded. Nothing is sent anywhere.
 */
export function createRecordingTunnel(recordingText: string) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const tunnel: any = new (Guacamole.Tunnel as any)();
  tunnel.connect = () => {
    tunnel.setState(1);
    // Deliver after the caller has wired its handlers (SessionRecording connects synchronously).
    window.setTimeout(() => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const parser: any = new (Guacamole as any).Parser();
      let delivered = 0;
      parser.oninstruction = (opcode: string, args: string[]) => { delivered += 1; tunnel.oninstruction?.(opcode, args); };
      let valid = true;
      try {
        parser.receive(recordingText);
      } catch {
        valid = false;
      }
      // The parser buffers unparseable input instead of throwing, so "nothing decoded" is the signal
      // that this is not a recording; report it rather than show an empty player.
      if (!valid || delivered === 0) {
        tunnel.onerror?.(new Guacamole.Status(Guacamole.Status.Code.SERVER_ERROR, 'The recording is not a valid Guacamole recording.'));
      }
      tunnel.setState(2);
    }, 0);
  };
  tunnel.disconnect = () => tunnel.setState(2);
  tunnel.sendMessage = () => { /* replay only */ };
  return tunnel;
}

// --- pointer input -----------------------------------------------------------------------------------
// Guacamole 1.5.0's Guacamole.Mouse locates the pointer by walking offsetLeft/offsetParent. That ignores
// scrolling inside a non-positioned scroll container (SecurePAM's <main class="overflow-y-auto">), so once
// the page was scrolled every click landed off by the scroll offset (measured live: 121 px at
// main.scrollTop=123). Positions are therefore computed here from getBoundingClientRect(), which already
// reflects scrolling, CSS transforms and layout; the Guacamole client then divides by its own display
// scale (sendMouseState(state, true)), so scaling is applied exactly once. Device pixel ratio does not
// enter: both the rect and Guacamole's display scale are in CSS pixels.

export interface ElementRect { left: number; top: number; width: number; height: number }

export interface PointerSample { clientX: number; clientY: number; buttons: number }

export interface MouseStateTemplate {
  x: number; y: number; left: boolean; middle: boolean; right: boolean; up: boolean; down: boolean;
}

/** Pointer position in CSS pixels relative to the (scaled) display element, clamped to it. */
export function displayPoint(clientX: number, clientY: number, rect: ElementRect): { x: number; y: number } {
  const clamp = (v: number, max: number) => Math.min(Math.max(v, 0), Math.max(max - 1, 0));
  return { x: clamp(clientX - rect.left, rect.width), y: clamp(clientY - rect.top, rect.height) };
}

/** DOM MouseEvent.buttons (1 left, 2 right, 4 middle) to a Guacamole mouse state. */
export function mouseState(sample: PointerSample, rect: ElementRect, wheel: 'up' | 'down' | null = null): MouseStateTemplate {
  const { x, y } = displayPoint(sample.clientX, sample.clientY, rect);
  return {
    x, y,
    left: (sample.buttons & 1) !== 0,
    right: (sample.buttons & 2) !== 0,
    middle: (sample.buttons & 4) !== 0,
    up: wheel === 'up',
    down: wheel === 'down',
  };
}

export interface MouseSink { send(state: MouseStateTemplate): void }

/**
 * Attach pointer handling to the display element. Returns a detach function.
 * - move/down/up send the full button state at the rect-mapped position;
 * - the wheel is a press-and-release of the up/down "buttons" (Guacamole's encoding of scrolling);
 * - mousedown focuses the desktop (Guacamole.Keyboard listens on it) and the browser context menu,
 *   text selection and drag are suppressed so right-clicks reach Windows instead of the browser.
 */
export function attachPointer(element: HTMLElement, focusTarget: HTMLElement, sink: MouseSink): () => void {
  const rect = () => element.getBoundingClientRect();
  const onMove = (e: MouseEvent) => sink.send(mouseState(e, rect()));
  const onDown = (e: MouseEvent) => { e.preventDefault(); focusTarget.focus({ preventScroll: true }); sink.send(mouseState(e, rect())); };
  const onUp = (e: MouseEvent) => { e.preventDefault(); sink.send(mouseState(e, rect())); };
  const onWheel = (e: WheelEvent) => {
    if (e.deltaY === 0) return;
    e.preventDefault();
    const direction = e.deltaY < 0 ? 'up' : 'down';
    sink.send(mouseState(e, rect(), direction));
    sink.send(mouseState(e, rect()));
  };
  const onContext = (e: Event) => e.preventDefault();
  element.addEventListener('mousemove', onMove);
  element.addEventListener('mousedown', onDown);
  element.addEventListener('mouseup', onUp);
  element.addEventListener('wheel', onWheel, { passive: false });
  element.addEventListener('contextmenu', onContext);
  return () => {
    element.removeEventListener('mousemove', onMove);
    element.removeEventListener('mousedown', onDown);
    element.removeEventListener('mouseup', onUp);
    element.removeEventListener('wheel', onWheel);
    element.removeEventListener('contextmenu', onContext);
  };
}

/** CSS cursor that shows the REMOTE cursor image at the local pointer (no lag, no second cursor). */
export function remoteCursorCss(dataUrl: string, hotspotX: number, hotspotY: number): string {
  return `url(${dataUrl}) ${Math.max(0, Math.round(hotspotX))} ${Math.max(0, Math.round(hotspotY))}, default`;
}
