import { describe, expect, it, vi } from 'vitest';
import { attachPointer, displayPoint, mouseState, remoteCursorCss, type MouseStateTemplate } from '@/lib/guacamole';

// Measured live: with SecurePAM's <main> scrolled by 123 px, Guacamole 1.5.0's offsetParent-based
// Mouse placed a click at y=199 when the pointer was at y=320 over the desktop (121 px too high).
// getBoundingClientRect() already includes that scroll, so these values reproduce the live case.
const LIVE_RECT = { left: 302, top: 269, width: 1052, height: 643 };   // canvas rect after scrolling
const LIVE_POINTER = { clientX: 846, clientY: 589 };                   // centre of the visible desktop

describe('displayPoint', () => {
  it('maps the live scrolled case to the pointer position over the desktop (no scroll error)', () => {
    expect(displayPoint(LIVE_POINTER.clientX, LIVE_POINTER.clientY, LIVE_RECT)).toEqual({ x: 544, y: 320 });
  });

  it('is relative to the element wherever the page has scrolled to', () => {
    const scrolled = { ...LIVE_RECT, top: LIVE_RECT.top - 400 }; // the same element after 400 px more scroll
    expect(displayPoint(LIVE_POINTER.clientX, LIVE_POINTER.clientY - 400, scrolled)).toEqual({ x: 544, y: 320 });
  });

  it('clamps to the element so a drag outside it cannot address pixels beyond the desktop', () => {
    expect(displayPoint(0, 0, LIVE_RECT)).toEqual({ x: 0, y: 0 });
    expect(displayPoint(5000, 5000, LIVE_RECT)).toEqual({ x: LIVE_RECT.width - 1, y: LIVE_RECT.height - 1 });
  });
});

describe('mouseState', () => {
  it('translates DOM buttons to Guacamole buttons', () => {
    const at = { clientX: 402, clientY: 369 };
    expect(mouseState({ ...at, buttons: 0 }, LIVE_RECT)).toMatchObject({ x: 100, y: 100, left: false, right: false, middle: false });
    expect(mouseState({ ...at, buttons: 1 }, LIVE_RECT)).toMatchObject({ left: true, right: false, middle: false });
    expect(mouseState({ ...at, buttons: 2 }, LIVE_RECT)).toMatchObject({ left: false, right: true, middle: false });
    expect(mouseState({ ...at, buttons: 4 }, LIVE_RECT)).toMatchObject({ middle: true });
    expect(mouseState({ ...at, buttons: 3 }, LIVE_RECT)).toMatchObject({ left: true, right: true });
  });

  it('encodes the wheel as the up/down buttons', () => {
    const s = mouseState({ clientX: 402, clientY: 369, buttons: 0 }, LIVE_RECT, 'down');
    expect(s).toMatchObject({ up: false, down: true });
  });
});

describe('attachPointer', () => {
  const setup = () => {
    const element = document.createElement('div');
    element.getBoundingClientRect = () => ({ ...LIVE_RECT, right: 0, bottom: 0, x: LIVE_RECT.left, y: LIVE_RECT.top, toJSON: () => ({}) }) as DOMRect;
    const focusTarget = document.createElement('div');
    focusTarget.tabIndex = 0;
    document.body.append(element, focusTarget);
    const sent: MouseStateTemplate[] = [];
    const detach = attachPointer(element, focusTarget, { send: (s) => sent.push(s) });
    return { element, focusTarget, sent, detach };
  };
  const fire = (el: HTMLElement, type: string, init: MouseEventInit) => {
    const event = new MouseEvent(type, { bubbles: true, cancelable: true, ...init });
    el.dispatchEvent(event);
    return event;
  };

  it('forwards move, press and release of a left click at rect-mapped coordinates', () => {
    const { element, sent } = setup();
    fire(element, 'mousemove', { ...LIVE_POINTER, buttons: 0 });
    fire(element, 'mousedown', { ...LIVE_POINTER, buttons: 1 });
    fire(element, 'mouseup', { ...LIVE_POINTER, buttons: 0 });
    expect(sent.map((s) => [s.x, s.y, s.left])).toEqual([[544, 320, false], [544, 320, true], [544, 320, false]]);
  });

  it('right-clicks reach the remote side and the browser context menu is suppressed', () => {
    const { element, sent } = setup();
    fire(element, 'mousedown', { ...LIVE_POINTER, button: 2, buttons: 2 });
    const menu = fire(element, 'contextmenu', { ...LIVE_POINTER });
    expect(sent[0]).toMatchObject({ right: true, left: false });
    expect(menu.defaultPrevented).toBe(true);
  });

  it('a click focuses the desktop so keyboard input goes to it', () => {
    const { element, focusTarget } = setup();
    const down = fire(element, 'mousedown', { ...LIVE_POINTER, buttons: 1 });
    expect(document.activeElement).toBe(focusTarget);
    expect(down.defaultPrevented).toBe(true);  // no text selection or native drag
  });

  it('the wheel sends a press then a release of the matching scroll button', () => {
    const { element, sent } = setup();
    element.dispatchEvent(new WheelEvent('wheel', { ...LIVE_POINTER, deltaY: -120, bubbles: true, cancelable: true }));
    expect(sent.map((s) => [s.up, s.down])).toEqual([[true, false], [false, false]]);
  });

  it('detaching stops forwarding', () => {
    const { element, sent, detach } = setup();
    detach();
    fire(element, 'mousemove', { ...LIVE_POINTER, buttons: 0 });
    expect(sent).toEqual([]);
  });
});

describe('remoteCursorCss', () => {
  it('uses the remote cursor image with its hotspot and a safe fallback', () => {
    expect(remoteCursorCss('data:image/png;base64,AAA', 3.4, 0)).toBe('url(data:image/png;base64,AAA) 3 0, default');
  });
});
