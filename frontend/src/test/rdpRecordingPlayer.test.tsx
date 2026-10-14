import { describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';

// A stand-in for Guacamole.SessionRecording that records every seek and lets the test drive callbacks.
const fake = vi.hoisted(() => ({ seeks: [] as number[], instance: null as null | Record<string, any> }));
vi.mock('@/lib/guacamole', () => ({
  createRecordingTunnel: () => ({}),
  Guacamole: {
    SessionRecording: function SessionRecording(this: any) {
      const el = document.createElement('div');
      let position = 0;
      let pending: (() => void) | null = null;
      Object.assign(this, {
        getDisplay: () => ({ getElement: () => el, getWidth: () => 1152, scale: () => {}, onresize: null }),
        connect: () => setTimeout(() => { this.onprogress?.(43623); this.onload?.(); }, 0),
        getDuration: () => 43623,
        getPosition: () => position,
        play: () => this.onplay?.(), pause: () => this.onpause?.(), disconnect: () => {},
        seek: (ms: number, cb?: () => void) => { fake.seeks.push(ms); pending = () => { position = ms; cb?.(); }; },
        finishSeek: () => { const p = pending; pending = null; p?.(); },
        reportProgress: (ms: number) => { position = ms; this.onseek?.(ms, 1, 1); },
      });
      fake.instance = this;
    },
  },
}));
vi.mock('@/components/SessionWatermark', () => ({ default: () => null }));

import RdpRecordingPlayer from '@/components/RdpRecordingPlayer';

// jsdom's Blob lacks .text(); the player only needs that method.
const recordingBlob = () => ({ text: async () => '4.sync,4.1000;' }) as unknown as Blob;

describe('RdpRecordingPlayer seeking', () => {
  it('issues exactly one seek per user action and never echoes positions back as new seeks', async () => {
    fake.seeks = [];
    render(<RdpRecordingPlayer blob={recordingBlob()} viewer="admin" label="playback" />);
    const slider = await screen.findByLabelText('Seek');
    await waitFor(() => expect(slider).not.toBeDisabled());

    fireEvent.change(slider, { target: { value: '40000' } });
    expect(fake.seeks).toEqual([40000]);

    // While the seek runs, intermediate progress and polling must not trigger further seeks
    // (previously the step-snapped echo issued seek(31800), aborting the user's seek).
    act(() => { fake.instance!.reportProgress(31822); });
    await act(async () => { await new Promise((r) => setTimeout(r, 600)); });
    expect(fake.seeks).toEqual([40000]);
    expect((slider as HTMLInputElement).value).toBe('40000');  // shows the user's target, not the echo

    act(() => { fake.instance!.finishSeek(); });
    expect(screen.getByText(/40\.0 \/ 43\.6 s/)).toBeInTheDocument();
    expect(fake.seeks).toEqual([40000]);
  });

  it('uses millisecond steps so the browser never snaps a position into a different value', async () => {
    render(<RdpRecordingPlayer blob={recordingBlob()} viewer="admin" label="playback" />);
    const slider = await screen.findByLabelText('Seek');
    expect(slider.getAttribute('step')).toBe('1');
  });
});
