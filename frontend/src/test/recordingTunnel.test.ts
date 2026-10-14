import { describe, expect, it, vi } from 'vitest';
import { createRecordingTunnel, encodeInstruction } from '@/lib/guacamole';

// Regression: guacamole-common-js 1.5.0's SessionRecording(Blob) path throws
// "Cannot read properties of undefined (reading 'size')", which left RDP playback blank.
// Recordings are therefore replayed through this tunnel, whose contract is tested here.
describe('createRecordingTunnel', () => {
  it('delivers every recorded instruction, then closes (which is what marks the recording loaded)', async () => {
    const text = encodeInstruction('size', 0, 1152, 691) + encodeInstruction('sync', 1000, 0) + encodeInstruction('mouse', 10, 20, 1, 1500);
    const tunnel = createRecordingTunnel(text);
    const seen: string[] = [];
    const states: number[] = [];
    tunnel.oninstruction = (op: string, args: string[]) => seen.push(`${op}:${args.join(',')}`);
    tunnel.onstatechange = (s: number) => states.push(s);
    tunnel.connect();
    await vi.waitFor(() => expect(states).toContain(2));
    expect(seen).toEqual(['size:0,1152,691', 'sync:1000,0', 'mouse:10,20,1,1500']);
    expect(states[0]).toBe(1);
  });

  it('reports a malformed recording as an error instead of silently showing nothing', async () => {
    const tunnel = createRecordingTunnel('not a guacamole recording');
    const onerror = vi.fn();
    tunnel.onerror = onerror;
    const states: number[] = [];
    tunnel.onstatechange = (s: number) => states.push(s);
    tunnel.connect();
    await vi.waitFor(() => expect(states).toContain(2));
    expect(onerror).toHaveBeenCalled();
  });

  it('is replay-only: it never sends anything', () => {
    const tunnel = createRecordingTunnel('');
    expect(() => tunnel.sendMessage('key', 65, 1)).not.toThrow();
  });
});
