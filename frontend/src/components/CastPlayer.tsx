import { useEffect, useMemo, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import SessionWatermark from '@/components/SessionWatermark';

interface CastHeader {
  version: number;
  width: number;
  height: number;
  title?: string;
}
type CastEvent = [number, string, string];

/** Parse an asciicast v2 recording; throws on anything else. */
export function parseCast(text: string): { header: CastHeader; events: CastEvent[] } {
  const lines = text.split('\n').filter((line) => line.trim());
  if (lines.length === 0) throw new Error('Empty recording');
  const header = JSON.parse(lines[0]) as CastHeader;
  if (header.version !== 2) throw new Error(`Unsupported recording version ${header.version}`);
  const events = lines.slice(1).map((line) => JSON.parse(line) as CastEvent);
  return { header, events };
}

/** Replays a verified terminal recording. Output only; no input is ever sent anywhere. */
export default function CastPlayer({ cast, viewer, label }: { cast: string; viewer: string; label: string }) {
  const parsed = useMemo(() => {
    try {
      return { ok: true as const, ...parseCast(cast) };
    } catch (error) {
      return { ok: false as const, error: (error as Error).message };
    }
  }, [cast]);
  if (!parsed.ok) {
    return <p className="text-sm text-red-400">This recording could not be read: {parsed.error}</p>;
  }
  return <Player header={parsed.header} events={parsed.events} viewer={viewer} label={label} />;
}

function Player({ header, events, viewer, label }: { header: CastHeader; events: CastEvent[]; viewer: string; label: string }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const timerRef = useRef<number | null>(null);
  const indexRef = useRef(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [done, setDone] = useState(false);
  const total = events.length ? events[events.length - 1][0] : 0;

  useEffect(() => {
    const term = new Terminal({ cols: header.width, rows: header.height, disableStdin: true, fontSize: 13,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', theme: { background: '#020617' } });
    term.open(containerRef.current!);
    termRef.current = term;
    return () => { if (timerRef.current) window.clearTimeout(timerRef.current); term.dispose(); };
  }, [header.width, header.height]);

  useEffect(() => {
    if (!playing) return;
    const step = () => {
      const term = termRef.current;
      const index = indexRef.current;
      if (!term || index >= events.length) { setPlaying(false); setDone(true); return; }
      const [time, kind, data] = events[index];
      if (kind === 'o') term.write(data);
      else if (kind === 'r') {
        const [cols, rows] = data.split('x').map(Number);
        if (cols && rows) term.resize(cols, rows);
      }
      indexRef.current = index + 1;
      const next = events[index + 1];
      const delay = next ? Math.min(2000, ((next[0] - time) * 1000) / speed) : 0;
      timerRef.current = window.setTimeout(step, delay);
    };
    step();
    return () => { if (timerRef.current) window.clearTimeout(timerRef.current); };
  }, [playing, speed, events]);

  const restart = () => {
    if (timerRef.current) window.clearTimeout(timerRef.current);
    termRef.current?.reset();
    indexRef.current = 0;
    setDone(false);
    setPlaying(true);
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 text-sm">
        <button className="btn-primary px-3 py-1.5" onClick={() => (done ? restart() : setPlaying(!playing))}>
          {playing ? 'Pause' : done ? 'Replay' : 'Play'}
        </button>
        <button className="btn-secondary px-3 py-1.5" onClick={restart}>Restart</button>
        <select className="input w-auto" value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
          {[1, 2, 4, 8].map((s) => <option key={s} value={s}>{s}x</option>)}
        </select>
        <span className="text-xs text-gray-500">{events.length} events · {total.toFixed(1)} s recorded</span>
      </div>
      <div className="relative overflow-auto rounded-lg border border-navy-700 bg-[#020617] p-2">
        <div ref={containerRef} data-testid="cast-player" />
        <SessionWatermark username={viewer} sessionNumber={label} />
      </div>
    </div>
  );
}
