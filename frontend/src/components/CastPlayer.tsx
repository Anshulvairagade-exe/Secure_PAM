import { forwardRef, useEffect, useImperativeHandle, useMemo, useRef, useState } from 'react';
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

export interface CastPlayerHandle {
  /** Jump the replay to `seconds` into the recording (state is rebuilt from the start, then playback resumes). */
  seek: (seconds: number) => void;
}

/** Replays a verified terminal recording. Output only; no input is ever sent anywhere. */
const CastPlayer = forwardRef<CastPlayerHandle, { cast: string; viewer: string; label: string }>(function CastPlayer(
  { cast, viewer, label },
  ref,
) {
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
  return <Player ref={ref} header={parsed.header} events={parsed.events} viewer={viewer} label={label} />;
});
export default CastPlayer;

const Player = forwardRef<CastPlayerHandle, { header: CastHeader; events: CastEvent[]; viewer: string; label: string }>(function Player(
  { header, events, viewer, label },
  ref,
) {
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const timerRef = useRef<number | null>(null);
  const indexRef = useRef(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [done, setDone] = useState(false);
  const [current, setCurrent] = useState(0);
  const [epoch, setEpoch] = useState(0);
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
      apply(term, kind, data);
      setCurrent(time);
      indexRef.current = index + 1;
      const next = events[index + 1];
      const delay = next ? Math.min(2000, ((next[0] - time) * 1000) / speed) : 0;
      timerRef.current = window.setTimeout(step, delay);
    };
    step();
    return () => { if (timerRef.current) window.clearTimeout(timerRef.current); };
  }, [playing, speed, events, epoch]);

  const seek = (seconds: number, resume = true) => {
    const term = termRef.current;
    if (!term) return;
    if (timerRef.current) window.clearTimeout(timerRef.current);
    term.reset();
    term.resize(header.width, header.height);
    let index = 0;
    while (index < events.length && events[index][0] <= seconds) {
      apply(term, events[index][1], events[index][2]);
      index += 1;
    }
    indexRef.current = index;
    setCurrent(Math.max(0, seconds));
    setDone(false);
    setPlaying(resume);
    setEpoch((e) => e + 1);
  };
  useImperativeHandle(ref, () => ({ seek: (seconds: number) => seek(seconds) }));

  const restart = () => seek(0);

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
        <input
          type="range" min={0} max={total} step={0.1} value={Math.min(current, total)} aria-label="Seek"
          className="min-w-0 flex-1" onChange={(e) => seek(Number(e.target.value), playing)}
        />
        <span className="whitespace-nowrap font-mono text-xs text-gray-400">{current.toFixed(1)} / {total.toFixed(1)} s</span>
      </div>
      <div className="relative overflow-auto rounded-lg border border-navy-700 bg-[#020617] p-2">
        <div ref={containerRef} data-testid="cast-player" />
        <SessionWatermark username={viewer} sessionNumber={label} />
      </div>
    </div>
  );
});

function apply(term: Terminal, kind: string, data: string) {
  if (kind === 'o') term.write(data);
  else if (kind === 'r') {
    const [cols, rows] = data.split('x').map(Number);
    if (cols && rows) term.resize(cols, rows);
  }
}
