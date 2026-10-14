import { useEffect, useRef, useState } from 'react';
import SessionWatermark from '@/components/SessionWatermark';
import { createRecordingTunnel, Guacamole } from '@/lib/guacamole';

/** Replays a verified RDP screen recording (Guacamole format) in the browser. */
export default function RdpRecordingPlayer({ blob, viewer, label }: { blob: Blob; viewer: string; label: string }) {
  const stageRef = useRef<HTMLDivElement>(null);
  const hostRef = useRef<HTMLDivElement>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const recordingRef = useRef<any>(null);
  const [playing, setPlaying] = useState(false);
  const [position, setPosition] = useState(0);
  const [duration, setDuration] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  // Target of a user seek in progress. While set, the slider shows it and position polling is paused:
  // otherwise the controlled slider echoes intermediate positions back as new seeks, and each one
  // aborts the user's seek (observed live: seek(40000) was cancelled by an echoed seek(31800)).
  const seekingRef = useRef<number | null>(null);
  const [seekTarget, setSeekTarget] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    let cleanup = () => {};
    // The server verified the SHA-256 before serving these bytes; they are replayed through a
    // replay-only tunnel because the library's Blob path is broken (see createRecordingTunnel).
    blob.text().then((text) => {
      if (cancelled) return;
      cleanup = start(text);
    }).catch(() => setError('The recording could not be read.'));
    return () => { cancelled = true; cleanup(); };
  }, [blob]);

  function start(text: string) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const recording: any = new Guacamole.SessionRecording(createRecordingTunnel(text));
    recordingRef.current = recording;
    const display = recording.getDisplay();
    const element = display.getElement();
    hostRef.current!.appendChild(element);
    const fit = () => {
      const w = display.getWidth();
      if (w > 0 && stageRef.current) display.scale(Math.min(1, stageRef.current.clientWidth / w));
    };
    display.onresize = fit;
    recording.onprogress = (ms: number) => setDuration(ms);
    recording.onload = () => { setLoaded(true); setDuration(recording.getDuration()); };
    recording.onerror = (message: string) => setError(message || 'The recording could not be read.');
    recording.onplay = () => setPlaying(true);
    recording.onpause = () => setPlaying(false);
    recording.onseek = (ms: number) => { if (seekingRef.current === null) setPosition(ms); };
    recording.connect();
    const timer = window.setInterval(() => { if (seekingRef.current === null) setPosition(recording.getPosition?.() ?? 0); }, 500);
    return () => {
      window.clearInterval(timer);
      try { recording.pause(); recording.disconnect(); } catch { /* ignore */ }
      hostRef.current?.replaceChildren();
    };
  }

  const seekTo = (target: number) => {
    const recording = recordingRef.current;
    if (!recording || Number.isNaN(target)) return;
    // A value equal to what is already shown is an echo of our own render, not a user action.
    if (seekingRef.current === null && Math.abs(target - position) < 1) return;
    seekingRef.current = target;
    setSeekTarget(target);
    recording.seek(target, () => {
      if (seekingRef.current !== target) return;  // superseded by a newer user seek
      seekingRef.current = null;
      setSeekTarget(null);
      setPosition(recording.getPosition?.() ?? target);
    });
  };

  const seconds = (ms: number) => (ms / 1000).toFixed(1);
  const shown = seekTarget ?? position;
  if (error) return <p className="text-sm text-red-400">This recording could not be played: {error}</p>;
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 text-sm">
        <button
          className="btn-primary px-3 py-1.5" disabled={!loaded}
          onClick={() => (playing ? recordingRef.current.pause() : recordingRef.current.play())}
        >
          {playing ? 'Pause' : 'Play'}
        </button>
        <input
          type="range" aria-label="Seek" min={0} max={Math.max(duration, 1)} step={1} className="min-w-0 flex-1"
          value={Math.min(shown, duration)} disabled={!loaded}
          onChange={(e) => seekTo(Number(e.target.value))}
        />
        <span className="whitespace-nowrap font-mono text-xs text-gray-400">{seconds(shown)} / {seconds(duration)} s</span>
      </div>
      <div ref={stageRef} className="relative min-h-[300px] overflow-auto rounded-lg border border-navy-700 bg-[#020617]" data-testid="rdp-recording-player">
        <div ref={hostRef} />
        {!loaded && <p className="absolute inset-0 flex items-center justify-center text-sm text-gray-400">Loading recording…</p>}
        <SessionWatermark username={viewer} sessionNumber={label} />
      </div>
    </div>
  );
}
