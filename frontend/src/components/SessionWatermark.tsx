import { useEffect, useState } from 'react';

/**
 * Tiled, always-on watermark over an embedded privileged session: operator
 * identity, session number and a live timestamp. It discourages and
 * attributes screenshots; it cannot prevent screenshots or external capture.
 */
export default function SessionWatermark({ username, sessionNumber }: { username: string; sessionNumber: string }) {
  const [now, setNow] = useState(() => new Date());

  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const label = `${username} · ${sessionNumber} · ${now.toISOString().replace('T', ' ').slice(0, 19)} UTC`;

  return (
    <div
      aria-hidden="true"
      data-testid="session-watermark"
      className="pointer-events-none absolute inset-0 z-10 select-none overflow-hidden"
    >
      <div className="absolute -inset-1/2 flex rotate-[-24deg] flex-wrap content-start gap-x-16 gap-y-14 opacity-[0.13]">
        {Array.from({ length: 60 }).map((_, i) => (
          <span key={i} className="whitespace-nowrap font-mono text-xs font-semibold text-white">
            {label}
          </span>
        ))}
      </div>
    </div>
  );
}
