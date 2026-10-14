import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Download, Search } from 'lucide-react';
import { recordingsApi } from '@/api';
import { getApiErrorMessage } from '@/api/errors';
import { EmptyState, ErrorBanner, Skeleton } from '@/components/Feedback';

export function formatClock(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds));
  return `${Math.floor(s / 60).toString().padStart(2, '0')}:${(s % 60).toString().padStart(2, '0')}`;
}

/**
 * Activity transcript beneath the replay: what the operator typed (as observed
 * at the gateway) and the output that followed, on the recording's timeline.
 * It never claims execution was verified; the server says what it can't prove.
 */
export default function TranscriptPanel({
  recordingId, canExport, onSeek,
}: { recordingId: string; canExport: boolean; onSeek: (seconds: number) => void }) {
  const [filter, setFilter] = useState('');
  const query = useQuery({
    queryKey: ['transcript', recordingId],
    queryFn: () => recordingsApi.transcript(recordingId),
    retry: false,
  });
  const exporter = useMutation({
    mutationFn: () => recordingsApi.exportTranscript(recordingId),
    onSuccess: (text) => {
      const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = `${query.data?.session_number ?? recordingId}-transcript.json`;
      link.click();
      URL.revokeObjectURL(url);
    },
  });

  const events = query.data?.transcript?.events ?? [];
  const needle = filter.trim().toLowerCase();
  const shown = needle
    ? events.filter((e) => e.input.toLowerCase().includes(needle) || e.output.toLowerCase().includes(needle))
    : events;

  return (
    <section className="space-y-3" aria-label="Activity transcript">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-semibold text-gray-200">Activity transcript</h3>
        <div className="flex items-center gap-2">
          <label className="relative">
            <Search size={14} className="pointer-events-none absolute left-2 top-2.5 text-gray-500" />
            <input
              className="input w-52 pl-7" placeholder="Search commands and output" value={filter}
              aria-label="Search transcript" onChange={(e) => setFilter(e.target.value)}
            />
          </label>
          {canExport && query.data?.available && (
            <button className="btn-secondary px-3 py-1.5 text-sm" disabled={exporter.isPending} onClick={() => exporter.mutate()}>
              <Download size={14} /> Export JSON
            </button>
          )}
        </div>
      </div>

      {query.isLoading && <Skeleton className="h-24" />}
      {query.isError && <ErrorBanner message={getApiErrorMessage(query.error, 'The transcript could not be loaded.')} />}
      {exporter.isError && <ErrorBanner message={getApiErrorMessage(exporter.error, 'The transcript could not be exported.')} />}
      {query.data && !query.data.available && (
        <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-300">
          No transcript: {query.data.reason}
        </p>
      )}
      {query.data?.transcript && (
        <>
          <p className="text-xs text-gray-500">{query.data.transcript.limitations}</p>
          {events.length === 0 ? (
            <EmptyState message="The operator entered no commands in this session." />
          ) : shown.length === 0 ? (
            <EmptyState message="No transcript entries match your search." />
          ) : (
            <ol className="divide-y divide-navy-800 rounded-lg border border-navy-700">
              {shown.map((e) => (
                <li key={e.seq}>
                  <button
                    className="block w-full px-3 py-2 text-left hover:bg-navy-800/50"
                    onClick={() => onSeek(Math.max(0, e.t - 0.5))}
                    title="Jump the replay to this entry"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs text-blue-400">{formatClock(e.t)}</span>
                      <code className="font-mono text-sm text-gray-100">$ {e.input}</code>
                      <span className="badge-neutral">observed input</span>
                      {e.confidence === 'low' && (
                        <span className="badge-warning" title="Tab completion, history or a secret prompt means the typed text may not match what ran">low confidence</span>
                      )}
                      {e.masked && <span className="badge-info">masked</span>}
                      {e.redacted && <span className="badge-info">redacted</span>}
                    </div>
                    {e.output && (
                      <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-words rounded bg-navy-950/60 p-2 font-mono text-xs text-gray-400">
                        {e.output}{e.output_truncated ? '\n… output truncated' : ''}
                      </pre>
                    )}
                  </button>
                </li>
              ))}
            </ol>
          )}
        </>
      )}
    </section>
  );
}
