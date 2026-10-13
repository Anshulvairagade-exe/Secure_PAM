import { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Download, PlayCircle } from 'lucide-react';
import { recordingsApi } from '@/api';
import { getApiErrorMessage } from '@/api/errors';
import { EmptyState, ErrorBanner, Skeleton } from '@/components/Feedback';
import CastPlayer from '@/components/CastPlayer';
import { useAuth } from '@/hooks/useAuth';
import type { Recording } from '@/types';

const STATUS_BADGE: Record<Recording['status'], string> = {
  PENDING: 'badge-warning',
  RECORDING: 'badge-danger',
  COMPLETED: 'badge-success',
  FAILED: 'badge-danger',
  DELETED: 'badge-neutral',
};

const INTEGRITY: Record<Recording['integrity'], [string, string]> = {
  verified: ['badge-success', 'SHA-256 verified'],
  mismatch: ['badge-danger', 'Integrity FAILED'],
  missing: ['badge-danger', 'Artifact missing'],
  not_available: ['badge-neutral', 'No artifact'],
};

function bytes(n?: number) {
  if (n == null) return '—';
  return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
}

export default function Recordings() {
  const { user } = useAuth();
  const [page, setPage] = useState(1);
  const [open, setOpen] = useState<{ recording: Recording; cast: string } | null>(null);

  const list = useQuery({
    queryKey: ['recordings', page],
    queryFn: () => recordingsApi.list({ page, page_size: 20 }),
  });

  const play = useMutation({
    mutationFn: async (recording: Recording) => ({ recording, cast: await recordingsApi.terminalCast(recording.id) }),
    onSuccess: setOpen,
  });

  const download = () => {
    if (!open) return;
    const url = URL.createObjectURL(new Blob([open.cast], { type: 'application/x-asciicast' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `${open.recording.session_number ?? open.recording.id}.cast`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-gray-100">Recording Center</h1>
        <p className="mt-0.5 text-sm text-gray-500">
          Server-side session recordings. Playback is served only after the stored SHA-256 is re-verified, and every
          view is audited.
        </p>
      </div>

      {list.isError && <ErrorBanner message={getApiErrorMessage(list.error, 'Failed to load recordings.')} />}
      {play.isError && <ErrorBanner message={getApiErrorMessage(play.error, 'The recording could not be played.')} />}

      {open && user && (
        <section className="card space-y-3 p-5">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-gray-200">
              {open.recording.session_number} · {open.recording.operator_username} on {open.recording.asset_name}
            </h2>
            <div className="flex gap-2">
              <button className="btn-secondary px-3 py-1.5 text-sm" onClick={download}>
                <Download size={14} /> Download .cast
              </button>
              <button className="btn-ghost px-3 py-1.5 text-sm" onClick={() => setOpen(null)}>Close</button>
            </div>
          </div>
          <p className="font-mono text-xs text-gray-500">sha256 {open.recording.sha256}</p>
          <CastPlayer cast={open.cast} viewer={user.username} label={`playback of ${open.recording.session_number}`} />
        </section>
      )}

      <div className="card overflow-hidden">
        {list.isLoading ? (
          <div className="space-y-2 p-4">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-10" />)}</div>
        ) : !list.data || list.data.items.length === 0 ? (
          <EmptyState message="No recordings yet. Sessions on targets that require recording appear here." />
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Session</th><th>Operator</th><th>Target</th><th>Type</th><th>Status</th>
                  <th>Started</th><th>Ended</th><th>Duration</th><th>Size</th><th>Integrity</th><th></th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((r) => {
                  const [badge, label] = INTEGRITY[r.integrity] ?? INTEGRITY.not_available;
                  const playable = r.status === 'COMPLETED' && r.recording_type === 'TERMINAL' && r.integrity === 'verified';
                  return (
                    <tr key={r.id}>
                      <td className="font-mono text-xs text-gray-400">{r.session_number ?? r.session_id.slice(0, 8)}</td>
                      <td className="text-gray-300">{r.operator_username ?? '—'}</td>
                      <td className="text-gray-300">{r.asset_name ?? '—'}</td>
                      <td className="text-gray-400">{r.recording_type}</td>
                      <td><span className={STATUS_BADGE[r.status]}>{r.status}</span></td>
                      <td className="whitespace-nowrap text-gray-500">{r.started_at ? new Date(r.started_at).toLocaleString() : '—'}</td>
                      <td className="whitespace-nowrap text-gray-500">{r.ended_at ? new Date(r.ended_at).toLocaleString() : '—'}</td>
                      <td className="text-gray-400">{r.duration_seconds != null ? `${r.duration_seconds}s` : '—'}</td>
                      <td className="text-gray-400">{bytes(r.file_size)}</td>
                      <td><span className={badge}>{label}</span></td>
                      <td className="text-right">
                        {playable && (
                          <button className="btn-ghost px-2 py-1 text-xs" disabled={play.isPending} onClick={() => play.mutate(r)}>
                            <PlayCircle size={14} /> Play
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {list.data && list.data.pages > 1 && (
        <div className="flex items-center justify-between text-sm text-gray-500">
          <span>Page {list.data.page} of {list.data.pages}</span>
          <div className="flex gap-2">
            <button className="btn-secondary" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</button>
            <button className="btn-secondary" disabled={page >= list.data.pages} onClick={() => setPage((p) => p + 1)}>Next</button>
          </div>
        </div>
      )}
    </div>
  );
}
