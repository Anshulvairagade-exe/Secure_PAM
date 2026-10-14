import { useRef, useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Download, ListTree, PlayCircle } from 'lucide-react';
import { recordingsApi, sessionsApi } from '@/api';
import { getApiErrorMessage } from '@/api/errors';
import { EmptyState, ErrorBanner, Skeleton } from '@/components/Feedback';
import CastPlayer, { type CastPlayerHandle } from '@/components/CastPlayer';
import TranscriptPanel from '@/components/TranscriptPanel';
import RdpRecordingPlayer from '@/components/RdpRecordingPlayer';
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
  no_display_data: ['badge-danger', 'No display data'],
};

const TYPE_LABEL: Record<string, string> = {
  TERMINAL: 'Terminal replay (SSH)',
  VIDEO: 'Screen recording (RDP)',
  HTTP: 'Web session',
};

function bytes(n?: number) {
  if (n == null) return '—';
  return n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
}

export default function Recordings() {
  const { user, hasPermission } = useAuth();
  const playerRef = useRef<CastPlayerHandle>(null);
  const [page, setPage] = useState(1);
  const [open, setOpen] = useState<{ recording: Recording; cast: string | null; screen?: Blob } | null>(null);
  // Drill-down: which recording's session the reviewer is inspecting.
  const [inspected, setInspected] = useState<Recording | null>(null);

  const list = useQuery({
    queryKey: ['recordings', page],
    queryFn: () => recordingsApi.list({ page, page_size: 20 }),
  });

  // Fetched in the browser only to show what the session was — status,
  // operator, target, times and failure reason. Read-only; auditors and
  // admins already hold sessions:read.
  const session = useQuery({
    queryKey: ['session', inspected?.session_id],
    queryFn: () => sessionsApi.get(inspected!.session_id),
    enabled: inspected !== null,
  });

  const play = useMutation({
    mutationFn: async (recording: Recording) =>
      recording.format === 'guacamole'
        ? { recording, cast: null, screen: await recordingsApi.guacamoleRecording(recording.id) }
        : { recording, cast: await recordingsApi.terminalCast(recording.id) },
    onSuccess: setOpen,
  });

  const download = () => {
    if (!open?.cast) return;
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

      {inspected && (
        <section className="card space-y-2 p-5" aria-live="polite">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-gray-200">
              Session {inspected.session_number ?? inspected.session_id.slice(0, 8)}
            </h2>
            <button className="btn-ghost px-3 py-1.5 text-sm" onClick={() => setInspected(null)}>Close</button>
          </div>
          {session.isLoading ? (
            <Skeleton className="h-10" />
          ) : session.isError ? (
            <ErrorBanner message={getApiErrorMessage(session.error, 'The session could not be loaded.')} />
          ) : session.data ? (
            <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-sm md:grid-cols-3">
              <div><dt className="text-xs text-gray-500">Status</dt><dd><span className="badge-neutral">{session.data.status}</span></dd></div>
              <div><dt className="text-xs text-gray-500">Operator</dt><dd className="font-mono text-xs text-gray-300">{session.data.user_id.slice(0, 8)}</dd></div>
              <div><dt className="text-xs text-gray-500">Target</dt><dd className="text-gray-300">{session.data.asset_name ?? '—'} · {session.data.protocol}</dd></div>
              <div><dt className="text-xs text-gray-500">Started</dt><dd className="text-gray-300">{session.data.start_time ? new Date(session.data.start_time).toLocaleString() : '—'}</dd></div>
              <div><dt className="text-xs text-gray-500">Ended</dt><dd className="text-gray-300">{session.data.end_time ? new Date(session.data.end_time).toLocaleString() : '—'}</dd></div>
              <div><dt className="text-xs text-gray-500">Grant</dt><dd className="font-mono text-xs text-gray-300">{session.data.jit_grant_id?.slice(0, 8) ?? '—'}</dd></div>
              {session.data.failure_message && (
                <div className="col-span-full"><dt className="text-xs text-gray-500">Failure</dt><dd className="text-amber-300">{session.data.failure_message}</dd></div>
              )}
            </dl>
          ) : null}
        </section>
      )}

      {open && user && (
        <section className="card space-y-4 p-5" aria-label="Recording viewer">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-gray-200">
              {open.recording.session_number} · {open.recording.operator_username} on {open.recording.asset_name}
            </h2>
            <div className="flex gap-2">
              {open.cast && hasPermission('recordings:download') && (
                <button className="btn-secondary px-3 py-1.5 text-sm" onClick={download}>
                  <Download size={14} /> Download .cast
                </button>
              )}
              <button className="btn-ghost px-3 py-1.5 text-sm" onClick={() => setOpen(null)}>Close</button>
            </div>
          </div>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-sm md:grid-cols-4">
            <div><dt className="text-xs text-gray-500">Operator</dt><dd className="text-gray-300">{open.recording.operator_username ?? '—'}</dd></div>
            <div><dt className="text-xs text-gray-500">Target</dt><dd className="text-gray-300">{open.recording.asset_name ?? '—'} · {open.recording.protocol ?? '—'}</dd></div>
            <div><dt className="text-xs text-gray-500">Started</dt><dd className="text-gray-300">{open.recording.started_at ? new Date(open.recording.started_at).toLocaleString() : '—'}</dd></div>
            <div><dt className="text-xs text-gray-500">Ended · duration</dt><dd className="text-gray-300">{open.recording.ended_at ? new Date(open.recording.ended_at).toLocaleString() : '—'} · {open.recording.duration_seconds != null ? `${open.recording.duration_seconds}s` : '—'}</dd></div>
          </dl>
          <p className="font-mono text-xs text-gray-500">
            {INTEGRITY[open.recording.integrity][1]} · sha256 {open.recording.sha256 ?? '—'}
          </p>
          {open.screen ? (
            <>
              <p className="text-xs text-gray-500">
                Screen recording of the remote Windows desktop (captured by the RDP gateway). It shows what was on
                screen; it does not by itself prove which commands were run.
              </p>
              <RdpRecordingPlayer blob={open.screen} viewer={user.username} label={`playback of ${open.recording.session_number}`} />
            </>
          ) : open.cast ? (
            <>
              <p className="text-xs text-gray-500">
                Terminal replay of the recorded SSH session output. This is a text terminal recording, not a desktop video.
              </p>
              <CastPlayer ref={playerRef} cast={open.cast} viewer={user.username} label={`playback of ${open.recording.session_number}`} />
            </>
          ) : (
            <p className="text-xs text-gray-500">Transcript only. Use Play on the row to replay the recording.</p>
          )}
          <TranscriptPanel
            recordingId={open.recording.id}
            canExport={hasPermission('recordings:download')}
            onSeek={(t) => playerRef.current?.seek(t)}
          />
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
                  const playable = r.status === 'COMPLETED' && r.integrity === 'verified'
                    && (r.recording_type === 'TERMINAL' || r.format === 'guacamole');
                  return (
                    <tr key={r.id}>
                      <td>
                        <button
                          className="font-mono text-xs text-blue-400 hover:text-blue-300 hover:underline"
                          onClick={() => setInspected(r)}
                          title="Show what this session was"
                        >
                          {r.session_number ?? r.session_id.slice(0, 8)}
                        </button>
                      </td>
                      <td className="text-gray-300">{r.operator_username ?? '—'}</td>
                      <td className="text-gray-300">{r.asset_name ?? '—'}</td>
                      <td className="text-gray-400">{TYPE_LABEL[r.recording_type] ?? r.recording_type}</td>
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
                        {r.transcript_available && (
                          <button className="btn-ghost px-2 py-1 text-xs" onClick={() => setOpen({ recording: r, cast: null })}>
                            <ListTree size={14} /> Transcript
                          </button>
                        )}
                        {r.recording_type === 'VIDEO' && !playable && (
                          <span className="text-xs text-gray-500" title="Only recordings with a verified artifact can be played">
                            {r.status === 'FAILED' ? 'no usable artifact' : 'not playable'}
                          </span>
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
