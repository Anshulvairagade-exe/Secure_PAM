import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { jitGrantsApi, sessionsApi } from '@/api';
import { getApiErrorMessage } from '@/api/errors';
import { EmptyState, ErrorBanner, Skeleton } from '@/components/Feedback';
import type { Session } from '@/types';
import { LIVE_SESSION_STATUSES, SESSION_STATUS_BADGE } from '@/utils/sessionStatus';

function elapsed(start?: string, end?: string, now = Date.now()): string {
  if (!start) return '—';
  const seconds = Math.max(0, Math.floor(((end ? Date.parse(end) : now) - Date.parse(start)) / 1000));
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return h ? `${h}h ${m}m` : `${m}m ${s.toString().padStart(2, '0')}s`;
}

/**
 * All sessions, every operator (ADMIN only — the backend scopes the list by
 * sessions:read). Terminating closes the live gateway connection and
 * completes the recording; revoking the JIT grant additionally kills the
 * underlying access so the approved request cannot be reused. Both steps
 * are audited server-side.
 */
export default function AdminSessions() {
  const queryClient = useQueryClient();
  const [page, setPage] = useState(1);
  const [notice, setNotice] = useState<string | null>(null);

  const sessions = useQuery({
    queryKey: ['sessions', 'all', page],
    queryFn: () => sessionsApi.list({ page, page_size: 20 }),
    refetchInterval: 5000,
  });
  const refresh = () => void queryClient.invalidateQueries({ queryKey: ['sessions'] });

  const terminate = useMutation({
    mutationFn: (id: string) => sessionsApi.terminate(id),
    onSuccess: refresh,
  });
  const revoke = useMutation({
    mutationFn: (grantId: string) => jitGrantsApi.revoke(grantId),
    onSuccess: refresh,
  });

  const terminateAndRevoke = async (s: Session) => {
    setNotice(null);
    try {
      await terminate.mutateAsync(s.id);
      if (s.jit_grant_id) {
        const result = await revoke.mutateAsync(s.jit_grant_id);
        setNotice(
          `Session ${s.session_number} terminated; its grant is ${result.status} ` +
          `(${result.sessions_ended} live session${result.sessions_ended === 1 ? '' : 's'} ended).`,
        );
      } else {
        setNotice(`Session ${s.session_number} terminated.`);
      }
    } catch (error) {
      setNotice(null);
    }
    refresh();
  };

  const revokeOnly = async (s: Session) => {
    if (!s.jit_grant_id) return;
    setNotice(null);
    try {
      const result = await revoke.mutateAsync(s.jit_grant_id);
      setNotice(
        `Grant for session ${s.session_number} is ${result.status} ` +
        `(${result.sessions_ended} live session${result.sessions_ended === 1 ? '' : 's'} ended).`,
      );
    } catch {
      /* surfaced below */
    }
    refresh();
  };

  const actionError = terminate.error ?? revoke.error;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-gray-100">All Sessions</h1>
        <p className="mt-0.5 text-sm text-gray-500">
          Every operator's sessions. Terminating ends the live connection; revoking the grant additionally
          removes the underlying access so it cannot be reused. Termination is immediate — the operator is
          disconnected without warning.
        </p>
      </div>

      {sessions.isError && <ErrorBanner message={getApiErrorMessage(sessions.error, 'Failed to load sessions.')} />}
      {actionError && <ErrorBanner message={getApiErrorMessage(actionError, 'The action could not be completed.')} />}
      {notice && <p className="rounded-md border border-green-500/20 bg-green-500/10 px-4 py-2 text-sm text-green-300" role="status">{notice}</p>}

      <div className="card overflow-hidden">
        {sessions.isLoading ? (
          <div className="space-y-2 p-4">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-10" />)}</div>
        ) : !sessions.data || sessions.data.items.length === 0 ? (
          <EmptyState message="No sessions yet." />
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Session</th><th>Operator</th><th>Target</th><th>Protocol</th><th>Status</th>
                  <th>Started</th><th>Duration</th><th></th>
                </tr>
              </thead>
              <tbody>
                {sessions.data.items.map((s) => (
                  <tr key={s.id}>
                    <td className="font-mono text-xs text-gray-400">{s.session_number}</td>
                    <td className="font-mono text-xs text-gray-400" title={s.user_id}>{s.user_id.slice(0, 8)}</td>
                    <td className="text-gray-300">{s.asset_name ?? '—'}</td>
                    <td className="text-gray-400">{s.protocol}</td>
                    <td><span className={SESSION_STATUS_BADGE[s.status] ?? 'badge-neutral'}>{s.status}</span></td>
                    <td className="whitespace-nowrap text-gray-500">{s.start_time ? new Date(s.start_time).toLocaleString() : '—'}</td>
                    <td className="text-gray-400">{elapsed(s.start_time, s.end_time)}</td>
                    <td className="text-right">
                      {LIVE_SESSION_STATUSES.has(s.status) ? (
                        <button
                          className="btn-ghost px-2 py-1 text-xs hover:text-red-400"
                          disabled={terminate.isPending || revoke.isPending}
                          onClick={() => void terminateAndRevoke(s)}
                          title="End the live connection, complete the recording, and revoke the JIT grant"
                        >
                          Terminate + revoke
                        </button>
                      ) : s.jit_grant_id ? (
                        <button
                          className="btn-ghost px-2 py-1 text-xs hover:text-red-400"
                          disabled={revoke.isPending}
                          onClick={() => void revokeOnly(s)}
                          title="Revoke the JIT grant so this approval cannot be reused"
                        >
                          Revoke grant
                        </button>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {sessions.data && sessions.data.pages > 1 && (
        <div className="flex items-center justify-between text-sm text-gray-500">
          <span>Page {sessions.data.page} of {sessions.data.pages}</span>
          <div className="flex gap-2">
            <button className="btn-secondary" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</button>
            <button className="btn-secondary" disabled={sessions.data && page >= sessions.data.pages} onClick={() => setPage((p) => p + 1)}>Next</button>
          </div>
        </div>
      )}
    </div>
  );
}
