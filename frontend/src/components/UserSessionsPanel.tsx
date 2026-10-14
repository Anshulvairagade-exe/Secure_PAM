import { useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { jitGrantsApi, sessionsApi, usersApi } from '@/api';
import { getApiErrorMessage } from '@/api/errors';
import { EmptyState, ErrorBanner, Skeleton } from '@/components/Feedback';
import Modal from '@/components/Modal';
import type { TerminationOutcome, UserSession } from '@/types';
import { LIVE_SESSION_STATUSES, SESSION_STATUS_BADGE, SESSION_STATUS_LABEL, sessionDuration } from '@/utils/sessionStatus';

type Confirm =
  | { kind: 'session'; session: UserSession }
  | { kind: 'all' }
  | { kind: 'grant'; id: string; label: string };

const GATEWAY_TEXT: Record<string, string> = {
  closed: 'gateway connection closed',
  not_connected: 'no gateway connection existed',
  delegated: 'connection owned by another worker; it closes it within a second',
  failed: 'gateway connection could NOT be closed',
};

function Outcome({ o }: { o: TerminationOutcome }) {
  return (
    <li className={o.ok ? 'text-gray-300' : 'text-red-400'}>
      <span className="font-mono">{o.session_number}</span>: {o.ok ? 'terminated' : `still ${o.status}`} · {GATEWAY_TEXT[o.gateway]}
      {o.recording && ` · recording ${o.recording}`}
      {o.grant_revoked != null && ` · grant ${o.grant_revoked ? 'revoked' : 'not revoked'}`}
      {o.errors.map((e) => <span key={e} className="block">{e}</span>)}
    </li>
  );
}

/** An administrator's view of one user's sessions (live and past) and unused approved grants. */
export default function UserSessionsPanel({ userId, onClose }: { userId: string; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const [reason, setReason] = useState('');
  const [outcome, setOutcome] = useState<{ complete: boolean; items: TerminationOutcome[]; note?: string } | null>(null);
  const [now] = useState(Date.now());
  // Set synchronously on click: isPending only flips on the next render, so a fast second
  // click could otherwise fire the same termination twice.
  const inFlight = useRef(false);

  const access = useQuery({ queryKey: ['user-access', userId], queryFn: () => usersApi.access(userId), refetchInterval: 5000 });

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ['user-access'] });
    void queryClient.invalidateQueries({ queryKey: ['users'] });
    void queryClient.invalidateQueries({ queryKey: ['sessions'] });
  };

  const act = useMutation({
    mutationFn: async (c: Confirm) => {
      const why = reason.trim() || undefined;
      if (c.kind === 'session') {
        const r = await sessionsApi.terminate(c.session.id, why);
        return { complete: r.complete as boolean, items: [r.result as TerminationOutcome] };
      }
      if (c.kind === 'all') {
        const r = await usersApi.terminateAll(userId, why);
        return { complete: r.complete, items: r.results };
      }
      await jitGrantsApi.revoke(c.id);
      return { complete: true, items: [], note: `Grant for ${c.label} revoked. It can no longer start a session.` };
    },
    onSuccess: (data) => { setOutcome(data); setConfirm(null); setReason(''); refresh(); },
    onError: (error) => {
      setOutcome({ complete: false, items: [], note: getApiErrorMessage(error, 'The action failed.') });
      setConfirm(null);
      refresh();
    },
    onSettled: () => { inFlight.current = false; },
  });
  const start = (c: Confirm) => {
    if (inFlight.current) return;
    inFlight.current = true;
    act.mutate(c);
  };

  const d = access.data;
  const live = d?.sessions.filter((s) => LIVE_SESSION_STATUSES.has(s.status)) ?? [];

  return (
    <section className="card space-y-5 p-5" aria-label="User sessions">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-gray-100">
          Sessions of <span className="font-mono">{d?.username ?? '…'}</span>
          {d && <span className="ml-2 text-xs font-normal text-gray-500">{d.active_sessions} of {d.session_limit} concurrent sessions in use</span>}
        </h2>
        <div className="flex gap-2">
          <button
            className="btn-secondary px-3 py-1.5 text-sm hover:text-red-400"
            disabled={live.length === 0 || act.isPending}
            onClick={() => setConfirm({ kind: 'all' })}
          >
            Terminate all sessions
          </button>
          <button className="btn-ghost px-3 py-1.5 text-sm" onClick={onClose}>Close</button>
        </div>
      </div>

      {access.isError && <ErrorBanner message={getApiErrorMessage(access.error, 'Sessions could not be loaded.')} />}
      {outcome && (
        <div
          role="status"
          className={`rounded-lg border px-4 py-3 text-sm ${outcome.complete ? 'border-green-500/30 bg-green-500/10 text-green-300' : 'border-red-500/30 bg-red-500/10 text-red-300'}`}
        >
          <p className="font-medium">
            {outcome.note ?? (outcome.complete ? 'Done.' : 'Not everything could be completed. Sessions listed below were not fully terminated.')}
          </p>
          {outcome.items.length > 0 && <ul className="mt-1 space-y-0.5 text-xs">{outcome.items.map((o) => <Outcome key={o.session_id} o={o} />)}</ul>}
        </div>
      )}

      {access.isLoading ? <Skeleton className="h-24" /> : d && (
        <>
          <div>
            <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">Sessions</h3>
            {d.sessions.length === 0 ? (
              <EmptyState message="This user has not started any sessions." />
            ) : (
              <div className="table-container">
                <table className="table">
                  <thead>
                    <tr><th>Session</th><th>Target</th><th>Protocol</th><th>Status</th><th>Started</th><th>Duration</th><th>Recording</th><th></th></tr>
                  </thead>
                  <tbody>
                    {d.sessions.map((s) => (
                      <tr key={s.id}>
                        <td className="font-mono text-xs text-gray-400">{s.session_number}</td>
                        <td className="text-gray-300">{s.asset_name ?? '—'}</td>
                        <td className="text-gray-400">{s.protocol}</td>
                        <td><span className={SESSION_STATUS_BADGE[s.status] ?? 'badge-neutral'}>{SESSION_STATUS_LABEL[s.status] ?? s.status}</span></td>
                        <td className="whitespace-nowrap text-gray-500">{s.start_time ? new Date(s.start_time).toLocaleString() : '—'}</td>
                        <td className="text-gray-400">{sessionDuration(s.start_time, s.end_time, now)}</td>
                        <td className="text-gray-400">{s.recording_status ?? 'not required'}</td>
                        <td className="text-right">
                          {LIVE_SESSION_STATUSES.has(s.status) && (
                            <button
                              className="btn-ghost px-2 py-1 text-xs hover:text-red-400"
                              disabled={act.isPending}
                              onClick={() => setConfirm({ kind: 'session', session: s })}
                            >
                              {s.status === 'TERMINATING' ? 'Retry terminate' : 'Terminate'}
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div>
            <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">
              Ready to connect <span className="normal-case text-gray-600">· approved grants not in use; not sessions</span>
            </h3>
            {d.ready_grants.length === 0 ? (
              <p className="text-xs text-gray-500">No unused approved grants.</p>
            ) : (
              <ul className="divide-y divide-navy-800">
                {d.ready_grants.map((g) => (
                  <li key={g.id} className="flex items-center justify-between gap-3 py-2 text-sm">
                    <span className="text-gray-300">
                      {g.asset_name ?? 'Target'} · {g.protocol}
                      <span className="ml-2 text-xs text-gray-500">{g.request_number} · expires {new Date(g.expires_at).toLocaleTimeString()}</span>
                    </span>
                    <button
                      className="btn-ghost px-2 py-1 text-xs hover:text-red-400"
                      disabled={act.isPending}
                      onClick={() => setConfirm({ kind: 'grant', id: g.id, label: `${g.asset_name ?? 'target'} (${g.request_number})` })}
                    >
                      Revoke grant
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </>
      )}

      {confirm && (
        <Modal title="Confirm" onClose={() => !act.isPending && setConfirm(null)}>
          <div className="space-y-4">
            <p className="text-sm text-gray-300">
              {confirm.kind === 'session' && <>Terminate session <span className="font-mono">{confirm.session.session_number}</span>? The live connection is closed, the recording is finalized and the grant that authorized it is revoked.</>}
              {confirm.kind === 'all' && <>Terminate all {live.length} live session(s) of <span className="font-mono">{d?.username}</span> and revoke the grants that authorized them? Unused approved grants are not affected.</>}
              {confirm.kind === 'grant' && <>Revoke the approved grant for {confirm.label}? It can never start a session afterwards.</>}
            </p>
            {confirm.kind !== 'grant' && (
              <input
                className="input" placeholder="Reason (recorded in the audit log)" maxLength={300}
                aria-label="Reason" value={reason} onChange={(e) => setReason(e.target.value)}
              />
            )}
            <div className="flex justify-end gap-2">
              <button className="btn-ghost" disabled={act.isPending} onClick={() => setConfirm(null)}>Cancel</button>
              <button className="btn-primary bg-red-600 hover:bg-red-500" disabled={act.isPending} onClick={() => start(confirm)}>
                {act.isPending ? 'Working…' : confirm.kind === 'grant' ? 'Revoke' : 'Terminate'}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </section>
  );
}
