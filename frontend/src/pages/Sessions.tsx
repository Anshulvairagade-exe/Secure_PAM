import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import { MonitorPlay, Plus, TerminalSquare } from 'lucide-react';
import { accessRequestsApi, assetsApi, sessionsApi } from '@/api';
import { getApiErrorMessage } from '@/api/errors';
import { EmptyState, ErrorBanner, Skeleton } from '@/components/Feedback';
import SshTerminal from '@/components/SshTerminal';
import { useAuth } from '@/hooks/useAuth';
import type { AccessRequest, Asset, Session, SSHLaunchResponse } from '@/types';

const LIVE = new Set(['CREATED', 'STARTING', 'ACTIVE']);

const STATUS_BADGE: Record<string, string> = {
  STARTING: 'badge-warning',
  ACTIVE: 'badge-success',
  COMPLETED: 'badge-neutral',
  EXPIRED: 'badge-neutral',
  FAILED: 'badge-danger',
  CREATED: 'badge-neutral',
  TERMINATING: 'badge-warning',
};

const RECORDING_BADGE: Record<string, string> = {
  RECORDING: 'badge-danger',
  COMPLETED: 'badge-success',
  FAILED: 'badge-danger',
  PENDING: 'badge-warning',
};

function elapsed(start?: string, end?: string, now = Date.now()): string {
  if (!start) return '—';
  const seconds = Math.max(0, Math.floor(((end ? Date.parse(end) : now) - Date.parse(start)) / 1000));
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return h ? `${h}h ${m}m` : `${m}m ${s.toString().padStart(2, '0')}s`;
}

/** Why a protocol cannot be launched in this deployment, or null when it can. */
export function gatewayUnavailableReason(protocol: string): string | null {
  if (protocol === 'SSH') return null;
  if (protocol === 'RDP') return 'RDP gateway (Guacamole) is not deployed; RDP sessions cannot connect.';
  return 'Web gateway is not deployed; web sessions cannot connect.';
}

export default function Sessions() {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [live, setLive] = useState<SSHLaunchResponse | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const sessions = useQuery({
    queryKey: ['sessions', 'mine'],
    queryFn: () => sessionsApi.list({ page: 1, page_size: 25 }),
    refetchInterval: 5000,
  });
  const activeRequests = useQuery({
    queryKey: ['access-requests', { status: 'ACTIVE' }],
    queryFn: () => accessRequestsApi.list({ page: 1, page_size: 50, status: 'ACTIVE' }),
  });
  const assets = useQuery({
    queryKey: ['assets', { page_size: 100 }],
    queryFn: () => assetsApi.list({ page: 1, page_size: 100 }),
  });
  // The grant (status, expiry) is only on the request detail.
  const details = useQueries({
    queries: (activeRequests.data?.items ?? [])
      .filter((r) => r.user_id === user?.id)
      .map((r) => ({ queryKey: ['access-request', r.id], queryFn: () => accessRequestsApi.get(r.id) })),
  });

  const assetById = new Map<string, Asset>((assets.data?.items ?? []).map((a) => [a.id, a]));
  const eligible: AccessRequest[] = details
    .map((d) => d.data)
    .filter((r): r is AccessRequest => !!r && r.status === 'ACTIVE' && r.jit_grant?.status === 'ACTIVE');

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ['sessions'] });
    void queryClient.invalidateQueries({ queryKey: ['access-request'] });
  };

  const launch = useMutation({
    mutationFn: (req: AccessRequest) => sessionsApi.launchSSH(req.id, req.asset_id!),
    onSuccess: (data) => { setActionError(null); setLive(data); refresh(); },
    onError: (error) => setActionError(getApiErrorMessage(error, 'The session could not be launched.')),
  });
  const terminate = useMutation({
    mutationFn: (id: string) => sessionsApi.terminate(id),
    onSuccess: () => { setActionError(null); refresh(); },
    onError: (error) => setActionError(getApiErrorMessage(error, 'The session could not be terminated.')),
  });

  const loadError = sessions.error ?? activeRequests.error ?? assets.error;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-gray-100">My Sessions</h1>
        <p className="mt-0.5 text-sm text-gray-500">
          Privileged sessions run through the SecurePAM gateway. Credentials are injected server-side and never
          reach this browser.
        </p>
      </div>

      {loadError && <ErrorBanner message={getApiErrorMessage(loadError, 'Failed to load sessions.')} />}
      {actionError && <ErrorBanner message={actionError} />}

      <section className="card p-5">
        <h2 className="mb-3 text-sm font-semibold text-gray-200">Ready to connect</h2>
        {activeRequests.isLoading || details.some((d) => d.isLoading) ? (
          <Skeleton className="h-12" />
        ) : eligible.length === 0 ? (
          <div className="flex items-center justify-between gap-4 text-sm text-gray-500">
            <span>No approved request with an active just-in-time grant.</span>
            <Link to="/access-requests/new" className="btn-primary"><Plus size={16} /> Request access</Link>
          </div>
        ) : (
          <ul className="divide-y divide-navy-800">
            {eligible.map((req) => {
              const asset = req.asset_id ? assetById.get(req.asset_id) : undefined;
              const unavailable = gatewayUnavailableReason(req.protocol);
              return (
                <li key={req.id} className="flex items-center justify-between gap-4 py-3">
                  <div className="min-w-0">
                    <p className="font-medium text-gray-200">{asset?.name ?? 'Target'} · {req.protocol}</p>
                    <p className="text-xs text-gray-500">
                      {req.request_number} · grant expires {new Date(req.jit_grant!.expires_at).toLocaleTimeString()}
                    </p>
                  </div>
                  {unavailable ? (
                    <span className="max-w-sm text-right text-xs text-amber-300">{unavailable}</span>
                  ) : (
                    <button
                      className="btn-primary"
                      disabled={launch.isPending || !!live}
                      onClick={() => launch.mutate(req)}
                    >
                      <TerminalSquare size={16} /> {launch.isPending ? 'Launching...' : 'Connect'}
                    </button>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </section>

      {live && user && (
        <section className="card space-y-3 p-5">
          <div className="flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-gray-200">
              <MonitorPlay size={16} /> {live.session_number}
            </h2>
            <div className="flex gap-2">
              <button
                className="btn-secondary px-3 py-1.5 text-sm hover:text-red-400"
                disabled={terminate.isPending}
                onClick={() => terminate.mutate(live.session_id)}
              >
                Terminate session
              </button>
              <button className="btn-ghost px-3 py-1.5 text-sm" onClick={() => { setLive(null); refresh(); }}>
                Close panel
              </button>
            </div>
          </div>
          <SshTerminal
            key={live.session_id}
            sessionId={live.session_id}
            sessionNumber={live.session_number}
            ticket={live.ticket}
            username={user.username}
            onStateChange={(state) => { if (state === 'closed' || state === 'error') refresh(); }}
          />
        </section>
      )}

      <section className="card overflow-hidden">
        <h2 className="px-5 pt-5 text-sm font-semibold text-gray-200">Your sessions</h2>
        {sessions.isLoading ? (
          <div className="space-y-2 p-4">{Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-10" />)}</div>
        ) : !sessions.data || sessions.data.items.length === 0 ? (
          <EmptyState message="No sessions yet. Connect from an approved request above." />
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Session</th><th>Target</th><th>Protocol</th><th>Status</th><th>Started</th>
                  <th>Duration</th><th>Recording</th><th></th>
                </tr>
              </thead>
              <tbody>
                {sessions.data.items.map((s: Session) => (
                  <tr key={s.id}>
                    <td className="font-mono text-xs text-gray-400">{s.session_number}</td>
                    <td className="text-gray-300">{s.asset_name ?? '—'}</td>
                    <td className="text-gray-400">{s.protocol}</td>
                    <td>
                      <span className={STATUS_BADGE[s.status] ?? 'badge-neutral'}>{s.status}</span>
                      {s.status === 'STARTING' && live?.session_id !== s.id && (
                        <span className="ml-2 text-xs text-gray-500">not connected</span>
                      )}
                    </td>
                    <td className="whitespace-nowrap text-gray-500">{s.start_time ? new Date(s.start_time).toLocaleString() : '—'}</td>
                    <td className="text-gray-400">{elapsed(s.start_time, s.end_time, now)}</td>
                    <td>
                      {s.recording_status
                        ? <span className={RECORDING_BADGE[s.recording_status] ?? 'badge-neutral'}>{s.recording_status}</span>
                        : <span className="text-xs text-gray-500">not required</span>}
                    </td>
                    <td className="text-right">
                      {LIVE.has(s.status) && (
                        <button
                          className="btn-ghost px-2 py-1 text-xs hover:text-red-400"
                          disabled={terminate.isPending}
                          onClick={() => terminate.mutate(s.id)}
                        >
                          Terminate
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
