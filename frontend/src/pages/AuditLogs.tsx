import { Fragment, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { auditApi } from '@/api';
import { getApiErrorMessage } from '@/api/errors';
import { ErrorBanner, EmptyState, Skeleton } from '@/components/Feedback';
import type { AuditLog, Severity } from '@/types';

const SEVERITY_BADGE: Record<Severity, string> = {
  INFO: 'badge-neutral',
  LOW: 'badge-info',
  MEDIUM: 'badge-warning',
  HIGH: 'badge-danger',
  CRITICAL: 'badge-danger',
};

const RESULT_BADGE: Record<AuditLog['result'], string> = {
  SUCCESS: 'badge-success',
  FAILURE: 'badge-danger',
  DENIED: 'badge-warning',
};

const SEVERITIES: Severity[] = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

export default function AuditLogs() {
  const [page, setPage] = useState(1);
  const [severity, setSeverity] = useState('');
  const [action, setAction] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);

  const query = useQuery({
    queryKey: ['audit', { page, severity, action }],
    queryFn: () =>
      auditApi.list({
        page,
        page_size: 25,
        ...(severity && { severity }),
        ...(action.trim() && { action: action.trim() }),
      }),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-gray-100">Audit Logs</h1>
        <p className="mt-0.5 text-sm text-gray-500">
          Structured security events, newest first. Secrets are never written to the audit trail.
        </p>
      </div>

      <div className="flex gap-3">
        <select className="input w-auto" value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }}>
          <option value="">All severities</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <input
          className="input w-64"
          placeholder="Exact action, e.g. APPROVAL_GRANTED"
          value={action}
          onChange={(e) => { setAction(e.target.value); setPage(1); }}
        />
      </div>

      {query.isError && <ErrorBanner message={getApiErrorMessage(query.error, 'Failed to load audit logs.')} />}

      <div className="card overflow-hidden">
        {query.isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-10" />)}
          </div>
        ) : query.data && query.data.items.length === 0 ? (
          <EmptyState message="No audit events match these filters." />
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Target</th>
                  <th>Result</th>
                  <th>Severity</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {query.data?.items.map((event) => (
                  <Fragment key={event.id}>
                    <tr>
                      <td className="whitespace-nowrap text-gray-500">{new Date(event.timestamp).toLocaleString()}</td>
                      <td className="text-gray-300">{event.actor_username}</td>
                      <td className="font-mono text-xs text-gray-300">{event.action}</td>
                      <td className="text-gray-400">
                        {event.target_type ? `${event.target_type}${event.target_id ? ` · ${event.target_id.slice(0, 8)}` : ''}` : '—'}
                      </td>
                      <td><span className={RESULT_BADGE[event.result] ?? 'badge-neutral'}>{event.result}</span></td>
                      <td><span className={SEVERITY_BADGE[event.severity] ?? 'badge-neutral'}>{event.severity}</span></td>
                      <td className="text-right">
                        {event.details && Object.keys(event.details).length > 0 && (
                          <button
                            className="btn-ghost px-2 py-1 text-xs"
                            onClick={() => setExpanded(expanded === event.id ? null : event.id)}
                          >
                            {expanded === event.id ? 'Hide' : 'Details'}
                          </button>
                        )}
                      </td>
                    </tr>
                    {expanded === event.id && (
                      <tr>
                        <td colSpan={7}>
                          <pre className="overflow-x-auto whitespace-pre-wrap text-xs text-gray-400">
                            {JSON.stringify(event.details, null, 2)}
                          </pre>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {query.data && query.data.pages > 1 && (
        <div className="flex items-center justify-between text-sm text-gray-500">
          <span>Page {query.data.page} of {query.data.pages} ({query.data.total} total)</span>
          <div className="flex gap-2">
            <button className="btn-secondary" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</button>
            <button className="btn-secondary" disabled={page >= query.data.pages} onClick={() => setPage((p) => p + 1)}>Next</button>
          </div>
        </div>
      )}
    </div>
  );
}
