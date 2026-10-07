import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus } from 'lucide-react';
import { accessRequestsApi } from '@/api';
import { getApiErrorMessage } from '@/api/errors';
import { ErrorBanner, EmptyState, Skeleton } from '@/components/Feedback';
import { useAuth } from '@/hooks/useAuth';
import type { RequestStatus } from '@/types';

const STATUS_BADGE: Record<RequestStatus, string> = {
  PENDING: 'badge-neutral',
  APPROVAL_REQUIRED: 'badge-warning',
  APPROVED: 'badge-success',
  REJECTED: 'badge-danger',
  DENIED: 'badge-danger',
  EXPIRED: 'badge-neutral',
  CANCELLED: 'badge-neutral',
  ACTIVE: 'badge-info',
};

const STATUSES: RequestStatus[] = [
  'APPROVAL_REQUIRED', 'ACTIVE', 'APPROVED', 'REJECTED', 'DENIED', 'CANCELLED', 'EXPIRED',
];

export default function AccessRequests() {
  const { hasPermission } = useAuth();
  const canViewAll = hasPermission('access_requests:read');
  const queryClient = useQueryClient();
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState('');

  const query = useQuery({
    queryKey: ['access-requests', { page, statusFilter }],
    queryFn: () =>
      accessRequestsApi.list({ page, page_size: 15, ...(statusFilter && { status: statusFilter }) }),
  });

  const cancelMutation = useMutation({
    mutationFn: (id: string) => accessRequestsApi.cancel(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['access-requests'] }),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-100">Access Requests</h1>
          <p className="mt-0.5 text-sm text-gray-500">
            {canViewAll ? 'All privileged access requests' : 'Your privileged access requests'}
          </p>
        </div>
        <Link to="/access-requests/new" className="btn-primary">
          <Plus size={16} /> New Request
        </Link>
      </div>

      <div className="flex gap-3">
        <select className="input w-auto" value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}>
          <option value="">All statuses</option>
          {STATUSES.map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
        </select>
      </div>

      {query.isError && <ErrorBanner message={getApiErrorMessage(query.error, 'Failed to load access requests.')} />}

      <div className="card overflow-hidden">
        {query.isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-10" />)}
          </div>
        ) : query.data && query.data.items.length === 0 ? (
          <EmptyState message="No access requests yet." />
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Request</th>
                  <th>Protocol</th>
                  <th>Reason</th>
                  <th>Risk</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {query.data?.items.map((req) => (
                  <tr key={req.id}>
                    <td className="font-mono text-xs text-gray-400">{req.request_number}</td>
                    <td className="text-gray-400">{req.protocol}</td>
                    <td className="max-w-xs truncate text-gray-300">{req.reason}</td>
                    <td className="text-gray-400">
                      {req.risk_level ? `${req.risk_level} (${req.risk_score})` : '—'}
                    </td>
                    <td><span className={STATUS_BADGE[req.status]}>{req.status.replace('_', ' ')}</span></td>
                    <td className="text-gray-500">{new Date(req.created_at).toLocaleString()}</td>
                    <td>
                      <div className="flex justify-end gap-2">
                        <Link to={`/access-requests/${req.id}`} className="btn-ghost px-2 py-1 text-xs">
                          View
                        </Link>
                        {(req.status === 'PENDING' || req.status === 'APPROVAL_REQUIRED') && (
                          <button
                            onClick={() => cancelMutation.mutate(req.id)}
                            disabled={cancelMutation.isPending}
                            className="btn-ghost px-2 py-1 text-xs hover:text-red-400"
                          >
                            Cancel
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
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
