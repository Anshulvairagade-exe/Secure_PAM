import { useState } from 'react';
import { useQuery, useQueries, useMutation, useQueryClient } from '@tanstack/react-query';
import { Check, X } from 'lucide-react';
import { approvalsApi, accessRequestsApi } from '@/api';
import { getApiErrorMessage } from '@/api/errors';
import { ErrorBanner, EmptyState, Skeleton } from '@/components/Feedback';
import Modal from '@/components/Modal';
import { useAuth } from '@/hooks/useAuth';
import type { Approval } from '@/types';

export default function Approvals() {
  const { hasPermission } = useAuth();
  const canApprove = hasPermission('approvals:approve');
  const canReject = hasPermission('approvals:reject');
  const queryClient = useQueryClient();

  const [statusFilter, setStatusFilter] = useState('PENDING');
  const [rejecting, setRejecting] = useState<Approval | null>(null);
  const [rejectComment, setRejectComment] = useState('');
  const [actionError, setActionError] = useState<string | null>(null);

  const approvalsQuery = useQuery({
    queryKey: ['approvals', { statusFilter }],
    queryFn: () => approvalsApi.list({ page_size: 50, ...(statusFilter && { status: statusFilter }) }),
  });

  const items = approvalsQuery.data?.items ?? [];

  // Fetch the underlying access request for each approval so the queue
  // can show requester/target/reason/risk — the Approval row itself only
  // has request_id.
  const requestQueries = useQueries({
    queries: items.map((a) => ({
      queryKey: ['access-requests', a.request_id],
      queryFn: () => accessRequestsApi.get(a.request_id),
      enabled: items.length > 0,
    })),
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['approvals'] });
    queryClient.invalidateQueries({ queryKey: ['access-requests'] });
  };

  const approveMutation = useMutation({
    mutationFn: (id: string) => approvalsApi.approve(id),
    onSuccess: invalidate,
    onError: (e) => setActionError(getApiErrorMessage(e, 'Failed to approve request.')),
  });

  const rejectMutation = useMutation({
    mutationFn: ({ id, comment }: { id: string; comment: string }) => approvalsApi.reject(id, comment),
    onSuccess: () => {
      invalidate();
      setRejecting(null);
      setRejectComment('');
    },
    onError: (e) => setActionError(getApiErrorMessage(e, 'Failed to reject request.')),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-gray-100">Approvals</h1>
        <p className="mt-0.5 text-sm text-gray-500">Access requests awaiting a decision</p>
      </div>

      {actionError && <ErrorBanner message={actionError} />}

      <select className="input w-auto" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
        <option value="PENDING">Pending</option>
        <option value="APPROVED">Approved</option>
        <option value="REJECTED">Rejected</option>
        <option value="">All</option>
      </select>

      {approvalsQuery.isError && (
        <ErrorBanner message={getApiErrorMessage(approvalsQuery.error, 'Failed to load approvals.')} />
      )}

      <div className="card overflow-hidden">
        {approvalsQuery.isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-16" />)}
          </div>
        ) : items.length === 0 ? (
          <EmptyState message="No approvals match this filter." />
        ) : (
          <div className="divide-y divide-navy-800/60">
            {items.map((approval, i) => {
              const reqQuery = requestQueries[i];
              const req = reqQuery?.data;
              return (
                <div key={approval.id} className="p-4">
                  {reqQuery?.isLoading ? (
                    <Skeleton className="h-16" />
                  ) : req ? (
                    <div className="flex items-start justify-between gap-4">
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs text-gray-500">{req.request_number}</span>
                          <span className="text-xs text-gray-600">·</span>
                          <span className="text-xs text-gray-500">{req.protocol}</span>
                          {req.risk_level && (
                            <span className="text-xs text-gray-500">· Risk: {req.risk_level} ({req.risk_score})</span>
                          )}
                        </div>
                        <p className="mt-1 text-sm text-gray-200">{req.reason}</p>
                        <p className="mt-1 text-xs text-gray-500">Requested duration: {req.requested_duration} min</p>
                        {approval.comment && (
                          <p className="mt-1 text-xs italic text-gray-500">"{approval.comment}"</p>
                        )}
                      </div>

                      {approval.status === 'PENDING' && (
                        <div className="flex flex-shrink-0 gap-2">
                          {canApprove && (
                            <button
                              onClick={() => approveMutation.mutate(approval.id)}
                              disabled={approveMutation.isPending}
                              className="btn-success px-3 py-1.5 text-xs"
                            >
                              <Check size={14} /> Approve
                            </button>
                          )}
                          {canReject && (
                            <button
                              onClick={() => { setRejecting(approval); setActionError(null); }}
                              className="btn-danger px-3 py-1.5 text-xs"
                            >
                              <X size={14} /> Reject
                            </button>
                          )}
                        </div>
                      )}
                      {approval.status !== 'PENDING' && (
                        <span className={approval.status === 'APPROVED' ? 'badge-success' : 'badge-danger'}>
                          {approval.status}
                        </span>
                      )}
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {rejecting && (
        <Modal title="Reject Access Request" onClose={() => setRejecting(null)} width="max-w-sm">
          <div className="space-y-4">
            <p className="text-sm text-gray-400">A rejection reason is required.</p>
            <textarea
              className="input"
              rows={3}
              value={rejectComment}
              onChange={(e) => setRejectComment(e.target.value)}
              placeholder="Why is this being rejected?"
              autoFocus
            />
            <div className="flex justify-end gap-2">
              <button className="btn-secondary" onClick={() => setRejecting(null)}>Cancel</button>
              <button
                className="btn-danger"
                disabled={!rejectComment.trim() || rejectMutation.isPending}
                onClick={() => rejectMutation.mutate({ id: rejecting.id, comment: rejectComment.trim() })}
              >
                {rejectMutation.isPending ? 'Rejecting...' : 'Reject'}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
