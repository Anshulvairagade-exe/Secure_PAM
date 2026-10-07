import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, ShieldAlert, ShieldCheck, Clock } from 'lucide-react';
import { accessRequestsApi } from '@/api';
import { getApiErrorMessage } from '@/api/errors';
import { ErrorBanner, Skeleton } from '@/components/Feedback';
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

const RISK_BADGE: Record<string, string> = {
  LOW: 'badge-success',
  MEDIUM: 'badge-warning',
  HIGH: 'badge-danger',
  CRITICAL: 'badge-critical',
};

export default function AccessRequestDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ['access-requests', id],
    queryFn: () => accessRequestsApi.get(id!),
    enabled: !!id,
  });

  const cancelMutation = useMutation({
    mutationFn: () => accessRequestsApi.cancel(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['access-requests'] });
    },
    onError: (e) => alert(getApiErrorMessage(e, 'Failed to cancel request.')),
  });

  if (query.isLoading) {
    return <Skeleton className="h-64" />;
  }
  if (query.isError) {
    return <ErrorBanner message={getApiErrorMessage(query.error, 'Failed to load this access request.')} />;
  }

  const req = query.data!;
  const canCancel = req.status === 'PENDING' || req.status === 'APPROVAL_REQUIRED';

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <button onClick={() => navigate('/access-requests')} className="flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-300">
        <ArrowLeft size={15} /> Back to Access Requests
      </button>

      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-mono text-xl font-bold text-gray-100">{req.request_number}</h1>
          <p className="mt-0.5 text-sm text-gray-500">{req.reason}</p>
        </div>
        <span className={STATUS_BADGE[req.status]}>{req.status.replace('_', ' ')}</span>
      </div>

      {canCancel && (
        <button
          onClick={() => cancelMutation.mutate()}
          disabled={cancelMutation.isPending}
          className="btn-danger"
        >
          {cancelMutation.isPending ? 'Cancelling...' : 'Cancel Request'}
        </button>
      )}

      <div className="grid grid-cols-2 gap-4">
        <div className="card p-4">
          <p className="text-xs font-medium uppercase text-gray-500">Protocol</p>
          <p className="mt-1 text-sm text-gray-200">{req.protocol}</p>
        </div>
        <div className="card p-4">
          <p className="text-xs font-medium uppercase text-gray-500">Requested Duration</p>
          <p className="mt-1 text-sm text-gray-200">{req.requested_duration} minutes</p>
        </div>
      </div>

      <div className="card p-5">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-gray-200">
          <ShieldAlert size={16} /> Risk Evaluation
        </h2>
        {req.risk_level ? (
          <>
            <div className="mb-3 flex items-center gap-2">
              <span className={RISK_BADGE[req.risk_level]}>{req.risk_level}</span>
              <span className="text-sm text-gray-400">Score: {req.risk_score}</span>
            </div>
            <ul className="space-y-1.5">
              {req.risk_factors?.map((f) => (
                <li key={f.code} className="flex items-start justify-between gap-3 text-sm">
                  <span className="text-gray-400">{f.reason}</span>
                  <span className="flex-shrink-0 font-mono text-xs text-amber-400">+{f.points}</span>
                </li>
              ))}
            </ul>
          </>
        ) : (
          <p className="text-sm text-gray-500">Not yet evaluated.</p>
        )}
      </div>

      <div className="card p-5">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-gray-200">
          <ShieldCheck size={16} /> Policy Decision
        </h2>
        {req.policy_decision ? (
          <>
            <p className="mb-3 text-sm text-gray-400">
              {req.policy_decision.policy_name ? (
                <>Evaluated against <span className="text-gray-200">{req.policy_decision.policy_name}</span></>
              ) : (
                'No policy assigned — default conservative controls applied'
              )}
            </p>
            <ul className="space-y-1 text-sm text-gray-400">
              {req.policy_decision.reasons.map((r, i) => (
                <li key={i}>• {r}</li>
              ))}
            </ul>
          </>
        ) : (
          <p className="text-sm text-gray-500">Not yet evaluated.</p>
        )}
      </div>

      <div className="card p-5">
        <h2 className="mb-3 flex items-center gap-2 text-sm font-semibold text-gray-200">
          <Clock size={16} /> Required Controls
        </h2>
        <div className="flex flex-wrap gap-3">
          <ControlBadge label="Approval" active={req.approval_required} />
          <ControlBadge label="JIT" active={req.jit_required} />
          <ControlBadge label="MFA" active={req.mfa_required} />
          <ControlBadge label="Recording" active={req.recording_required} />
        </div>
      </div>
    </div>
  );
}

function ControlBadge({ label, active }: { label: string; active: boolean }) {
  return (
    <span className={active ? 'badge-warning' : 'badge-neutral'}>
      {label}: {active ? 'Required' : 'Not required'}
    </span>
  );
}
