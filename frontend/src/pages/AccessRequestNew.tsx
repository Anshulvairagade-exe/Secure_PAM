import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useMutation } from '@tanstack/react-query';
import { assetsApi, applicationsApi, accessRequestsApi } from '@/api';
import { getApiErrorMessage } from '@/api/errors';
import { ErrorBanner } from '@/components/Feedback';

type TargetKind = 'asset' | 'application';

export default function AccessRequestNew() {
  const navigate = useNavigate();
  const [targetKind, setTargetKind] = useState<TargetKind>('asset');
  const [targetId, setTargetId] = useState('');
  const [reason, setReason] = useState('');
  const [duration, setDuration] = useState(30);
  const [error, setError] = useState<string | null>(null);

  // page_size=100 — simple MVP listing, not paginated target-pickers.
  const assetsQuery = useQuery({ queryKey: ['assets', 'picker'], queryFn: () => assetsApi.list({ page_size: 100, enabled: true }) });
  const appsQuery = useQuery({ queryKey: ['applications', 'picker'], queryFn: () => applicationsApi.list({ page_size: 100, enabled: true }) });

  const targets = targetKind === 'asset' ? assetsQuery.data?.items ?? [] : appsQuery.data?.items ?? [];
  const selectedTarget = targets.find((t) => t.id === targetId);
  // Protocol is never user-editable — it's always the target's own
  // registered protocol, matching what the backend validates against.
  const protocol = selectedTarget?.protocol ?? '';

  const createMutation = useMutation({
    mutationFn: () =>
      accessRequestsApi.create({
        ...(targetKind === 'asset' ? { asset_id: targetId } : { application_id: targetId }),
        protocol,
        reason,
        requested_duration: duration,
      }),
    onSuccess: (data) => navigate(`/access-requests/${data.id}`),
    onError: (e) => setError(getApiErrorMessage(e, 'Failed to create access request.')),
  });

  function submit() {
    setError(null);
    if (!targetId || !reason.trim()) return;
    createMutation.mutate();
  }

  return (
    <div className="mx-auto max-w-xl space-y-6">
      <div>
        <h1 className="text-xl font-bold text-gray-100">New Access Request</h1>
        <p className="mt-0.5 text-sm text-gray-500">
          Risk and policy are evaluated server-side once you submit — nothing here decides access.
        </p>
      </div>

      <div className="card space-y-4 p-6">
        {error && <ErrorBanner message={error} />}

        <div>
          <span className="mb-1.5 block text-xs font-medium text-gray-400">Target Type</span>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => { setTargetKind('asset'); setTargetId(''); }}
              className={targetKind === 'asset' ? 'btn-primary flex-1' : 'btn-secondary flex-1'}
            >
              Asset
            </button>
            <button
              type="button"
              onClick={() => { setTargetKind('application'); setTargetId(''); }}
              className={targetKind === 'application' ? 'btn-primary flex-1' : 'btn-secondary flex-1'}
            >
              Application
            </button>
          </div>
        </div>

        <label className="block">
          <span className="mb-1.5 block text-xs font-medium text-gray-400">Target</span>
          <select className="input" value={targetId} onChange={(e) => setTargetId(e.target.value)}>
            <option value="">Select a {targetKind}...</option>
            {targets.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name} ({t.protocol}, {t.environment}, {t.criticality})
              </option>
            ))}
          </select>
        </label>

        {selectedTarget && (
          <div className="rounded-lg border border-navy-700/50 bg-navy-800/40 px-3.5 py-2.5 text-sm text-gray-400">
            Protocol: <span className="font-medium text-gray-200">{protocol}</span> — fixed to this target's
            registered protocol, cannot be changed here.
          </div>
        )}

        <label className="block">
          <span className="mb-1.5 block text-xs font-medium text-gray-400">Reason</span>
          <textarea
            className="input"
            rows={3}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Why do you need access?"
          />
        </label>

        <label className="block">
          <span className="mb-1.5 block text-xs font-medium text-gray-400">Requested Duration (minutes)</span>
          <input
            type="number"
            className="input"
            min={1}
            max={480}
            value={duration}
            onChange={(e) => setDuration(Number(e.target.value))}
          />
          <span className="mt-1 block text-xs text-gray-600">
            May be reduced by the target's policy — the final grant is never longer than this.
          </span>
        </label>

        <div className="flex justify-end gap-2 pt-2">
          <button className="btn-secondary" onClick={() => navigate('/access-requests')}>Cancel</button>
          <button
            className="btn-primary"
            disabled={!targetId || !reason.trim() || createMutation.isPending}
            onClick={submit}
          >
            {createMutation.isPending ? 'Submitting...' : 'Submit Request'}
          </button>
        </div>
      </div>
    </div>
  );
}
