import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Pencil, Trash2, ShieldCheck } from 'lucide-react';
import { policiesApi } from '@/api';
import { getApiErrorMessage } from '@/api/errors';
import { ErrorBanner, EmptyState, Skeleton } from '@/components/Feedback';
import Modal from '@/components/Modal';
import { useAuth } from '@/hooks/useAuth';
import type { Policy, PolicyInput } from '@/types';

const ROLES = ['ADMIN', 'OPERATOR', 'APPROVER', 'AUDITOR'];
const ASSET_TYPES = ['WINDOWS_SERVER', 'WINDOWS_WORKSTATION', 'LINUX_SERVER', 'UNIX_SERVER', 'NETWORK_DEVICE', 'OTHER'];
const ENVIRONMENTS = ['DEVELOPMENT', 'TEST', 'STAGING', 'PRODUCTION'];
const PROTOCOLS = ['RDP', 'SSH', 'HTTPS', 'HTTP'];
const DAYS = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'];
const RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

const RISK_BADGE: Record<string, string> = {
  LOW: 'badge-success',
  MEDIUM: 'badge-warning',
  HIGH: 'badge-danger',
  CRITICAL: 'badge-critical',
};

const EMPTY_FORM: PolicyInput = {
  name: '',
  description: '',
  enabled: true,
  allowed_roles: [],
  allowed_asset_types: [],
  allowed_environments: [],
  allowed_protocols: [],
  allowed_days: [],
  business_hours_only: false,
  risk_threshold: 'LOW',
  min_risk_score: 0,
  require_approval: false,
  jit_required: true,
  require_mfa: true,
  require_recording: false,
  max_session_duration: 30,
  download_allowed: true,
  upload_allowed: true,
  clipboard_allowed: true,
  auto_approve: false,
  deny_access: false,
};

export default function Policies() {
  const { hasPermission } = useAuth();
  const canCreate = hasPermission('policies:create');
  const canUpdate = hasPermission('policies:update');
  const canDelete = hasPermission('policies:delete');
  const queryClient = useQueryClient();

  const [page, setPage] = useState(1);
  const [editing, setEditing] = useState<Policy | 'new' | null>(null);
  const [form, setForm] = useState<PolicyInput>(EMPTY_FORM);
  const [formError, setFormError] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Policy | null>(null);

  const query = useQuery({
    queryKey: ['policies', { page }],
    queryFn: () => policiesApi.list({ page, page_size: 10 }),
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['policies'] });

  const createMutation = useMutation({
    mutationFn: (data: PolicyInput) => policiesApi.create(data),
    onSuccess: () => {
      invalidate();
      setEditing(null);
    },
    onError: (e) => setFormError(getApiErrorMessage(e, 'Failed to create policy.')),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<PolicyInput> }) => policiesApi.update(id, data),
    onSuccess: () => {
      invalidate();
      setEditing(null);
    },
    onError: (e) => setFormError(getApiErrorMessage(e, 'Failed to update policy.')),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => policiesApi.delete(id),
    onSuccess: () => {
      invalidate();
      setDeleteTarget(null);
    },
  });

  function openCreate() {
    setForm(EMPTY_FORM);
    setFormError(null);
    setEditing('new');
  }

  function openEdit(policy: Policy) {
    setForm({ ...policy, allowed_roles: policy.allowed_roles ?? [], allowed_asset_types: policy.allowed_asset_types ?? [], allowed_environments: policy.allowed_environments ?? [], allowed_protocols: policy.allowed_protocols ?? [], allowed_days: policy.allowed_days ?? [] });
    setFormError(null);
    setEditing(policy);
  }

  function submit() {
    setFormError(null);
    if (editing === 'new') {
      createMutation.mutate(form);
    } else if (editing) {
      updateMutation.mutate({ id: editing.id, data: form });
    }
  }

  function toggleInList<T extends string>(list: T[] | null | undefined, value: T): T[] {
    const current = list ?? [];
    return current.includes(value) ? current.filter((v) => v !== value) : [...current, value];
  }

  const pending = createMutation.isPending || updateMutation.isPending;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-100">Policies</h1>
          <p className="mt-0.5 text-sm text-gray-500">
            Access control rules — evaluated server-side by the (future) Risk Engine, never by the frontend
          </p>
        </div>
        {canCreate && (
          <button onClick={openCreate} className="btn-primary">
            <Plus size={16} /> New Policy
          </button>
        )}
      </div>

      {query.isError && <ErrorBanner message={getApiErrorMessage(query.error, 'Failed to load policies.')} />}

      <div className="card overflow-hidden">
        {query.isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-10" />)}
          </div>
        ) : query.data && query.data.items.length === 0 ? (
          <EmptyState message="No policies defined yet." />
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Risk Threshold</th>
                  <th>Approval</th>
                  <th>MFA</th>
                  <th>Recording</th>
                  <th>Max Duration</th>
                  <th>Enabled</th>
                  {(canUpdate || canDelete) && <th></th>}
                </tr>
              </thead>
              <tbody>
                {query.data?.items.map((policy) => (
                  <tr key={policy.id}>
                    <td>
                      <p className="font-medium text-gray-100">{policy.name}</p>
                      {policy.description && <p className="text-xs text-gray-500">{policy.description}</p>}
                    </td>
                    <td><span className={RISK_BADGE[policy.risk_threshold]}>{policy.risk_threshold}</span></td>
                    <td className="text-gray-400">{policy.require_approval ? 'Required' : '—'}</td>
                    <td className="text-gray-400">{policy.require_mfa ? 'Required' : '—'}</td>
                    <td className="text-gray-400">{policy.require_recording ? 'Required' : '—'}</td>
                    <td className="text-gray-400">{policy.max_session_duration} min</td>
                    <td>
                      <span className={policy.enabled ? 'badge-success' : 'badge-neutral'}>
                        {policy.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    {(canUpdate || canDelete) && (
                      <td>
                        <div className="flex justify-end gap-1">
                          {canUpdate && (
                            <button onClick={() => openEdit(policy)} className="btn-ghost p-1.5">
                              <Pencil size={14} />
                            </button>
                          )}
                          {canDelete && (
                            <button onClick={() => setDeleteTarget(policy)} className="btn-ghost p-1.5 hover:text-red-400">
                              <Trash2 size={14} />
                            </button>
                          )}
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {query.data && query.data.pages > 1 && (
        <div className="flex items-center justify-between text-sm text-gray-500">
          <span>
            Page {query.data.page} of {query.data.pages} ({query.data.total} total)
          </span>
          <div className="flex gap-2">
            <button className="btn-secondary" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</button>
            <button className="btn-secondary" disabled={page >= query.data.pages} onClick={() => setPage((p) => p + 1)}>Next</button>
          </div>
        </div>
      )}

      {editing && (
        <Modal title={editing === 'new' ? 'New Policy' : `Edit ${editing.name}`} onClose={() => setEditing(null)} width="max-w-2xl">
          <div className="space-y-4">
            {formError && <ErrorBanner message={formError} />}

            <div className="grid grid-cols-2 gap-3">
              <Field label="Name">
                <input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
              </Field>
              <Field label="Risk Threshold">
                <select className="input" value={form.risk_threshold} onChange={(e) => setForm({ ...form, risk_threshold: e.target.value as Policy['risk_threshold'] })}>
                  {RISK_LEVELS.map((r) => <option key={r} value={r}>{r}</option>)}
                </select>
              </Field>
              <Field label="Max Session Duration (min)">
                <input type="number" className="input" value={form.max_session_duration} onChange={(e) => setForm({ ...form, max_session_duration: Number(e.target.value) })} />
              </Field>
              <Field label="Min Risk Score">
                <input type="number" className="input" value={form.min_risk_score} onChange={(e) => setForm({ ...form, min_risk_score: Number(e.target.value) })} />
              </Field>
            </div>

            <Field label="Description">
              <textarea className="input" rows={2} value={form.description ?? ''} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            </Field>

            <div className="grid grid-cols-2 gap-4">
              <CheckboxGroup label="Allowed Roles (empty = all)" options={ROLES} selected={form.allowed_roles ?? []} onToggle={(v) => setForm({ ...form, allowed_roles: toggleInList(form.allowed_roles, v) as Policy['allowed_roles'] })} />
              <CheckboxGroup label="Allowed Protocols (empty = all)" options={PROTOCOLS} selected={form.allowed_protocols ?? []} onToggle={(v) => setForm({ ...form, allowed_protocols: toggleInList(form.allowed_protocols, v) })} />
              <CheckboxGroup label="Allowed Environments (empty = all)" options={ENVIRONMENTS} selected={form.allowed_environments ?? []} onToggle={(v) => setForm({ ...form, allowed_environments: toggleInList(form.allowed_environments, v) as Policy['allowed_environments'] })} />
              <CheckboxGroup label="Allowed Days (empty = every day)" options={DAYS} selected={form.allowed_days ?? []} onToggle={(v) => setForm({ ...form, allowed_days: toggleInList(form.allowed_days, v) as Policy['allowed_days'] })} />
            </div>
            <CheckboxGroup label="Allowed Asset Types (empty = all)" options={ASSET_TYPES} selected={form.allowed_asset_types ?? []} onToggle={(v) => setForm({ ...form, allowed_asset_types: toggleInList(form.allowed_asset_types, v) as Policy['allowed_asset_types'] })} />

            <div className="flex flex-wrap gap-4 border-t border-navy-700/50 pt-4">
              <Checkbox label="Enabled" checked={form.enabled} onChange={(v) => setForm({ ...form, enabled: v })} />
              <Checkbox label="Business hours only" checked={form.business_hours_only} onChange={(v) => setForm({ ...form, business_hours_only: v })} />
              <Checkbox label="Require approval" checked={form.require_approval} onChange={(v) => setForm({ ...form, require_approval: v })} />
              <Checkbox label="JIT required" checked={form.jit_required} onChange={(v) => setForm({ ...form, jit_required: v })} />
              <Checkbox label="Require MFA" checked={form.require_mfa} onChange={(v) => setForm({ ...form, require_mfa: v })} />
              <Checkbox label="Require recording" checked={form.require_recording} onChange={(v) => setForm({ ...form, require_recording: v })} />
              <Checkbox label="Download allowed" checked={form.download_allowed} onChange={(v) => setForm({ ...form, download_allowed: v })} />
              <Checkbox label="Upload allowed" checked={form.upload_allowed} onChange={(v) => setForm({ ...form, upload_allowed: v })} />
              <Checkbox label="Clipboard allowed" checked={form.clipboard_allowed} onChange={(v) => setForm({ ...form, clipboard_allowed: v })} />
              <Checkbox label="Auto-approve" checked={form.auto_approve} onChange={(v) => setForm({ ...form, auto_approve: v })} />
              <Checkbox label="Deny access outright" checked={form.deny_access} onChange={(v) => setForm({ ...form, deny_access: v })} />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button className="btn-secondary" onClick={() => setEditing(null)}>Cancel</button>
              <button className="btn-primary" disabled={pending} onClick={submit}>
                {pending ? 'Saving...' : editing === 'new' ? 'Create Policy' : 'Save Changes'}
              </button>
            </div>
          </div>
        </Modal>
      )}

      {deleteTarget && (
        <Modal title="Delete Policy" onClose={() => setDeleteTarget(null)} width="max-w-sm">
          <div className="space-y-4">
            <div className="flex items-start gap-3 text-sm text-gray-300">
              <ShieldCheck size={18} className="mt-0.5 flex-shrink-0 text-red-400" />
              <p>
                Delete <span className="font-medium text-gray-100">{deleteTarget.name}</span>? This
                soft-deletes the policy. Any Asset/Application still pointing at it keeps working —
                its policy reference is simply cleared.
              </p>
            </div>
            {deleteMutation.isError && (
              <ErrorBanner message={getApiErrorMessage(deleteMutation.error, 'Failed to delete policy.')} />
            )}
            <div className="flex justify-end gap-2">
              <button className="btn-secondary" onClick={() => setDeleteTarget(null)}>Cancel</button>
              <button className="btn-danger" disabled={deleteMutation.isPending} onClick={() => deleteMutation.mutate(deleteTarget.id)}>
                {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-gray-400">{label}</span>
      {children}
    </label>
  );
}

function Checkbox({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center gap-2 text-sm text-gray-300">
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} className="h-4 w-4 rounded border-navy-600 bg-navy-800 text-blue-500" />
      {label}
    </label>
  );
}

function CheckboxGroup({
  label,
  options,
  selected,
  onToggle,
}: {
  label: string;
  options: string[];
  selected: string[];
  onToggle: (value: string) => void;
}) {
  return (
    <div>
      <span className="mb-1.5 block text-xs font-medium text-gray-400">{label}</span>
      <div className="flex flex-wrap gap-2">
        {options.map((opt) => (
          <button
            key={opt}
            type="button"
            onClick={() => onToggle(opt)}
            className={selected.includes(opt) ? 'badge-info' : 'badge-neutral'}
          >
            {opt}
          </button>
        ))}
      </div>
    </div>
  );
}
