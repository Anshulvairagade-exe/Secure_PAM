import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Search, Pencil, Trash2, Globe } from 'lucide-react';
import { applicationsApi } from '@/api';
import { getApiErrorMessage } from '@/api/errors';
import { ErrorBanner, EmptyState, Skeleton } from '@/components/Feedback';
import Modal from '@/components/Modal';
import { useAuth } from '@/hooks/useAuth';
import type { Application, ApplicationInput } from '@/types';

const ENVIRONMENTS = ['DEVELOPMENT', 'TEST', 'STAGING', 'PRODUCTION'];
const CRITICALITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const PROTOCOLS = ['HTTP', 'HTTPS'];
const ACCESS_MODES = ['STANDARD_PROXY', 'ISOLATED_BROWSER'];

const CRITICALITY_BADGE: Record<string, string> = {
  LOW: 'badge-success',
  MEDIUM: 'badge-warning',
  HIGH: 'badge-danger',
  CRITICAL: 'badge-critical',
};

const EMPTY_FORM: ApplicationInput = {
  name: '',
  description: '',
  hostname: '',
  port: 443,
  protocol: 'HTTPS',
  environment: 'PRODUCTION',
  criticality: 'MEDIUM',
  access_mode: 'STANDARD_PROXY',
  enabled: true,
  approval_required: false,
  mfa_required: true,
  recording_required: false,
  download_allowed: false,
  upload_allowed: false,
  clipboard_allowed: false,
  session_timeout: 30,
};

export default function Applications() {
  const { hasPermission } = useAuth();
  const canCreate = hasPermission('applications:create');
  const canUpdate = hasPermission('applications:update');
  const canDelete = hasPermission('applications:delete');
  const queryClient = useQueryClient();

  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [environment, setEnvironment] = useState('');
  const [accessMode, setAccessMode] = useState('');
  const [editing, setEditing] = useState<Application | 'new' | null>(null);
  const [form, setForm] = useState<ApplicationInput>(EMPTY_FORM);
  const [formError, setFormError] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Application | null>(null);

  const query = useQuery({
    queryKey: ['applications', { page, search, environment, accessMode }],
    queryFn: () =>
      applicationsApi.list({
        page,
        page_size: 10,
        ...(search && { search }),
        ...(environment && { environment }),
        ...(accessMode && { access_mode: accessMode }),
      }),
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['applications'] });

  const createMutation = useMutation({
    mutationFn: (data: ApplicationInput) => applicationsApi.create(data),
    onSuccess: () => {
      invalidate();
      setEditing(null);
    },
    onError: (e) => setFormError(getApiErrorMessage(e, 'Failed to create application.')),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<ApplicationInput> }) => applicationsApi.update(id, data),
    onSuccess: () => {
      invalidate();
      setEditing(null);
    },
    onError: (e) => setFormError(getApiErrorMessage(e, 'Failed to update application.')),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => applicationsApi.delete(id),
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

  function openEdit(app: Application) {
    setForm(app);
    setFormError(null);
    setEditing(app);
  }

  function submit() {
    setFormError(null);
    if (editing === 'new') {
      createMutation.mutate(form);
    } else if (editing) {
      updateMutation.mutate({ id: editing.id, data: form });
    }
  }

  const pending = createMutation.isPending || updateMutation.isPending;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-100">Applications</h1>
          <p className="mt-0.5 text-sm text-gray-500">Registered internal web applications</p>
        </div>
        {canCreate && (
          <button onClick={openCreate} className="btn-primary">
            <Plus size={16} /> New Application
          </button>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative w-64">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            className="input pl-8"
            placeholder="Search name or hostname..."
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(1);
            }}
          />
        </div>
        <select className="input w-auto" value={environment} onChange={(e) => { setEnvironment(e.target.value); setPage(1); }}>
          <option value="">All environments</option>
          {ENVIRONMENTS.map((e) => <option key={e} value={e}>{e}</option>)}
        </select>
        <select className="input w-auto" value={accessMode} onChange={(e) => { setAccessMode(e.target.value); setPage(1); }}>
          <option value="">All access modes</option>
          {ACCESS_MODES.map((m) => <option key={m} value={m}>{m}</option>)}
        </select>
      </div>

      {query.isError && <ErrorBanner message={getApiErrorMessage(query.error, 'Failed to load applications.')} />}

      <div className="card overflow-hidden">
        {query.isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-10" />)}
          </div>
        ) : query.data && query.data.items.length === 0 ? (
          <EmptyState message="No applications match these filters." />
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Hostname</th>
                  <th>Protocol</th>
                  <th>Environment</th>
                  <th>Criticality</th>
                  <th>Access Mode</th>
                  <th>Enabled</th>
                  {(canUpdate || canDelete) && <th></th>}
                </tr>
              </thead>
              <tbody>
                {query.data?.items.map((app) => (
                  <tr key={app.id}>
                    <td className="font-medium text-gray-100">{app.name}</td>
                    <td className="text-gray-400">{app.hostname}:{app.port}</td>
                    <td className="text-gray-400">{app.protocol}</td>
                    <td className="text-gray-400">{app.environment}</td>
                    <td><span className={CRITICALITY_BADGE[app.criticality]}>{app.criticality}</span></td>
                    <td className="text-gray-400">{app.access_mode}</td>
                    <td>
                      <span className={app.enabled ? 'badge-success' : 'badge-neutral'}>
                        {app.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    {(canUpdate || canDelete) && (
                      <td>
                        <div className="flex justify-end gap-1">
                          {canUpdate && (
                            <button onClick={() => openEdit(app)} className="btn-ghost p-1.5">
                              <Pencil size={14} />
                            </button>
                          )}
                          {canDelete && (
                            <button onClick={() => setDeleteTarget(app)} className="btn-ghost p-1.5 hover:text-red-400">
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
            <button className="btn-secondary" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
              Previous
            </button>
            <button
              className="btn-secondary"
              disabled={page >= query.data.pages}
              onClick={() => setPage((p) => p + 1)}
            >
              Next
            </button>
          </div>
        </div>
      )}

      {editing && (
        <Modal title={editing === 'new' ? 'New Application' : `Edit ${editing.name}`} onClose={() => setEditing(null)}>
          <div className="space-y-4">
            {formError && <ErrorBanner message={formError} />}

            <div className="grid grid-cols-2 gap-3">
              <Field label="Name">
                <input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
              </Field>
              <Field label="Hostname">
                <input className="input" value={form.hostname} onChange={(e) => setForm({ ...form, hostname: e.target.value })} />
              </Field>
              <Field label="Port">
                <input
                  type="number"
                  className="input"
                  value={form.port}
                  onChange={(e) => setForm({ ...form, port: Number(e.target.value) })}
                />
              </Field>
              <Field label="Protocol">
                <select className="input" value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value as Application['protocol'] })}>
                  {PROTOCOLS.map((p) => <option key={p} value={p}>{p}</option>)}
                </select>
              </Field>
              <Field label="Environment">
                <select className="input" value={form.environment} onChange={(e) => setForm({ ...form, environment: e.target.value as Application['environment'] })}>
                  {ENVIRONMENTS.map((e) => <option key={e} value={e}>{e}</option>)}
                </select>
              </Field>
              <Field label="Criticality">
                <select className="input" value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value as Application['criticality'] })}>
                  {CRITICALITIES.map((c) => <option key={c} value={c}>{c}</option>)}
                </select>
              </Field>
              <Field label="Access Mode">
                <select className="input" value={form.access_mode} onChange={(e) => setForm({ ...form, access_mode: e.target.value as Application['access_mode'] })}>
                  {ACCESS_MODES.map((m) => <option key={m} value={m}>{m}</option>)}
                </select>
              </Field>
              <Field label="Session Timeout (min)">
                <input
                  type="number"
                  className="input"
                  value={form.session_timeout}
                  onChange={(e) => setForm({ ...form, session_timeout: Number(e.target.value) })}
                />
              </Field>
            </div>

            <Field label="Description">
              <textarea
                className="input"
                rows={2}
                value={form.description ?? ''}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
              />
            </Field>

            <div className="flex flex-wrap gap-4 pt-1">
              <Checkbox label="Enabled" checked={form.enabled} onChange={(v) => setForm({ ...form, enabled: v })} />
              <Checkbox label="Approval required" checked={form.approval_required} onChange={(v) => setForm({ ...form, approval_required: v })} />
              <Checkbox label="MFA required" checked={form.mfa_required} onChange={(v) => setForm({ ...form, mfa_required: v })} />
              <Checkbox label="Recording required" checked={form.recording_required} onChange={(v) => setForm({ ...form, recording_required: v })} />
              <Checkbox label="Download allowed" checked={form.download_allowed} onChange={(v) => setForm({ ...form, download_allowed: v })} />
              <Checkbox label="Upload allowed" checked={form.upload_allowed} onChange={(v) => setForm({ ...form, upload_allowed: v })} />
              <Checkbox label="Clipboard allowed" checked={form.clipboard_allowed} onChange={(v) => setForm({ ...form, clipboard_allowed: v })} />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button className="btn-secondary" onClick={() => setEditing(null)}>Cancel</button>
              <button className="btn-primary" disabled={pending} onClick={submit}>
                {pending ? 'Saving...' : editing === 'new' ? 'Create Application' : 'Save Changes'}
              </button>
            </div>
          </div>
        </Modal>
      )}

      {deleteTarget && (
        <Modal title="Delete Application" onClose={() => setDeleteTarget(null)} width="max-w-sm">
          <div className="space-y-4">
            <div className="flex items-start gap-3 text-sm text-gray-300">
              <Globe size={18} className="mt-0.5 flex-shrink-0 text-red-400" />
              <p>
                Delete <span className="font-medium text-gray-100">{deleteTarget.name}</span>? This
                soft-deletes the application — it will disappear from all lists and be blocked if any
                active sessions still reference it.
              </p>
            </div>
            {deleteMutation.isError && (
              <ErrorBanner message={getApiErrorMessage(deleteMutation.error, 'Failed to delete application.')} />
            )}
            <div className="flex justify-end gap-2">
              <button className="btn-secondary" onClick={() => setDeleteTarget(null)}>Cancel</button>
              <button
                className="btn-danger"
                disabled={deleteMutation.isPending}
                onClick={() => deleteMutation.mutate(deleteTarget.id)}
              >
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
