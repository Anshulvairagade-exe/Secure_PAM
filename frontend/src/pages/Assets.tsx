import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Search, Pencil, Trash2, Server, KeyRound, CheckCircle2 } from 'lucide-react';
import { assetsApi, credentialProvisioningApi } from '@/api';
import {
  CredentialFields, EMPTY_CREDENTIAL, ProvisioningBanner, ProvisioningErrorView, credentialComplete, provisioningError,
} from '@/components/AssetCredentialForm';
import { getApiErrorMessage } from '@/api/errors';
import { ErrorBanner, EmptyState, Skeleton } from '@/components/Feedback';
import Modal from '@/components/Modal';
import { useAuth } from '@/hooks/useAuth';
import type { Asset, AssetInput, CredentialInput } from '@/types';

const ASSET_TYPES = ['WINDOWS_SERVER', 'WINDOWS_WORKSTATION', 'LINUX_SERVER', 'UNIX_SERVER', 'NETWORK_DEVICE', 'OTHER'];
const ENVIRONMENTS = ['DEVELOPMENT', 'TEST', 'STAGING', 'PRODUCTION'];
const CRITICALITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const PROTOCOLS = ['RDP', 'SSH', 'HTTPS', 'HTTP'];

const CRITICALITY_BADGE: Record<string, string> = {
  LOW: 'badge-success',
  MEDIUM: 'badge-warning',
  HIGH: 'badge-danger',
  CRITICAL: 'badge-critical',
};

const EMPTY_FORM: AssetInput = {
  name: '',
  hostname: '',
  ip_address: '',
  port: 22,
  protocol: 'SSH',
  asset_type: 'LINUX_SERVER',
  environment: 'DEVELOPMENT',
  criticality: 'MEDIUM',
  description: '',
  owner: '',
  enabled: true,
  recording_required: false,
  approval_required: false,
  jit_required: true,
};

export default function Assets() {
  const { hasPermission } = useAuth();
  const canCreate = hasPermission('assets:create');
  const canUpdate = hasPermission('assets:update');
  const canDelete = hasPermission('assets:delete');
  const queryClient = useQueryClient();

  const [page, setPage] = useState(1);
  const [searchParams] = useSearchParams();
  const [search, setSearch] = useState(searchParams.get('search') ?? '');
  const [environment, setEnvironment] = useState('');
  const [criticality, setCriticality] = useState('');
  const [assetType, setAssetType] = useState('');
  const [editing, setEditing] = useState<Asset | 'new' | null>(null);
  const [form, setForm] = useState<AssetInput>(EMPTY_FORM);
  const [formError, setFormError] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Asset | null>(null);
  const canVault = hasPermission('vault:manage');
  const [credMode, setCredMode] = useState<'now' | 'later'>('later');
  const [cred, setCred] = useState<CredentialInput>(EMPTY_CREDENTIAL);
  const [credError, setCredError] = useState<ReturnType<typeof provisioningError> | null>(null);
  const [credTarget, setCredTarget] = useState<Asset | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const provisioning = useQuery({ queryKey: ['credential-provisioning'], queryFn: credentialProvisioningApi.status, enabled: canVault });
  const provisioningReady = provisioning.data?.configured ?? false;

  const query = useQuery({
    queryKey: ['assets', { page, search, environment, criticality, assetType }],
    queryFn: () =>
      assetsApi.list({
        page,
        page_size: 10,
        ...(search && { search }),
        ...(environment && { environment }),
        ...(criticality && { criticality }),
        ...(assetType && { asset_type: assetType }),
      }),
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['assets'] });

  const createMutation = useMutation({
    mutationFn: (data: AssetInput) => assetsApi.create(data),
    onSuccess: () => {
      invalidate();
      setEditing(null);
    },
    onError: (e) => setFormError(getApiErrorMessage(e, 'Failed to create asset.')),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<AssetInput> }) => assetsApi.update(id, data),
    onSuccess: () => {
      invalidate();
      setEditing(null);
    },
    onError: (e) => setFormError(getApiErrorMessage(e, 'Failed to update asset.')),
  });

  const resetCred = () => { setCred(EMPTY_CREDENTIAL); setCredError(null); };
  const createWithCredential = useMutation({
    mutationFn: () => credentialProvisioningApi.createAsset({ asset: form, credential: cred }),
    onSuccess: (r) => {
      invalidate(); void queryClient.invalidateQueries({ queryKey: ['credential-provisioning'] });
      setEditing(null); resetCred();
      setNotice(`${r.asset.name} created. Credential stored at ${r.vault_path} (version ${r.version}) and verified.`);
    },
    onError: (e) => { setCredError(provisioningError(e)); setCred((c) => ({ ...c, password: '' })); },
  });
  const setCredential = useMutation({
    mutationFn: (asset: Asset) => credentialProvisioningApi.setCredential(asset.id, cred),
    onSuccess: (r) => {
      void queryClient.invalidateQueries({ queryKey: ['credential-provisioning'] });
      setCredTarget(null); resetCred();
      setNotice(`Credential for ${r.asset.name} stored at ${r.vault_path} (version ${r.version}) and verified.`);
    },
    onError: (e) => { setCredError(provisioningError(e)); setCred((c) => ({ ...c, password: '' })); },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => assetsApi.delete(id),
    onSuccess: () => {
      invalidate();
      setDeleteTarget(null);
    },
  });

  function openCreate() {
    setForm(EMPTY_FORM);
    setFormError(null);
    resetCred();
    setCredMode(canVault && provisioningReady ? 'now' : 'later');
    setEditing('new');
  }

  function openEdit(asset: Asset) {
    setForm(asset);
    setFormError(null);
    setEditing(asset);
  }

  function submit() {
    setFormError(null);
    if (editing === 'new' && credMode === 'now') {
      setCredError(null);
      createWithCredential.mutate();
    } else if (editing === 'new') {
      createMutation.mutate(form);
    } else if (editing) {
      updateMutation.mutate({ id: editing.id, data: form });
    }
  }

  const pending = createMutation.isPending || updateMutation.isPending || createWithCredential.isPending;

  return (
    <div className="space-y-6">
      <div className="page-header">
        <div>
          <h1 className="page-title">Assets</h1>
          <p className="page-subtitle">Registered infrastructure targets and the OpenBao credential each one uses.</p>
        </div>
        {canCreate && (
          <button onClick={openCreate} className="btn-primary">
            <Plus size={16} /> New Asset
          </button>
        )}
      </div>

      {canVault && <ProvisioningBanner status={provisioning.data} />}
      {notice && (
        <div role="status" className="flex items-center justify-between gap-3 rounded-lg border border-green-500/30 bg-green-500/10 px-4 py-2 text-sm text-green-400">
          <span className="flex items-center gap-2"><CheckCircle2 size={16} /> {notice}</span>
          <button className="text-xs text-gray-400 hover:text-gray-200" onClick={() => setNotice(null)}>Dismiss</button>
        </div>
      )}

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
        <select className="input w-auto" value={criticality} onChange={(e) => { setCriticality(e.target.value); setPage(1); }}>
          <option value="">All criticality</option>
          {CRITICALITIES.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <select className="input w-auto" value={assetType} onChange={(e) => { setAssetType(e.target.value); setPage(1); }}>
          <option value="">All types</option>
          {ASSET_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
      </div>

      {query.isError && <ErrorBanner message={getApiErrorMessage(query.error, 'Failed to load assets.')} />}

      <div className="card overflow-hidden">
        {query.isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-10" />)}
          </div>
        ) : query.data && query.data.items.length === 0 ? (
          <EmptyState message="No assets match these filters." />
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Hostname</th>
                  <th>Type</th>
                  <th>Protocol</th>
                  <th>Environment</th>
                  <th>Criticality</th>
                  <th>Enabled</th>
                  {(canUpdate || canDelete) && <th></th>}
                </tr>
              </thead>
              <tbody>
                {query.data?.items.map((asset) => (
                  <tr key={asset.id}>
                    <td className="font-medium text-gray-100">{asset.name}</td>
                    <td className="text-gray-400">{asset.hostname}</td>
                    <td className="text-gray-400">{asset.asset_type}</td>
                    <td className="text-gray-400">{asset.protocol}</td>
                    <td className="text-gray-400">{asset.environment}</td>
                    <td><span className={CRITICALITY_BADGE[asset.criticality]}>{asset.criticality}</span></td>
                    <td>
                      <span className={asset.enabled ? 'badge-success' : 'badge-neutral'}>
                        {asset.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    {(canUpdate || canDelete) && (
                      <td>
                        <div className="flex justify-end gap-1">
                          {canVault && (
                            <button onClick={() => { resetCred(); setCredTarget(asset); }} className="btn-ghost p-1.5"
                              title="Set or rotate this asset's credential in OpenBao" aria-label={`Set credential for ${asset.name}`}>
                              <KeyRound size={14} />
                            </button>
                          )}
                          {canUpdate && (
                            <button onClick={() => openEdit(asset)} className="btn-ghost p-1.5" aria-label={`Edit ${asset.name}`}>
                              <Pencil size={14} />
                            </button>
                          )}
                          {canDelete && (
                            <button onClick={() => setDeleteTarget(asset)} className="btn-ghost p-1.5 hover:text-red-400">
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
        <Modal title={editing === 'new' ? 'New Asset' : `Edit ${editing.name}`} onClose={() => setEditing(null)}>
          <div className="space-y-4">
            {formError && <ErrorBanner message={formError} />}

            <div className="grid grid-cols-2 gap-3">
              <Field label="Name">
                <input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
              </Field>
              <Field label="Hostname">
                <input className="input" value={form.hostname} onChange={(e) => setForm({ ...form, hostname: e.target.value })} />
              </Field>
              <Field label="IP Address">
                <input className="input" value={form.ip_address} onChange={(e) => setForm({ ...form, ip_address: e.target.value })} />
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
                <select className="input" value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value as Asset['protocol'] })}>
                  {PROTOCOLS.map((p) => <option key={p} value={p}>{p}</option>)}
                </select>
              </Field>
              <Field label="Asset Type">
                <select className="input" value={form.asset_type} onChange={(e) => setForm({ ...form, asset_type: e.target.value as Asset['asset_type'] })}>
                  {ASSET_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
              </Field>
              <Field label="Environment">
                <select className="input" value={form.environment} onChange={(e) => setForm({ ...form, environment: e.target.value as Asset['environment'] })}>
                  {ENVIRONMENTS.map((e) => <option key={e} value={e}>{e}</option>)}
                </select>
              </Field>
              <Field label="Criticality">
                <select className="input" value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value as Asset['criticality'] })}>
                  {CRITICALITIES.map((c) => <option key={c} value={c}>{c}</option>)}
                </select>
              </Field>
              <Field label="Owner">
                <input className="input" value={form.owner ?? ''} onChange={(e) => setForm({ ...form, owner: e.target.value })} />
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
              <Checkbox label="JIT required" checked={form.jit_required} onChange={(v) => setForm({ ...form, jit_required: v })} />
              <Checkbox label="Approval required" checked={form.approval_required} onChange={(v) => setForm({ ...form, approval_required: v })} />
              <Checkbox label="Recording required" checked={form.recording_required} onChange={(v) => setForm({ ...form, recording_required: v })} />
            </div>

            {editing === 'new' && canVault && (
              <fieldset className="space-y-3 rounded-lg border border-navy-700/60 p-4">
                <legend className="px-1 text-sm font-semibold text-gray-200">Credential</legend>
                <div className="flex flex-wrap gap-4 text-sm" role="radiogroup" aria-label="Credential provisioning">
                  <label className="flex items-center gap-2 text-gray-300">
                    <input type="radio" name="credmode" checked={credMode === 'now'} disabled={!provisioningReady}
                      onChange={() => setCredMode('now')} />
                    Provision now in OpenBao
                  </label>
                  <label className="flex items-center gap-2 text-gray-300">
                    <input type="radio" name="credmode" checked={credMode === 'later'} onChange={() => setCredMode('later')} />
                    Later, or in the OpenBao UI
                  </label>
                </div>
                {!provisioningReady && (
                  <p className="text-xs text-amber-400">{provisioning.data?.reason ?? 'Credential provisioning status is unavailable.'}</p>
                )}
                {credMode === 'now' && <CredentialFields status={provisioning.data} value={cred} onChange={setCred} />}
                {credError && <ProvisioningErrorView error={credError} />}
              </fieldset>
            )}

            <div className="flex justify-end gap-2 pt-2">
              <button className="btn-secondary" onClick={() => { setEditing(null); resetCred(); }}>Cancel</button>
              <button className="btn-primary" disabled={pending || (editing === 'new' && credMode === 'now' && !credentialComplete(cred))} onClick={submit}>
                {pending ? 'Saving...' : editing === 'new' ? 'Create Asset' : 'Save Changes'}
              </button>
            </div>
          </div>
        </Modal>
      )}

      {credTarget && (
        <Modal title={`Credential for ${credTarget.name}`} onClose={() => { setCredTarget(null); resetCred(); }}>
          <div className="space-y-4">
            {!provisioningReady && <ProvisioningBanner status={provisioning.data} />}
            <CredentialFields status={provisioning.data} value={cred} onChange={setCred} currentAssetId={credTarget.id} />
            {credError && <ProvisioningErrorView error={credError} />}
            <div className="flex justify-end gap-2 pt-2">
              <button className="btn-secondary" onClick={() => { setCredTarget(null); resetCred(); }}>Cancel</button>
              <button className="btn-primary" disabled={!provisioningReady || !credentialComplete(cred) || setCredential.isPending}
                onClick={() => { setCredError(null); setCredential.mutate(credTarget); }}>
                {setCredential.isPending ? 'Storing and verifying…' : 'Store and verify'}
              </button>
            </div>
          </div>
        </Modal>
      )}

      {deleteTarget && (
        <Modal title="Delete Asset" onClose={() => setDeleteTarget(null)} width="max-w-sm">
          <div className="space-y-4">
            <div className="flex items-start gap-3 text-sm text-gray-300">
              <Server size={18} className="mt-0.5 flex-shrink-0 text-red-400" />
              <p>
                Delete <span className="font-medium text-gray-100">{deleteTarget.name}</span>? This
                soft-deletes the asset — it will disappear from all lists and be blocked if any active
                sessions still reference it.
              </p>
            </div>
            {deleteMutation.isError && (
              <ErrorBanner message={getApiErrorMessage(deleteMutation.error, 'Failed to delete asset.')} />
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
