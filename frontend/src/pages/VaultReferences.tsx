import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { KeyRound } from 'lucide-react';
import { assetsApi, credentialRefsApi } from '@/api';
import { getApiErrorMessage } from '@/api/errors';
import { ErrorBanner, EmptyState, Skeleton } from '@/components/Feedback';
import { useAuth } from '@/hooks/useAuth';
import type { Asset, CredentialRefCheckStatus, SecretType } from '@/types';

const SECRET_TYPES: SecretType[] = ['PASSWORD', 'SSH_KEY', 'API_KEY', 'CERTIFICATE'];

/** Safe, user-facing label for each check status. The detail message comes
 *  from the backend; only status/reason is ever rendered — never a secret. */
const CHECK_LABELS: Record<CredentialRefCheckStatus, { label: string; className: string }> = {
  ok: { label: 'Readable', className: 'badge-success' },
  secret_not_found: { label: 'Secret missing', className: 'badge-warning' },
  access_denied: { label: 'Permission denied', className: 'badge-danger' },
  unavailable: { label: 'Provider unavailable', className: 'badge-danger' },
  malformed: { label: 'Malformed secret', className: 'badge-warning' },
  no_reference: { label: 'No reference', className: 'badge-neutral' },
};

export default function VaultReferences() {
  const { hasPermission } = useAuth();
  const canManage = hasPermission('vault:manage');
  const assets = useQuery({
    queryKey: ['assets', { page_size: 100 }],
    queryFn: () => assetsApi.list({ page: 1, page_size: 100 }),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-gray-100">Vault References</h1>
        <p className="mt-0.5 text-sm text-gray-500">
          Each asset points at a secret in the configured provider. Only the reference is stored
          here; secret values stay in OpenBao and are never sent to the browser.
        </p>
      </div>

      {assets.isError && <ErrorBanner message={getApiErrorMessage(assets.error, 'Failed to load assets.')} />}

      <div className="card overflow-hidden">
        {assets.isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-12" />)}
          </div>
        ) : assets.data && assets.data.items.length === 0 ? (
          <EmptyState message="No assets registered." />
        ) : (
          <div className="divide-y divide-navy-800">
            {assets.data?.items.map((asset) => (
              <AssetReferenceRow key={asset.id} asset={asset} canManage={canManage} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function AssetReferenceRow({ asset, canManage }: { asset: Asset; canManage: boolean }) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [secretName, setSecretName] = useState('');
  const [secretType, setSecretType] = useState<SecretType>('PASSWORD');
  const [username, setUsername] = useState('');

  const ref = useQuery({
    queryKey: ['credential-ref', asset.id],
    queryFn: () => credentialRefsApi.get(asset.id),
  });
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['credential-ref', asset.id] });

  const save = useMutation({
    mutationFn: () =>
      credentialRefsApi.set(asset.id, {
        secret_name: secretName.trim(),
        secret_type: secretType,
        ...(username.trim() && { username: username.trim() }),
      }),
    onSuccess: () => { setEditing(false); setSecretName(''); setUsername(''); void invalidate(); },
  });
  const deactivate = useMutation({
    mutationFn: () => credentialRefsApi.deactivate(asset.id),
    onSuccess: () => void invalidate(),
  });
  const check = useMutation({
    mutationFn: () => credentialRefsApi.check(asset.id),
  });

  return (
    <div className="space-y-3 p-4">
      <div className="flex items-center justify-between gap-4">
        <div className="min-w-0">
          <p className="font-medium text-gray-200">{asset.name}</p>
          <p className="text-xs text-gray-500">{asset.protocol} · {asset.environment}</p>
        </div>
        <div className="flex min-w-0 items-center gap-3 text-sm">
          {ref.isLoading ? (
            <Skeleton className="h-5 w-48" />
          ) : ref.data ? (
            <span className="flex min-w-0 items-center gap-2 text-gray-300">
              <KeyRound size={14} className="shrink-0 text-green-400" />
              <span className="truncate font-mono text-xs">{ref.data.vault_path}</span>
              <span className="badge-neutral">{ref.data.secret_type}</span>
              {ref.data.username && <span className="text-xs text-gray-500">user {ref.data.username}</span>}
            </span>
          ) : (
            <span className="badge-warning">No credential reference</span>
          )}
          {canManage && !editing && (
            <button className="btn-secondary px-2 py-1 text-xs" onClick={() => setEditing(true)}>
              {ref.data ? 'Change' : 'Set'}
            </button>
          )}
          {canManage && ref.data && !editing && (
            <button
              className="btn-secondary px-2 py-1 text-xs"
              disabled={check.isPending}
              onClick={() => check.mutate()}
            >
              {check.isPending ? 'Checking…' : 'Check'}
            </button>
          )}
          {canManage && ref.data && !editing && (
            <button
              className="btn-ghost px-2 py-1 text-xs hover:text-red-400"
              disabled={deactivate.isPending}
              onClick={() => deactivate.mutate()}
            >
              Deactivate
            </button>
          )}
        </div>
      </div>

      {editing && (
        <form
          className="flex flex-wrap items-center gap-2"
          onSubmit={(e) => { e.preventDefault(); save.mutate(); }}
        >
          <input
            className="input w-56"
            placeholder="Secret name, e.g. test-linux-01"
            value={secretName}
            onChange={(e) => setSecretName(e.target.value)}
            required
          />
          <select className="input w-auto" value={secretType} onChange={(e) => setSecretType(e.target.value as SecretType)}>
            {SECRET_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <input
            className="input w-40"
            placeholder="Username (optional)"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <button type="submit" className="btn-primary px-3 py-1.5 text-sm" disabled={save.isPending}>Save</button>
          <button type="button" className="btn-ghost px-3 py-1.5 text-sm" onClick={() => setEditing(false)}>Cancel</button>
          <p className="w-full text-xs text-gray-500">
            Stored as &lt;prefix&gt;/assets/&lt;secret name&gt;. Put the secret itself into OpenBao; it is never entered here.
          </p>
        </form>
      )}

      {(save.isError || deactivate.isError || ref.isError) && (
        <ErrorBanner message={getApiErrorMessage(save.error ?? deactivate.error ?? ref.error, 'Credential reference update failed.')} />
      )}

      {check.data && (
        <p className="flex flex-wrap items-center gap-2 text-xs" role="status">
          <span className={CHECK_LABELS[check.data.status].className}>
            {CHECK_LABELS[check.data.status].label}
          </span>
          <span className="text-gray-400">{check.data.message}</span>
        </p>
      )}
      {check.isError && (
        <ErrorBanner message={getApiErrorMessage(check.error, 'Credential reference check failed.')} />
      )}
    </div>
  );
}
