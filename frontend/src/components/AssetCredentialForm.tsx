import { useState } from 'react';
import { ExternalLink, KeyRound, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { AxiosError } from 'axios';
import type { CredentialInput, ProvisioningErrorBody, ProvisioningStatus } from '@/types';

/** Turns a provisioning failure into stage + recovery text (never contains the secret). */
export function provisioningError(e: unknown): ProvisioningErrorBody | { detail: string; recovery?: string } {
  const data = (e as AxiosError<Partial<ProvisioningErrorBody> & { detail?: unknown }>)?.response?.data;
  if (data && typeof data.stage === 'string') return data as ProvisioningErrorBody;
  return { detail: typeof data?.detail === 'string' ? data.detail : 'The request failed.' };
}

export function ProvisioningErrorView({ error }: { error: ReturnType<typeof provisioningError> }) {
  return (
    <div role="alert" className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm">
      <p className="font-medium text-red-400">
        {'stage' in error ? `Failed at “${error.stage}”: ${error.detail}` : error.detail}
      </p>
      {'recovery' in error && error.recovery && <p className="mt-1 text-xs text-gray-400">{error.recovery}</p>}
      {'written_version' in error && error.written_version != null && (
        <p className="mt-1 text-xs text-amber-400">Version {error.written_version} was written to OpenBao but is not bound to the asset.</p>
      )}
    </div>
  );
}

export function OpenBaoButton({ status }: { status?: ProvisioningStatus }) {
  if (!status?.openbao_ui_url) {
    return (
      <button type="button" className="btn-secondary" disabled title="OPENBAO_UI_URL is not configured for this deployment">
        <ExternalLink size={15} /> Open OpenBao Vault
      </button>
    );
  }
  return (
    <a className="btn-secondary" href={status.openbao_ui_url} target="_blank" rel="noopener noreferrer"
      title="Opens the OpenBao web UI (private address). Sign in there with your administrator identity.">
      <ExternalLink size={15} /> Open OpenBao Vault
    </a>
  );
}

export function ProvisioningBanner({ status }: { status?: ProvisioningStatus }) {
  if (!status) return null;
  return (
    <div className={`flex flex-wrap items-center justify-between gap-3 rounded-lg border px-4 py-3 text-sm ${
      status.configured ? 'border-green-500/30 bg-green-500/10' : 'border-amber-500/30 bg-amber-500/10'}`}>
      <div className="flex items-start gap-2">
        {status.configured ? <ShieldCheck size={18} className="mt-0.5 text-green-400" /> : <ShieldAlert size={18} className="mt-0.5 text-amber-400" />}
        <div>
          <p className={status.configured ? 'font-medium text-green-400' : 'font-medium text-amber-400'}>
            {status.configured ? 'Credential provisioning is configured' : 'Credential provisioning is not configured'}
          </p>
          <p className="text-xs text-gray-400">
            {status.configured
              ? 'New assets can store their credential in OpenBao in the same step; it is verified before it is bound.'
              : `${status.reason} Assets can still be created; store their credential later.`}
          </p>
        </div>
      </div>
      <OpenBaoButton status={status} />
    </div>
  );
}

/** Masked credential entry bound to an APPROVED reference name; the browser never chooses a path. */
export function CredentialFields({ status, value, onChange, currentAssetId }: {
  status?: ProvisioningStatus; value: CredentialInput; onChange: (v: CredentialInput) => void; currentAssetId?: string;
}) {
  const [show, setShow] = useState(false);
  const refs = status?.references ?? [];
  return (
    <div className="space-y-3">
      <label className="block space-y-1">
        <span className="text-xs font-medium text-gray-400">Approved credential reference</span>
        <select className="input" value={value.secret_name} onChange={(e) => onChange({ ...value, secret_name: e.target.value })}>
          <option value="">Choose…</option>
          {refs.map((r) => {
            const taken = r.bound_asset_id !== null && r.bound_asset_id !== currentAssetId;
            return (
              <option key={r.name} value={r.name} disabled={taken}>
                {r.name}{taken ? ` (bound to ${r.bound_asset_name ?? 'another asset'})` : r.bound_asset_id ? ' (this asset)' : ''}
              </option>
            );
          })}
        </select>
        <span className="block text-xs text-gray-500">
          Stored at <span className="font-mono">{value.secret_name ? refs.find((r) => r.name === value.secret_name)?.path : 'securepam/assets/…'}</span>.
          New references are added by an operator (policy + allowlist), not here.
        </span>
      </label>
      <div className="grid grid-cols-2 gap-3">
        <label className="block space-y-1">
          <span className="text-xs font-medium text-gray-400">Username</span>
          <input className="input" autoComplete="off" value={value.username} onChange={(e) => onChange({ ...value, username: e.target.value })} />
        </label>
        <label className="block space-y-1">
          <span className="text-xs font-medium text-gray-400">Password</span>
          <div className="relative">
            <input className="input pr-14" type={show ? 'text' : 'password'} autoComplete="new-password"
              value={value.password} onChange={(e) => onChange({ ...value, password: e.target.value })} />
            <button type="button" className="kbd-focus absolute right-2 top-1/2 -translate-y-1/2 text-xs text-gray-500 hover:text-gray-200"
              onClick={() => setShow((v) => !v)} aria-label={show ? 'Hide password' : 'Show password'}>{show ? 'Hide' : 'Show'}</button>
          </div>
        </label>
      </div>
      <p className="flex items-center gap-1.5 text-xs text-gray-500">
        <KeyRound size={12} /> Sent once over TLS to SecurePAM, written by the credential-writer identity, verified, then discarded.
        It is never shown again or stored in SecurePAM's database.
      </p>
    </div>
  );
}

export const EMPTY_CREDENTIAL: CredentialInput = { secret_name: '', username: '', password: '', secret_type: 'PASSWORD' };
export const credentialComplete = (c: CredentialInput) => Boolean(c.secret_name && c.username.trim() && c.password);
