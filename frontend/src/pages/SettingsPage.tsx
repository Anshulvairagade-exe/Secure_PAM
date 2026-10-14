import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { authApi, healthApi, riskApi, sessionPolicyApi, settingsApi } from '@/api';
import ThemeToggle from '@/theme/ThemeToggle';
import { useTheme } from '@/theme/ThemeProvider';
import { getApiErrorMessage } from '@/api/errors';
import { ErrorBanner, Skeleton } from '@/components/Feedback';
import { useAuth } from '@/hooks/useAuth';
import type { ServiceHealth } from '@/types';

const STATUS: Record<string, [string, string]> = {
  healthy: ['badge-success', 'Healthy'],
  degraded: ['badge-warning', 'Degraded'],
  unhealthy: ['badge-danger', 'Unavailable'],
  mock: ['badge-info', 'Development stand-in'],
  not_configured: ['badge-neutral', 'Not deployed'],
};

const SERVICE_NAMES: Record<string, string> = {
  database: 'PostgreSQL',
  redis: 'Redis',
  identity_provider: 'Identity provider (Keycloak)',
  vault: 'Secret provider (OpenBao)',
  gateway_ssh: 'SSH gateway',
  gateway_rdp: 'RDP gateway (Guacamole)',
  gateway_web: 'Web gateway',
  siem: 'SIEM forwarding',
  recording_storage: 'Recording storage',
};

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-6 py-2 text-sm">
      <span className="text-gray-500">{label}</span>
      <span className="text-right text-gray-200">{value}</span>
    </div>
  );
}

function SessionPolicyCard({ canEdit }: { canEdit: boolean }) {
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState<string | null>(null);
  const policy = useQuery({ queryKey: ['session-policy'], queryFn: sessionPolicyApi.get });
  const save = useMutation({
    mutationFn: (value: number) => sessionPolicyApi.update(value),
    onSuccess: () => { setDraft(null); void queryClient.invalidateQueries({ queryKey: ['session-policy'] }); },
  });
  const p = policy.data;
  const value = draft ?? String(p?.max_concurrent_sessions ?? '');
  const n = Number(value);
  const valid = p !== undefined && Number.isInteger(n) && n >= p.min_allowed && n <= p.max_allowed;

  return (
    <section className="card p-5" aria-label="Session policy">
      <SectionTitle title="Session policy" scope="app" />
      {policy.isError && <ErrorBanner message={getApiErrorMessage(policy.error, 'Session policy is unavailable.')} />}
      {policy.isLoading ? <Skeleton className="h-10" /> : p && (
        <div className="space-y-2">
          <div className="flex items-center justify-between gap-6 text-sm">
            <label htmlFor="max-sessions" className="text-gray-500">Concurrent sessions per user</label>
            {canEdit ? (
              <span className="flex items-center gap-2">
                <input
                  id="max-sessions" type="number" className="input w-20" min={p.min_allowed} max={p.max_allowed}
                  value={value} onChange={(e) => setDraft(e.target.value)}
                />
                <button
                  className="btn-primary px-3 py-1.5" disabled={!valid || save.isPending || draft === null || n === p.max_concurrent_sessions}
                  onClick={() => save.mutate(n)}
                >
                  {save.isPending ? 'Saving…' : 'Save'}
                </button>
              </span>
            ) : (
              <span className="text-gray-200">{p.max_concurrent_sessions}</span>
            )}
          </div>
          <p className="text-xs text-gray-500">
            A launch beyond this many live sessions is refused. Allowed {p.min_allowed}–{p.max_allowed}; default {p.default}.
            Sessions already running are not ended when the limit is lowered. Changes are audited.
          </p>
          {draft !== null && !valid && <p className="text-xs text-red-400">Enter a whole number from {p.min_allowed} to {p.max_allowed}.</p>}
          {save.isError && <ErrorBanner message={getApiErrorMessage(save.error, 'The limit could not be saved.')} />}
        </div>
      )}
    </section>
  );
}

type Scope = 'browser' | 'app' | 'deploy';
const SCOPE: Record<Scope, [string, string, string]> = {
  browser: ['scope-browser', 'Your browser', 'Stored only in this browser; affects only you.'],
  app: ['scope-app', 'Application · persisted', 'Saved in the SecurePAM database; applies to everyone; changes are audited.'],
  deploy: ['scope-deploy', 'Deployment · read-only', 'Set by environment configuration at deploy time; cannot be changed here.'],
};

function SectionTitle({ title, scope }: { title: string; scope: Scope }) {
  const [cls, label, help] = SCOPE[scope];
  return (
    <div className="mb-3 flex items-center justify-between gap-3">
      <h2 className="section-title">{title}</h2>
      <span className={cls} title={help}>{label}</span>
    </div>
  );
}

function RiskThresholdCard() {
  const queryClient = useQueryClient();
  const summary = useQuery({ queryKey: ['risk-summary', 30], queryFn: () => riskApi.summary(30) });
  const [draft, setDraft] = useState<{ mfa: string; launch: string } | null>(null);
  const t = summary.data?.thresholds;
  const mfa = draft?.mfa ?? String(t?.['risk.mfa_failure_threshold'] ?? '');
  const launch = draft?.launch ?? String(t?.['risk.launch_denial_threshold'] ?? '');
  const save = useMutation({
    mutationFn: () => riskApi.setThresholds({ mfa_failure_threshold: Number(mfa), launch_denial_threshold: Number(launch) }),
    onSuccess: () => { setDraft(null); void queryClient.invalidateQueries({ queryKey: ['risk-summary'] }); },
  });
  const valid = Number.isInteger(Number(mfa)) && Number(mfa) >= 1 && Number(mfa) <= 50
    && Number.isInteger(Number(launch)) && Number(launch) >= 1 && Number(launch) <= 100;
  return (
    <section className="card p-5" aria-label="Risk detection thresholds">
      <SectionTitle title="Risk detection thresholds" scope="app" />
      {summary.isError && <ErrorBanner message={getApiErrorMessage(summary.error, 'Thresholds are unavailable.')} />}
      {summary.isLoading ? <Skeleton className="h-16" /> : t && (
        <div className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="space-y-1 text-sm">
              <span className="text-gray-500">MFA failures within 60 minutes that make a finding HIGH</span>
              <input type="number" min={1} max={50} className="input" value={mfa}
                onChange={(e) => setDraft({ mfa: e.target.value, launch })} />
            </label>
            <label className="space-y-1 text-sm">
              <span className="text-gray-500">Session-launch denials within 60 minutes that raise a finding</span>
              <input type="number" min={1} max={100} className="input" value={launch}
                onChange={(e) => setDraft({ mfa, launch: e.target.value })} />
            </label>
          </div>
          <div className="flex items-center gap-3">
            <button className="btn-primary px-3 py-1.5" disabled={!valid || draft === null || save.isPending} onClick={() => save.mutate()}>
              {save.isPending ? 'Saving…' : 'Save thresholds'}
            </button>
            <p className="text-xs text-gray-500">Used by the Risk Center detector on its next evaluation (every 5 minutes, or “Evaluate now”).</p>
          </div>
          {save.isError && <ErrorBanner message={getApiErrorMessage(save.error, 'The thresholds could not be saved.')} />}
        </div>
      )}
    </section>
  );
}

export default function SettingsPage() {
  const { user, hasPermission } = useAuth();
  const { resolved } = useTheme();
  const summary = useQuery({ queryKey: ['settings-summary'], queryFn: settingsApi.summary });
  const health = useQuery({ queryKey: ['health-detailed'], queryFn: healthApi.detailed, refetchInterval: 15000 });
  const authConfig = useQuery({ queryKey: ['auth-config'], queryFn: authApi.getConfig });
  const d = summary.data;
  // Keycloak account console (where users enrol/replace authenticators), derived from the public OIDC config.
  const accountUrl = authConfig.data?.auth_url?.replace(/\/protocol\/openid-connect\/auth$/, '/account/#/security/signingin');

  return (
    <div className="space-y-6">
      <div className="page-header">
        <div>
          <h1 className="page-title">Settings</h1>
          <p className="page-subtitle">
            Each section shows where its value lives: your browser, the SecurePAM database (persisted, audited), or the
            deployment configuration (read-only here). No secrets are ever shown.
          </p>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <section className="card p-5" aria-label="Profile">
          <SectionTitle title="Profile & sign-in" scope="deploy" />
          {summary.isLoading ? <Skeleton className="h-24" /> : (
            <div className="divide-y divide-navy-800">
              <Row label="Name" value={user?.full_name ?? '—'} />
              <Row label="Username" value={<span className="font-mono">{user?.username}</span>} />
              <Row label="Roles" value={user?.roles?.join(', ') || 'none'} />
              <Row label="Sign-in" value={d?.authentication ?? '—'} />
              <Row label="Multi-factor authentication" value={d?.mfa_provider ?? '—'} />
              {d?.mfa_self_service && accountUrl ? (
                <Row label="Manage your authenticator" value={
                  <a className="text-blue-400 hover:underline" href={accountUrl} target="_blank" rel="noopener noreferrer">
                    Keycloak account security ↗
                  </a>} />
              ) : (
                <Row label="Manage your authenticator" value={<span className="text-gray-500">Not applicable to development accounts</span>} />
              )}
            </div>
          )}
        </section>

        <section className="card p-5" aria-label="Appearance">
          <SectionTitle title="Appearance" scope="browser" />
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="text-sm text-gray-200">Colour theme</p>
              <p className="text-xs text-gray-500">Showing {resolved}. “System” follows your operating system's setting.</p>
            </div>
            <ThemeToggle />
          </div>
        </section>
      </div>

      <SessionPolicyCard canEdit={hasPermission('settings:update')} />
      {hasPermission('risk:manage') && <RiskThresholdCard />}

      <section className="card p-5">
        <div className="mb-3 flex items-center justify-between gap-3">
          <h2 className="section-title">Integrations & service health</h2>
          <div className="flex items-center gap-2">
            {health.data && (
              <span className={(STATUS[health.data.status] ?? STATUS.unhealthy)[0]}>
                Overall: {(STATUS[health.data.status] ?? STATUS.unhealthy)[1]}
              </span>
            )}
            <span className="scope-deploy">Live status</span>
          </div>
        </div>
        {health.isError && <ErrorBanner message={getApiErrorMessage(health.error, 'Service status is unavailable.')} />}
        {health.isLoading ? <Skeleton className="h-40" /> : health.data ? (
          <div className="divide-y divide-navy-800">
            {health.data.services.map((svc: ServiceHealth) => {
              const [badge, label] = STATUS[svc.status] ?? ['badge-neutral', 'Unknown'];
              return (
                <div key={svc.service} className="flex items-start justify-between gap-6 py-2.5">
                  <div className="min-w-0">
                    <p className="text-sm text-gray-200">{SERVICE_NAMES[svc.service] ?? svc.service}</p>
                    {svc.details && <p className="text-xs text-gray-500">{svc.details}</p>}
                  </div>
                  <div className="flex shrink-0 items-center gap-3">
                    {svc.latency_ms != null && <span className="text-xs text-gray-500">{svc.latency_ms} ms</span>}
                    <span className={badge}>{label}</span>
                  </div>
                </div>
              );
            })}
          </div>
        ) : null}
      </section>

      <div className="grid gap-6 lg:grid-cols-2">
        <section className="card p-5">
          <SectionTitle title="Security & audit" scope="deploy" />
          {summary.isError && <ErrorBanner message={getApiErrorMessage(summary.error, 'Configuration is unavailable.')} />}
          {summary.isLoading ? <Skeleton className="h-40" /> : d ? (
            <div className="divide-y divide-navy-800">
              <Row label="Keycloak MFA-failure import" value={d.mfa_failure_sync_enabled ? 'Enabled' : 'Disabled'} />
              <Row label="SIEM event forwarding" value={d.siem_forwarding_enabled ? 'Enabled (JSON event file)' : 'Disabled'} />
              <Row label="Secret provider" value={d.secret_provider === 'mock' ? 'Development stand-in (mock)' : 'OpenBao'} />
              <Row label="Credential provisioning" value={d.credential_provisioning_configured ? 'Configured (writer identity)' : 'Not configured'} />
              <Row label="OpenBao web UI link" value={d.openbao_ui_configured ? 'Configured' : 'Not configured'} />
              <Row label="Recording storage" value={d.recording_storage_writable ? 'Writable' : 'NOT writable: sessions requiring recording are refused'} />
              <Row label="Recording retention" value={d.recording_retention_days ? `${d.recording_retention_days} days` : '—'} />
              <Row label="Notifications" value={<span className="text-gray-500">Not implemented (no delivery channel)</span>} />
            </div>
          ) : null}
        </section>

        <section className="card p-5">
          <SectionTitle title="Access & session limits" scope="deploy" />
          {summary.isLoading ? <Skeleton className="h-40" /> : d ? (
            <div className="divide-y divide-navy-800">
              <Row label="Environment" value={`${d.environment} · v${d.version}`} />
              <Row label="Just-in-time grants" value={`default ${d.jit_default_minutes} min, max ${d.jit_max_minutes} min`} />
              <Row label="Session timeout" value={`default ${d.session_default_timeout_minutes} min, max ${d.session_max_timeout_minutes} min`} />
              <Row label="API rate limit" value={`${d.rate_limit_per_minute}/min per client, sign-in ${d.rate_limit_login_per_minute}/min`} />
              <Row label="SSH recording format" value={d.ssh_recording_format} />
            </div>
          ) : null}
        </section>
      </div>
    </div>
  );
}
