import { useQuery } from '@tanstack/react-query';
import { healthApi, settingsApi } from '@/api';
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

export default function SettingsPage() {
  const { hasRole } = useAuth();
  const summary = useQuery({ queryKey: ['settings-summary'], queryFn: settingsApi.summary });
  const health = useQuery({ queryKey: ['health-detailed'], queryFn: healthApi.detailed, refetchInterval: 15000 });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-gray-100">Settings</h1>
        <p className="mt-0.5 text-sm text-gray-500">
          {hasRole('ADMIN')
            ? 'Configuration is managed through deployment settings (environment variables) and is read-only here, including for administrators.'
            : 'Read-only view of the platform configuration and service status.'}
        </p>
      </div>

      <section className="card p-5">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-200">Service status</h2>
          {health.data && (
            <span className={(STATUS[health.data.status] ?? STATUS.unhealthy)[0]}>
              Overall: {(STATUS[health.data.status] ?? STATUS.unhealthy)[1]}
            </span>
          )}
        </div>
        {health.isError && <ErrorBanner message={getApiErrorMessage(health.error, 'Service status is unavailable.')} />}
        {health.isLoading ? (
          <Skeleton className="h-40" />
        ) : health.data ? (
          <div className="divide-y divide-navy-800">
            {health.data.services.map((s: ServiceHealth) => {
              const [badge, label] = STATUS[s.status] ?? ['badge-neutral', 'Unknown'];
              return (
                <div key={s.service} className="flex items-start justify-between gap-6 py-2.5">
                  <div className="min-w-0">
                    <p className="text-sm text-gray-200">{SERVICE_NAMES[s.service] ?? s.service}</p>
                    {s.details && <p className="text-xs text-gray-500">{s.details}</p>}
                  </div>
                  <div className="flex shrink-0 items-center gap-3">
                    {s.latency_ms != null && <span className="text-xs text-gray-500">{s.latency_ms} ms</span>}
                    <span className={badge}>{label}</span>
                  </div>
                </div>
              );
            })}
          </div>
        ) : null}
      </section>

      <section className="card p-5">
        <h2 className="mb-2 text-sm font-semibold text-gray-200">Configuration</h2>
        {summary.isError && <ErrorBanner message={getApiErrorMessage(summary.error, 'Configuration is unavailable.')} />}
        {summary.isLoading ? (
          <Skeleton className="h-48" />
        ) : summary.data ? (
          <div className="divide-y divide-navy-800">
            <Row label="Environment" value={`${summary.data.environment} · v${summary.data.version}`} />
            <Row label="Authentication" value={summary.data.authentication} />
            <Row label="Secret provider" value={summary.data.secret_provider} />
            <Row label="Just-in-time grants" value={`default ${summary.data.jit_default_minutes} min, maximum ${summary.data.jit_max_minutes} min`} />
            <Row label="Session timeout" value={`default ${summary.data.session_default_timeout_minutes} min, maximum ${summary.data.session_max_timeout_minutes} min`} />
            <Row label="API rate limit" value={`${summary.data.rate_limit_per_minute}/min per client, sign-in ${summary.data.rate_limit_login_per_minute}/min`} />
            <Row label="Recording storage" value={summary.data.recording_storage_writable ? 'Writable' : 'NOT writable: sessions requiring recording are refused'} />
            <Row label="Recording retention" value={summary.data.recording_retention_days ? `${summary.data.recording_retention_days} days` : '—'} />
            <Row label="SSH recording format" value={summary.data.ssh_recording_format} />
            <Row label="Managed by" value={summary.data.managed_by} />
          </div>
        ) : null}
      </section>
    </div>
  );
}
