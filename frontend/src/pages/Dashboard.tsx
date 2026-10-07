import { useQuery } from '@tanstack/react-query';
import { formatDistanceToNow } from 'date-fns';
import {
  MonitorPlay,
  FileClock,
  Flame,
  CalendarClock,
  ShieldAlert,
  KeyRound,
  Server,
  HardDrive,
} from 'lucide-react';
import { dashboardApi } from '@/api';
import { getApiErrorMessage } from '@/api/errors';
import { ErrorBanner, EmptyState, Skeleton } from '@/components/Feedback';
import type { DashboardActivity, Severity } from '@/types';

const SEVERITY_BADGE: Record<Severity, string> = {
  INFO: 'badge-info',
  LOW: 'badge-success',
  MEDIUM: 'badge-warning',
  HIGH: 'badge-danger',
  CRITICAL: 'badge-critical',
};

function StatCard({
  label,
  value,
  icon: Icon,
  accent,
}: {
  label: string;
  value: number | string;
  icon: React.ElementType;
  accent: 'blue' | 'green' | 'amber' | 'red' | 'purple' | 'cyan';
}) {
  return (
    <div className="stat-card" data-accent={accent}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-gray-500">{label}</p>
          <p className="mt-2 text-2xl font-bold text-gray-100">{value}</p>
        </div>
        <Icon size={18} className="text-gray-500" />
      </div>
    </div>
  );
}

export default function Dashboard() {
  const summaryQuery = useQuery({
    queryKey: ['dashboard', 'summary'],
    queryFn: dashboardApi.getSummary,
    refetchInterval: 30_000,
  });

  const activityQuery = useQuery({
    queryKey: ['dashboard', 'activity'],
    queryFn: () => dashboardApi.getActivity(15),
    refetchInterval: 30_000,
  });

  const s = summaryQuery.data;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-gray-100">Security Dashboard</h1>
        <p className="mt-0.5 text-sm text-gray-500">Live privileged access overview</p>
      </div>

      {summaryQuery.isError && (
        <ErrorBanner message={getApiErrorMessage(summaryQuery.error, 'Failed to load dashboard summary.')} />
      )}

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4">
        {summaryQuery.isLoading ? (
          Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} className="stat-card h-24" />)
        ) : (
          <>
            <StatCard label="Active Sessions" value={s?.active_sessions ?? 0} icon={MonitorPlay} accent="blue" />
            <StatCard label="Pending Requests" value={s?.pending_requests ?? 0} icon={FileClock} accent="amber" />
            <StatCard label="High Risk Sessions" value={s?.high_risk_sessions ?? 0} icon={Flame} accent="red" />
            <StatCard label="Today's Sessions" value={s?.today_sessions ?? 0} icon={CalendarClock} accent="cyan" />
            <StatCard label="Failed MFA Attempts" value={s?.failed_mfa_attempts ?? 0} icon={ShieldAlert} accent="red" />
            <StatCard label="Active JIT Grants" value={s?.jit_grants_active ?? 0} icon={KeyRound} accent="green" />
            <StatCard label="Registered Assets" value={s?.registered_assets ?? 0} icon={Server} accent="purple" />
            <StatCard
              label="Recording Storage"
              value={`${(s?.recording_storage_mb ?? 0).toFixed(1)} MB`}
              icon={HardDrive}
              accent="blue"
            />
          </>
        )}
      </div>

      <div className="card p-5">
        <h2 className="mb-4 text-sm font-semibold text-gray-200">Recent Security Events</h2>

        {activityQuery.isLoading && (
          <div className="space-y-2">
            {Array.from({ length: 4 }).map((_, i) => (
              <Skeleton key={i} className="h-10" />
            ))}
          </div>
        )}

        {activityQuery.isError && (
          <ErrorBanner message={getApiErrorMessage(activityQuery.error, 'Failed to load recent activity.')} />
        )}

        {activityQuery.data && activityQuery.data.length === 0 && (
          <EmptyState message="No security events yet. Activity will appear here as requests, approvals, and sessions occur." />
        )}

        <div className="space-y-1">
          {activityQuery.data?.map((event: DashboardActivity) => (
            <div
              key={event.event_id}
              className="flex items-center justify-between gap-3 rounded-lg px-3 py-2.5 hover:bg-navy-800/40"
            >
              <div className="flex items-center gap-3 overflow-hidden">
                <span className={SEVERITY_BADGE[event.severity]}>{event.severity}</span>
                <p className="truncate text-sm text-gray-300">
                  <span className="font-medium text-gray-100">{event.actor}</span>{' '}
                  {event.action.split('_').join(' ').toLowerCase()}
                  {event.target && <span className="text-gray-500"> · {event.target}</span>}
                </p>
              </div>
              <span className="flex-shrink-0 text-xs text-gray-500">
                {formatDistanceToNow(new Date(event.timestamp), { addSuffix: true })}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
