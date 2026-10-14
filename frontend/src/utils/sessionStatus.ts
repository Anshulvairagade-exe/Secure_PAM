/** One place for how a session status is shown, so every page labels states the same way. */
export const LIVE_SESSION_STATUSES = new Set(['CREATED', 'STARTING', 'ACTIVE', 'TERMINATING']);

export const SESSION_STATUS_BADGE: Record<string, string> = {
  CREATED: 'badge-neutral',
  STARTING: 'badge-warning',
  ACTIVE: 'badge-success',
  TERMINATING: 'badge-warning',
  TERMINATED: 'badge-danger',
  COMPLETED: 'badge-neutral',
  EXPIRED: 'badge-neutral',
  FAILED: 'badge-danger',
};

export const SESSION_STATUS_LABEL: Record<string, string> = {
  STARTING: 'Starting (not connected yet)',
  ACTIVE: 'Active',
  TERMINATING: 'Terminating',
  TERMINATED: 'Terminated by admin',
  COMPLETED: 'Ended',
  EXPIRED: 'Expired',
  FAILED: 'Failed',
  CREATED: 'Created',
};

export function sessionDuration(start?: string | null, end?: string | null, now = Date.now()): string {
  if (!start) return '—';
  const seconds = Math.max(0, Math.floor(((end ? Date.parse(end) : now) - Date.parse(start)) / 1000));
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return h ? `${h}h ${m}m` : `${m}m ${(seconds % 60).toString().padStart(2, '0')}s`;
}
