import { describe, expect, it, vi, beforeEach } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import { renderPage } from './render';

const api = vi.hoisted(() => ({
  authApi: { getConfig: vi.fn(() => Promise.resolve({ dev_mode: true })) },
  usersApi: { list: vi.fn(), get: vi.fn(), access: vi.fn(), terminateAll: vi.fn() },
  rolesApi: { list: vi.fn() },
  sessionsApi: { terminate: vi.fn() },
  jitGrantsApi: { revoke: vi.fn() },
  sessionPolicyApi: { get: vi.fn(), update: vi.fn() },
  settingsApi: { summary: vi.fn() },
  healthApi: { detailed: vi.fn() },
}));
vi.mock('@/api', () => api);
const auth = vi.hoisted(() => ({ perms: new Set<string>(['sessions:terminate', 'settings:update', 'users:update']) }));
vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    user: { id: 'me', username: 'admin', roles: ['ADMIN'], permissions: [] },
    hasRole: () => true,
    hasPermission: (p: string) => auth.perms.has(p),
  }),
}));

import Users from '@/pages/Users';
import SettingsPage from '@/pages/SettingsPage';
import UserSessionsPanel from '@/components/UserSessionsPanel';

const lastButton = (name: string) => { const all = screen.getAllByRole('button', { name }); return all[all.length - 1]; };
const never = () => new Promise(() => {});
const axiosError = (status: number, detail: string) =>
  Object.assign(new Error(detail), { isAxiosError: true, response: { status, data: { detail } } });

const live = {
  id: 's1', session_number: 'SES-LIVE1', asset_name: 'Kali Lab SSH', protocol: 'SSH', status: 'ACTIVE',
  start_time: '2026-10-14T00:00:00Z', end_time: null, created_at: '2026-10-14T00:00:00Z',
  recording_status: 'RECORDING', jit_grant_id: 'g1',
};
const ended = { ...live, id: 's2', session_number: 'SES-OLD22', status: 'TERMINATED', end_time: '2026-10-14T00:05:00Z', recording_status: 'COMPLETED' };
const access = {
  user_id: 'u2', username: 'operator', session_limit: 2, active_sessions: 1, sessions: [live, ended],
  ready_grants: [{ id: 'g9', request_id: 'r9', request_number: 'REQ-READY', asset_name: 'Kali Lab SSH', protocol: 'SSH', expires_at: '2026-10-14T01:00:00Z' }],
};
const outcome = (over = {}) => ({
  session_id: 's1', session_number: 'SES-LIVE1', ok: true, status: 'TERMINATED', gateway: 'closed',
  recording: 'COMPLETED', grant_revoked: true, errors: [], ...over,
});

beforeEach(() => { vi.resetAllMocks(); auth.perms = new Set(['sessions:terminate', 'settings:update', 'users:update']); });

describe('UserSessionsPanel', () => {
  it('shows loading, then sessions and unused grants as separate things', async () => {
    api.usersApi.access.mockReturnValueOnce(never());
    const { container, unmount } = renderPage(<UserSessionsPanel userId="u2" onClose={() => {}} />);
    expect(container.querySelector('.animate-pulse')).not.toBeNull();
    unmount();
    api.usersApi.access.mockResolvedValue(access);
    renderPage(<UserSessionsPanel userId="u2" onClose={() => {}} />);
    expect(await screen.findByText('SES-LIVE1')).toBeInTheDocument();
    expect(screen.getByText('1 of 2 concurrent sessions in use')).toBeInTheDocument();
    expect(screen.getByText('Active')).toBeInTheDocument();
    expect(screen.getByText('Terminated by admin')).toBeInTheDocument();
    expect(screen.getByText(/Ready to connect/)).toBeInTheDocument();
    expect(screen.getByText(/REQ-READY/)).toBeInTheDocument();
    expect(screen.getAllByText('Terminate')).toHaveLength(1); // only the live one
  });

  it('shows empty and error states', async () => {
    api.usersApi.access.mockResolvedValue({ ...access, sessions: [], ready_grants: [], active_sessions: 0 });
    const first = renderPage(<UserSessionsPanel userId="u2" onClose={() => {}} />);
    expect(await screen.findByText(/has not started any sessions/)).toBeInTheDocument();
    expect(screen.getByText(/No unused approved grants/)).toBeInTheDocument();
    first.unmount();
    api.usersApi.access.mockRejectedValue(axiosError(403, 'Missing permission: sessions:terminate'));
    renderPage(<UserSessionsPanel userId="u2" onClose={() => {}} />);
    expect(await screen.findByText(/Missing permission/)).toBeInTheDocument();
  });

  it('asks for confirmation, then terminates once and reports the real outcome', async () => {
    api.usersApi.access.mockResolvedValue(access);
    api.sessionsApi.terminate.mockResolvedValue({ complete: true, result: outcome() });
    renderPage(<UserSessionsPanel userId="u2" onClose={() => {}} />);
    fireEvent.click(await screen.findByText('Terminate'));
    expect(api.sessionsApi.terminate).not.toHaveBeenCalled(); // nothing happens before confirming
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'incident 42' } });
    const confirm = lastButton('Terminate');
    fireEvent.click(confirm);
    fireEvent.click(confirm);
    await waitFor(() => expect(api.sessionsApi.terminate).toHaveBeenCalledTimes(1));
    expect(api.sessionsApi.terminate).toHaveBeenCalledWith('s1', 'incident 42');
    expect(await screen.findByText(/gateway connection closed/)).toBeInTheDocument();
    expect(screen.getByText(/grant revoked/)).toBeInTheDocument();
  });

  it('cancelling the dialog does nothing', async () => {
    api.usersApi.access.mockResolvedValue(access);
    renderPage(<UserSessionsPanel userId="u2" onClose={() => {}} />);
    fireEvent.click(await screen.findByText('Terminate'));
    fireEvent.click(screen.getByText('Cancel'));
    expect(api.sessionsApi.terminate).not.toHaveBeenCalled();
    expect(screen.queryByText('Confirm')).toBeNull();
  });

  it('reports a partial failure honestly and never says terminated', async () => {
    api.usersApi.access.mockResolvedValue(access);
    api.usersApi.terminateAll.mockResolvedValue({
      user_id: 'u2', complete: false, terminated: 0,
      results: [outcome({ ok: false, status: 'TERMINATING', gateway: 'failed', recording: null, grant_revoked: null,
        errors: ['The gateway connection could not be closed (ConnectionError).'] })],
    });
    renderPage(<UserSessionsPanel userId="u2" onClose={() => {}} />);
    await screen.findByText('SES-LIVE1');
    fireEvent.click(screen.getByText('Terminate all sessions'));
    fireEvent.click(lastButton('Terminate'));
    expect(await screen.findByText(/Not everything could be completed/)).toBeInTheDocument();
    expect(screen.getByText(/still TERMINATING/)).toBeInTheDocument();
    expect(screen.getByText(/could NOT be closed/)).toBeInTheDocument();
  });

  it('shows the server error when an action is refused', async () => {
    api.usersApi.access.mockResolvedValue(access);
    api.sessionsApi.terminate.mockRejectedValue(axiosError(403, 'You are not authorized to terminate this session.'));
    renderPage(<UserSessionsPanel userId="u2" onClose={() => {}} />);
    fireEvent.click(await screen.findByText('Terminate'));
    fireEvent.click(lastButton('Terminate'));
    expect(await screen.findByText(/not authorized/)).toBeInTheDocument();
  });

  it('revokes an unused grant after confirmation', async () => {
    api.usersApi.access.mockResolvedValue(access);
    api.jitGrantsApi.revoke.mockResolvedValue({ id: 'g9', status: 'REVOKED', sessions_ended: 0 });
    renderPage(<UserSessionsPanel userId="u2" onClose={() => {}} />);
    fireEvent.click(await screen.findByText('Revoke grant'));
    fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));
    await waitFor(() => expect(api.jitGrantsApi.revoke).toHaveBeenCalledWith('g9'));
  });
});

describe('Users page session column', () => {
  const user = {
    id: 'u2', username: 'operator', full_name: 'Demo Operator', email: 'op@x', is_active: true, is_system_user: false,
    mfa_enabled: false, external_id: null, identity_source: 'development account', roles: [], last_login: null,
    created_at: '2026-10-01T00:00:00Z', active_sessions: 2,
  };
  it('shows the active count and View sessions for admins only', async () => {
    api.usersApi.list.mockResolvedValue({ items: [user], total: 1, page: 1, page_size: 25, pages: 1 });
    api.rolesApi.list.mockResolvedValue([]);
    api.usersApi.access.mockResolvedValue(access);
    const first = renderPage(<Users />);
    expect(await screen.findByText('2 active')).toBeInTheDocument();
    fireEvent.click(screen.getByText('View sessions'));
    expect(await screen.findByText('SES-LIVE1')).toBeInTheDocument();
    first.unmount();
    auth.perms = new Set();
    renderPage(<Users />);
    expect(await screen.findByText('2 active')).toBeInTheDocument();
    expect(screen.queryByText('View sessions')).toBeNull();
  });
});

describe('Session policy', () => {
  const policy = { max_concurrent_sessions: 2, min_allowed: 1, max_allowed: 20, default: 2 };
  beforeEach(() => {
    api.settingsApi.summary.mockReturnValue(never());
    api.healthApi.detailed.mockReturnValue(never());
  });

  it('lets an admin change the limit within bounds', async () => {
    api.sessionPolicyApi.get.mockResolvedValue(policy);
    api.sessionPolicyApi.update.mockResolvedValue({ ...policy, max_concurrent_sessions: 3 });
    renderPage(<SettingsPage />);
    const input = await screen.findByLabelText('Concurrent sessions per user');
    fireEvent.change(input, { target: { value: '99' } });
    expect(screen.getByText(/Enter a whole number from 1 to 20/)).toBeInTheDocument();
    expect(screen.getByText('Save')).toBeDisabled();
    fireEvent.change(input, { target: { value: '3' } });
    fireEvent.click(screen.getByText('Save'));
    await waitFor(() => expect(api.sessionPolicyApi.update).toHaveBeenCalledWith(3));
  });

  it('is read-only without settings:update', async () => {
    auth.perms = new Set();
    api.sessionPolicyApi.get.mockResolvedValue(policy);
    renderPage(<SettingsPage />);
    expect(await screen.findByText('Concurrent sessions per user')).toBeInTheDocument();
    expect(screen.queryByText('Save')).toBeNull();
  });

  it('shows the server refusal', async () => {
    api.sessionPolicyApi.get.mockResolvedValue(policy);
    api.sessionPolicyApi.update.mockRejectedValue(axiosError(403, 'Missing permission: settings:update'));
    renderPage(<SettingsPage />);
    fireEvent.change(await screen.findByLabelText('Concurrent sessions per user'), { target: { value: '4' } });
    fireEvent.click(screen.getByText('Save'));
    expect(await screen.findByText(/Missing permission: settings:update/)).toBeInTheDocument();
  });
});
