import { describe, expect, it, vi, beforeEach } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import { renderPage } from './render';

const api = vi.hoisted(() => ({
  sessionsApi: { list: vi.fn(), get: vi.fn(), launchSSH: vi.fn(), terminate: vi.fn() },
  jitGrantsApi: { revoke: vi.fn() },
  recordingsApi: { list: vi.fn(), terminalCast: vi.fn() },
}));
vi.mock('@/api', () => api);
vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    user: { id: 'admin1', username: 'admin', roles: ['ADMIN'], permissions: ['sessions:terminate'] },
    hasRole: (role: string) => role === 'ADMIN',
    hasPermission: () => true,
    hasAnyRole: (roles: string[]) => roles.includes('ADMIN'),
  }),
}));

import AdminSessions from '@/pages/AdminSessions';
import Recordings from '@/pages/Recordings';

const page = <T,>(items: T[]) => ({ items, total: items.length, page: 1, page_size: 20, pages: 1 });
const axiosError = (status: number, detail: string) =>
  Object.assign(new Error(detail), { isAxiosError: true, response: { status, data: { detail } } });

const live = {
  id: 's-live', session_number: 'SES-LIVE', user_id: 'op-user-id-1', asset_name: 'Kali Lab SSH',
  protocol: 'SSH', status: 'ACTIVE', start_time: '2026-10-13T10:00:00Z', end_time: null,
  jit_grant_id: 'grant-1', recording_id: null, request_id: 'r1',
};
const done = {
  id: 's-done', session_number: 'SES-DONE', user_id: 'op-user-id-2', asset_name: 'WIN-01',
  protocol: 'RDP', status: 'COMPLETED', start_time: '2026-10-13T09:00:00Z', end_time: '2026-10-13T09:05:00Z',
  jit_grant_id: 'grant-2', recording_id: null, request_id: 'r2',
};

beforeEach(() => vi.resetAllMocks());

describe('All Sessions (admin)', () => {
  it('lists every operator session, not just your own', async () => {
    api.sessionsApi.list.mockResolvedValue(page([live, done]));
    renderPage(<AdminSessions />);
    expect(await screen.findByText('SES-LIVE')).toBeInTheDocument();
    expect(screen.getByText('SES-DONE')).toBeInTheDocument();
    expect(screen.getByText('Kali Lab SSH')).toBeInTheDocument();
  });

  it('terminate + revoke ends the connection and kills the grant', async () => {
    api.sessionsApi.list.mockResolvedValue(page([live]));
    api.sessionsApi.terminate.mockResolvedValue({ message: 'Session terminated successfully' });
    api.jitGrantsApi.revoke.mockResolvedValue({ id: 'grant-1', status: 'REVOKED', revoked_at: '2026-10-13T10:01:00Z', sessions_ended: 1 });
    renderPage(<AdminSessions />);
    fireEvent.click(await screen.findByRole('button', { name: /Terminate \+ revoke/ }));
    await waitFor(() => expect(api.sessionsApi.terminate).toHaveBeenCalledWith('s-live'));
    await waitFor(() => expect(api.jitGrantsApi.revoke).toHaveBeenCalledWith('grant-1'));
    expect(await screen.findByText(/terminated; its grant is REVOKED/)).toBeInTheDocument();
  });

  it('revokes the grant alone on a finished session', async () => {
    api.sessionsApi.list.mockResolvedValue(page([done]));
    api.jitGrantsApi.revoke.mockResolvedValue({ id: 'grant-2', status: 'REVOKED', revoked_at: '2026-10-13T09:06:00Z', sessions_ended: 0 });
    renderPage(<AdminSessions />);
    fireEvent.click(await screen.findByRole('button', { name: /Revoke grant/ }));
    await waitFor(() => expect(api.jitGrantsApi.revoke).toHaveBeenCalledWith('grant-2'));
    expect(api.sessionsApi.terminate).not.toHaveBeenCalled();
    expect(await screen.findByText(/Grant for session SES-DONE is REVOKED/)).toBeInTheDocument();
  });

  it('shows the server error instead of pretending the action worked', async () => {
    api.sessionsApi.list.mockResolvedValue(page([live]));
    api.sessionsApi.terminate.mockRejectedValue(axiosError(409, 'Session is already COMPLETED'));
    renderPage(<AdminSessions />);
    fireEvent.click(await screen.findByRole('button', { name: /Terminate \+ revoke/ }));
    expect(await screen.findByText(/already COMPLETED/)).toBeInTheDocument();
    expect(api.jitGrantsApi.revoke).not.toHaveBeenCalled();
  });
});

describe('Recording Center session drill-down', () => {
  const rec = {
    id: 'rec-1', session_id: 's-live', session_number: 'SES-LIVE', operator_username: 'operator',
    asset_name: 'Kali Lab SSH', recording_type: 'TERMINAL', status: 'COMPLETED',
    integrity: 'verified', file_size: 2048, created_at: '2026-10-13T10:00:00Z',
  };

  it('fetches and shows what the session was when its number is clicked', async () => {
    api.recordingsApi.list.mockResolvedValue(page([rec]));
    api.sessionsApi.get.mockResolvedValue({ ...live, failure_message: undefined });
    renderPage(<Recordings />);
    fireEvent.click(await screen.findByRole('button', { name: 'SES-LIVE' }));
    await waitFor(() => expect(api.sessionsApi.get).toHaveBeenCalledWith('s-live'));
    expect(await screen.findByText('ACTIVE')).toBeInTheDocument();
    expect(screen.getAllByText(/Kali Lab SSH/).length).toBeGreaterThanOrEqual(2);
  });

  it('shows the failure reason for a failed session recording', async () => {
    api.recordingsApi.list.mockResolvedValue(page([{ ...rec, session_number: 'SES-BAD' }]));
    api.sessionsApi.get.mockResolvedValue({
      ...live, session_number: 'SES-BAD', status: 'FAILED',
      failure_message: 'The target rejected the stored credential.',
    });
    renderPage(<Recordings />);
    fireEvent.click(await screen.findByRole('button', { name: 'SES-BAD' }));
    expect(await screen.findByText(/target rejected the stored credential/)).toBeInTheDocument();
  });

  it('shows the API error when the session cannot be loaded', async () => {
    api.recordingsApi.list.mockResolvedValue(page([rec]));
    api.sessionsApi.get.mockRejectedValue(axiosError(404, 'Session not found'));
    renderPage(<Recordings />);
    fireEvent.click(await screen.findByRole('button', { name: 'SES-LIVE' }));
    expect(await screen.findByText(/Session not found/)).toBeInTheDocument();
  });
});
