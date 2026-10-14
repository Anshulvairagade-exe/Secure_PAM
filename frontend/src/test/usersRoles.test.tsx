import { describe, expect, it, vi, beforeEach } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import { renderPage } from './render';

const api = vi.hoisted(() => ({
  usersApi: { list: vi.fn(), get: vi.fn(), deactivate: vi.fn(), reactivate: vi.fn(), assignRole: vi.fn(), removeRole: vi.fn() },
  rolesApi: { list: vi.fn() },
  settingsApi: { summary: vi.fn(() => Promise.resolve({ dev_mode: true })) },
  recordingsApi: { transcript: vi.fn(), exportTranscript: vi.fn() },
}));
vi.mock('@/api', () => api);
const auth = vi.hoisted(() => ({ canUpdate: true }));
vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    user: { id: 'me', username: 'admin', roles: ['ADMIN'], permissions: [] },
    hasRole: () => true,
    hasPermission: (p: string) => (p === 'users:update' ? auth.canUpdate : true),
  }),
}));

import Users from '@/pages/Users';
import Roles from '@/pages/Roles';
import TranscriptPanel from '@/components/TranscriptPanel';

const page = <T,>(items: T[]) => ({ items, total: items.length, page: 1, page_size: 25, pages: 1 });
const never = () => new Promise(() => {});
const axiosError = (status: number, detail: string) =>
  Object.assign(new Error(detail), { isAxiosError: true, response: { status, data: { detail } } });

const operator = {
  id: 'u2', username: 'operator', full_name: 'Demo Operator', email: 'op@x', is_active: true, is_system_user: false,
  mfa_enabled: false, active_sessions: 1, external_id: 'abcdef12-0000', identity_source: 'development account',
  roles: [{ id: 'r1', name: 'OPERATOR' }], last_login: null, created_at: '2026-10-01T00:00:00Z',
};
const detail = { ...operator, last_login_ip: '10.0.0.5', failed_login_count: 0, permissions: ['sessions:create'], live_sessions: 1 };
const roles = [
  { id: 'r1', name: 'OPERATOR', description: 'Uses access', is_system: true, is_active: true,
    permissions: [{ name: 'sessions:create', description: null }, { name: 'sessions:read_own', description: null }],
    users: [{ id: 'u2', username: 'operator', is_active: true }] },
  { id: 'r2', name: 'AUDITOR', description: 'Reviews', is_system: true, is_active: true, permissions: [], users: [] },
];

beforeEach(() => { vi.resetAllMocks(); auth.canUpdate = true; api.rolesApi.list.mockResolvedValue(roles); });

describe('Users', () => {
  it('shows loading placeholders', () => {
    api.usersApi.list.mockReturnValue(never());
    const { container } = renderPage(<Users />);
    expect(container.querySelector('.animate-pulse')).not.toBeNull();
  });

  it('shows an empty state, not fabricated users', async () => {
    api.usersApi.list.mockResolvedValue(page([]));
    renderPage(<Users />);
    expect(await screen.findByText(/No users have signed in/)).toBeInTheDocument();
  });

  it('shows the server error', async () => {
    api.usersApi.list.mockRejectedValue(axiosError(403, 'Missing permission: users:read'));
    renderPage(<Users />);
    expect(await screen.findByText(/Missing permission: users:read/)).toBeInTheDocument();
  });

  it('lists real users with roles and identity, and manages roles from the detail panel', async () => {
    api.usersApi.list.mockResolvedValue(page([operator]));
    api.usersApi.get.mockResolvedValue(detail);
    api.usersApi.assignRole.mockResolvedValue(operator);
    renderPage(<Users />);
    expect(await screen.findByText('Demo Operator')).toBeInTheDocument();
    expect(screen.getByText('development account')).toBeInTheDocument();
    fireEvent.click(screen.getByText('Demo Operator'));
    expect(await screen.findByText('sessions:create')).toBeInTheDocument();
    fireEvent.change(await screen.findByLabelText('Role to add'), { target: { value: 'r2' } });
    fireEvent.click(screen.getByText('Assign'));
    await waitFor(() => expect(api.usersApi.assignRole).toHaveBeenCalledWith('u2', 'r2'));
  });

  it('hides change controls without users:update', async () => {
    auth.canUpdate = false;
    api.usersApi.list.mockResolvedValue(page([operator]));
    api.usersApi.get.mockResolvedValue(detail);
    renderPage(<Users />);
    fireEvent.click(await screen.findByText('Demo Operator'));
    await screen.findByText('sessions:create');
    expect(screen.queryByText('Deactivate account')).toBeNull();
    expect(screen.queryByLabelText('Role to add')).toBeNull();
  });

  it('offers no controls on your own account', async () => {
    api.usersApi.list.mockResolvedValue(page([{ ...operator, id: 'me', username: 'admin' }]));
    api.usersApi.get.mockResolvedValue({ ...detail, id: 'me', username: 'admin' });
    renderPage(<Users />);
    fireEvent.click(await screen.findByText('Demo Operator'));
    expect(await screen.findByText(/cannot change your own roles/)).toBeInTheDocument();
    expect(screen.queryByText('Deactivate account')).toBeNull();
  });
});

describe('Roles', () => {
  it('shows roles with permissions and assigned users', async () => {
    renderPage(<Roles />);
    expect(await screen.findByLabelText('Role OPERATOR')).toBeInTheDocument();
    expect(screen.getByText('create, read_own')).toBeInTheDocument();
    expect(screen.getByText('operator')).toBeInTheDocument();
    expect(screen.getByText(/No users hold this role/)).toBeInTheDocument();
    expect(screen.getByText(/carry no authority here/)).toBeInTheDocument();
  });

  it('shows the server error', async () => {
    api.rolesApi.list.mockRejectedValue(axiosError(403, 'Missing permission: users:read'));
    renderPage(<Roles />);
    expect(await screen.findByText(/Missing permission: users:read/)).toBeInTheDocument();
  });
});

describe('Activity transcript', () => {
  const entry = (seq: number, t: number, input: string, output: string, extra = {}) => ({
    seq, t, input, output, output_truncated: false, masked: false, redacted: false, edited: false,
    confidence: 'high', source: 'terminal_input_observed', execution_verified: false, ...extra,
  });
  const available = {
    available: true, reason: null, recording_id: 'rec1', session_number: 'SES-1',
    transcript: {
      limitations: 'Entries are lines typed by the operator; not proof the target executed them.',
      events_truncated: false,
      events: [entry(1, 3.2, 'whoami', 'kali'), entry(2, 9, 'pwd', '/home/kali'),
        entry(3, 12, 'cat /et', '', { edited: true, confidence: 'low' })],
    },
  };

  it('lists observed input with timestamps, output, confidence and the limitation notice', async () => {
    api.recordingsApi.transcript.mockResolvedValue(available);
    renderPage(<TranscriptPanel recordingId="rec1" canExport onSeek={() => {}} />);
    expect(await screen.findByText('$ whoami')).toBeInTheDocument();
    expect(screen.getByText('kali')).toBeInTheDocument();
    expect(screen.getByText('00:03')).toBeInTheDocument();
    expect(screen.getByText('low confidence')).toBeInTheDocument();
    expect(screen.getByText(/not proof the target executed/)).toBeInTheDocument();
    expect(screen.getAllByText('observed input').length).toBe(3);
    expect(screen.queryByText(/verified execution/i)).toBeNull();
  });

  it('seeks the replay when an entry is clicked and filters by search', async () => {
    api.recordingsApi.transcript.mockResolvedValue(available);
    const onSeek = vi.fn();
    renderPage(<TranscriptPanel recordingId="rec1" canExport={false} onSeek={onSeek} />);
    fireEvent.click(await screen.findByText('$ pwd'));
    expect(onSeek).toHaveBeenCalledWith(8.5);
    fireEvent.change(screen.getByLabelText('Search transcript'), { target: { value: 'whoami' } });
    expect(screen.queryByText('$ pwd')).toBeNull();
    expect(screen.queryByText('Export JSON')).toBeNull();
    fireEvent.change(screen.getByLabelText('Search transcript'), { target: { value: 'zzz' } });
    expect(screen.getByText(/No transcript entries match/)).toBeInTheDocument();
  });

  it('says why no transcript exists instead of inventing one', async () => {
    api.recordingsApi.transcript.mockResolvedValue({
      available: false, reason: 'Activity for Windows/RDP sessions needs endpoint telemetry (Security event 4688).',
      recording_id: 'rec1', session_number: 'SES-1', transcript: null });
    renderPage(<TranscriptPanel recordingId="rec1" canExport onSeek={() => {}} />);
    expect(await screen.findByText(/needs endpoint telemetry/)).toBeInTheDocument();
    expect(screen.queryByText('Export JSON')).toBeNull();
  });

  it('shows the server error', async () => {
    api.recordingsApi.transcript.mockRejectedValue(axiosError(409, 'Transcript failed integrity verification and was not served'));
    renderPage(<TranscriptPanel recordingId="rec1" canExport onSeek={() => {}} />);
    expect(await screen.findByText(/failed integrity verification/)).toBeInTheDocument();
  });
});
