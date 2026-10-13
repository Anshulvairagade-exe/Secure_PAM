import { describe, expect, it, vi, beforeEach } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { renderPage } from './render';

const api = vi.hoisted(() => ({
  sessionsApi: { list: vi.fn(), launchSSH: vi.fn(), terminate: vi.fn() },
  accessRequestsApi: { list: vi.fn(), get: vi.fn() },
  assetsApi: { list: vi.fn() },
  recordingsApi: { list: vi.fn(), terminalCast: vi.fn() },
  settingsApi: { summary: vi.fn() },
  healthApi: { detailed: vi.fn() },
}));
vi.mock('@/api', () => api);
vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    user: { id: 'u1', username: 'operator', roles: ['OPERATOR'], permissions: [] },
    hasRole: (role: string) => role === 'OPERATOR',
    hasPermission: () => false,
  }),
}));
// xterm needs a real canvas; these tests cover data states, not terminal rendering.
vi.mock('@/components/SshTerminal', () => ({ default: () => <div>terminal</div> }));

import Sessions, { gatewayUnavailableReason } from '@/pages/Sessions';
import Recordings from '@/pages/Recordings';
import SettingsPage from '@/pages/SettingsPage';
import SessionWatermark from '@/components/SessionWatermark';
import { parseCast } from '@/components/CastPlayer';

const page = <T,>(items: T[]) => ({ items, total: items.length, page: 1, page_size: 25, pages: 1 });
const never = () => new Promise(() => {});
const axiosError = (status: number, detail: string) =>
  Object.assign(new Error(detail), { isAxiosError: true, response: { status, data: { detail } } });

beforeEach(() => vi.resetAllMocks());

describe('My Sessions', () => {
  it('shows loading placeholders while data loads', () => {
    api.sessionsApi.list.mockImplementation(never);
    api.accessRequestsApi.list.mockImplementation(never);
    api.assetsApi.list.mockImplementation(never);
    const { container } = renderPage(<Sessions />);
    expect(container.querySelectorAll('.animate-pulse').length).toBeGreaterThan(0);
  });

  it('shows empty states with a create action when there is nothing to connect', async () => {
    api.sessionsApi.list.mockResolvedValue(page([]));
    api.accessRequestsApi.list.mockResolvedValue(page([]));
    api.assetsApi.list.mockResolvedValue(page([]));
    renderPage(<Sessions />);
    expect(await screen.findByText(/No approved request with an active just-in-time grant/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Request access/ })).toHaveAttribute('href', '/access-requests/new');
    expect(await screen.findByText(/No sessions yet/)).toBeInTheDocument();
  });

  it('shows the API error instead of fabricated data', async () => {
    api.sessionsApi.list.mockRejectedValue(axiosError(503, 'Database unavailable'));
    api.accessRequestsApi.list.mockResolvedValue(page([]));
    api.assetsApi.list.mockResolvedValue(page([]));
    renderPage(<Sessions />);
    expect(await screen.findByText(/Database unavailable/)).toBeInTheDocument();
  });

  it('offers Connect only for SSH requests with an active grant, and lists real sessions', async () => {
    const grant = { id: 'g', protocol: 'SSH', status: 'ACTIVE', granted_at: '2026-10-13T10:00:00Z', expires_at: '2026-10-13T11:00:00Z' };
    const ssh = { id: 'r1', user_id: 'u1', asset_id: 'a1', protocol: 'SSH', status: 'ACTIVE', request_number: 'REQ-1', jit_grant: grant };
    const rdp = { id: 'r2', user_id: 'u1', asset_id: 'a2', protocol: 'RDP', status: 'ACTIVE', request_number: 'REQ-2', jit_grant: { ...grant, protocol: 'RDP' } };
    api.accessRequestsApi.list.mockResolvedValue(page([ssh, rdp]));
    api.accessRequestsApi.get.mockImplementation((id: string) => Promise.resolve(id === 'r1' ? ssh : rdp));
    api.assetsApi.list.mockResolvedValue(page([{ id: 'a1', name: 'Kali Lab SSH' }, { id: 'a2', name: 'WIN-01' }]));
    api.sessionsApi.list.mockResolvedValue(page([{
      id: 's1', session_number: 'SES-1', user_id: 'u1', asset_name: 'Kali Lab SSH', protocol: 'SSH',
      status: 'COMPLETED', start_time: '2026-10-13T10:00:00Z', end_time: '2026-10-13T10:05:00Z',
      request_id: 'r1', recording_status: 'COMPLETED',
    }]));
    renderPage(<Sessions />);
    expect(await screen.findByRole('button', { name: /Connect/ })).toBeEnabled();
    expect(screen.getByText(/RDP gateway \(Guacamole\) is not deployed/)).toBeInTheDocument();
    expect(await screen.findByText('SES-1')).toBeInTheDocument();
    expect(screen.getByText('5m 00s')).toBeInTheDocument();
  });

  it('only SSH has a deployed gateway', () => {
    expect(gatewayUnavailableReason('SSH')).toBeNull();
    expect(gatewayUnavailableReason('RDP')).toMatch(/not deployed/);
    expect(gatewayUnavailableReason('HTTPS')).toMatch(/not deployed/);
  });
});

describe('Recording Center', () => {
  it('shows an empty state', async () => {
    api.recordingsApi.list.mockResolvedValue(page([]));
    renderPage(<Recordings />);
    expect(await screen.findByText(/No recordings yet/)).toBeInTheDocument();
  });

  it('shows the server denial for users without recordings access', async () => {
    api.recordingsApi.list.mockRejectedValue(axiosError(403, 'Missing permission: recordings:read'));
    renderPage(<Recordings />);
    expect(await screen.findByText(/recordings:read/)).toBeInTheDocument();
  });

  it('offers playback only for completed, verified terminal recordings', async () => {
    const base = { recording_type: 'TERMINAL', status: 'COMPLETED', created_at: '2026-10-13T10:00:00Z', operator_username: 'operator', asset_name: 'Kali Lab SSH' };
    api.recordingsApi.list.mockResolvedValue(page([
      { ...base, id: 'ok', session_id: 's1', session_number: 'SES-OK', integrity: 'verified', file_size: 2048 },
      { ...base, id: 'bad', session_id: 's2', session_number: 'SES-BAD', integrity: 'mismatch' },
      { ...base, id: 'fail', session_id: 's3', session_number: 'SES-FAIL', status: 'FAILED', integrity: 'not_available' },
    ]));
    renderPage(<Recordings />);
    expect(await screen.findByText('SES-OK')).toBeInTheDocument();
    expect(screen.getAllByRole('button', { name: /Play/ })).toHaveLength(1);
    expect(screen.getByText('Integrity FAILED')).toBeInTheDocument();
    expect(screen.getByText('SHA-256 verified')).toBeInTheDocument();
    expect(screen.getByText('2.0 KB')).toBeInTheDocument();
  });
});

describe('Settings', () => {
  it('reports mock and undeployed services as such, never as healthy', async () => {
    api.settingsApi.summary.mockResolvedValue({
      environment: 'development', version: '0.1.0', dev_mode: true, authentication: 'development accounts (DEV_MODE)',
      secret_provider: 'openbao', jit_default_minutes: 30, jit_max_minutes: 480, session_default_timeout_minutes: 30,
      session_max_timeout_minutes: 480, rate_limit_per_minute: 60, rate_limit_login_per_minute: 10,
      recording_storage_writable: true, recording_retention_days: 90, ssh_recording_format: 'asciicast v2', managed_by: 'env',
    });
    api.healthApi.detailed.mockResolvedValue({
      status: 'healthy', version: '0.1.0', environment: 'development', dev_mode: true,
      services: [
        { service: 'database', status: 'healthy' },
        { service: 'identity_provider', status: 'mock', details: 'DEV_MODE' },
        { service: 'gateway_rdp', status: 'not_configured', details: 'Guacamole is not deployed' },
        { service: 'recording_storage', status: 'unhealthy' },
      ],
    });
    renderPage(<SettingsPage />);
    expect(await screen.findByText('Development stand-in')).toBeInTheDocument();
    expect(screen.getByText('Not deployed')).toBeInTheDocument();
    expect(screen.getByText('Unavailable')).toBeInTheDocument();
    expect(await screen.findByText('openbao')).toBeInTheDocument();
  });

  it('shows an error when status cannot be loaded', async () => {
    api.settingsApi.summary.mockRejectedValue(axiosError(500, 'boom'));
    api.healthApi.detailed.mockRejectedValue(axiosError(401, 'Not authenticated'));
    renderPage(<SettingsPage />);
    await waitFor(() => expect(screen.getByText(/Not authenticated/)).toBeInTheDocument());
  });
});

describe('Session evidence helpers', () => {
  it('watermarks with operator identity and session number', () => {
    renderPage(<SessionWatermark username="operator" sessionNumber="SES-42" />);
    expect(screen.getByTestId('session-watermark').textContent).toMatch(/operator · SES-42 · \d{4}-\d{2}-\d{2}/);
  });

  it('parses asciicast v2 and rejects other formats', () => {
    const cast = '{"version": 2, "width": 80, "height": 24}\n[0.5, "o", "hi"]\n';
    expect(parseCast(cast).events).toEqual([[0.5, 'o', 'hi']]);
    expect(() => parseCast('{"version": 1}')).toThrow(/Unsupported/);
  });
});
