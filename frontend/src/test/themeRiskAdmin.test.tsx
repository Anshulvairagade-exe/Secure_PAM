import { describe, expect, it, vi, beforeEach } from 'vitest';
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { renderPage } from './render';

const api = vi.hoisted(() => ({
  riskApi: { summary: vi.fn(), findings: vi.fn(), finding: vi.fn(), setStatus: vi.fn(), evaluate: vi.fn(), setThresholds: vi.fn() },
  usersApi: { list: vi.fn(), get: vi.fn(), create: vi.fn(), update: vi.fn() },
  rolesApi: { list: vi.fn() },
  settingsApi: { summary: vi.fn() },
  assetsApi: { list: vi.fn(), create: vi.fn(), update: vi.fn(), delete: vi.fn() },
  credentialProvisioningApi: { status: vi.fn(), createAsset: vi.fn(), setCredential: vi.fn() },
}));
vi.mock('@/api', () => api);
const perms = vi.hoisted(() => ({ set: new Set<string>(['risk:manage', 'users:create', 'users:update', 'vault:manage', 'assets:create']) }));
vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    user: { id: 'me', username: 'admin', full_name: 'Admin', roles: ['ADMIN'], permissions: [] },
    hasRole: () => true, hasAnyRole: () => true,
    hasPermission: (p: string) => perms.set.has(p),
  }),
}));

import { ThemeProvider, THEME_STORAGE_KEY } from '@/theme/ThemeProvider';
import ThemeToggle from '@/theme/ThemeToggle';
import themeInitSource from '../../public/theme-init.js?raw';
import RiskCenter from '@/pages/RiskCenter';
import Users from '@/pages/Users';
import Assets from '@/pages/Assets';

function mockSystemDark(dark: boolean) {
  window.matchMedia = vi.fn().mockImplementation((q: string) => ({
    matches: q.includes('dark') ? dark : false, media: q, addEventListener: vi.fn(), removeEventListener: vi.fn(),
  })) as unknown as typeof window.matchMedia;
}

describe('Theme', () => {
  beforeEach(() => { localStorage.clear(); document.documentElement.className = ''; });

  it('follows the OS on first visit and persists an explicit choice', () => {
    mockSystemDark(true);
    render(<ThemeProvider><ThemeToggle /></ThemeProvider>);
    expect(document.documentElement.classList.contains('dark')).toBe(true);
    expect(screen.getByRole('radio', { name: /system/i })).toHaveAttribute('aria-checked', 'true');

    fireEvent.click(screen.getByRole('radio', { name: /light/i }));
    expect(document.documentElement.classList.contains('dark')).toBe(false);
    expect(document.documentElement.style.colorScheme).toBe('light');
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('light');

    fireEvent.click(screen.getByRole('radio', { name: /dark/i }));
    expect(document.documentElement.classList.contains('dark')).toBe(true);
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('dark');

    fireEvent.click(screen.getByRole('radio', { name: /system/i }));
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBeNull();
  });

  it('restores the saved choice even when the OS prefers the other theme', () => {
    mockSystemDark(true);
    localStorage.setItem(THEME_STORAGE_KEY, 'light');
    render(<ThemeProvider><ThemeToggle /></ThemeProvider>);
    expect(document.documentElement.classList.contains('dark')).toBe(false);
    expect(screen.getByRole('radio', { name: /light/i })).toHaveAttribute('aria-checked', 'true');
  });

  it('pre-paint script applies the same rule (no flash)', () => {
    const src = themeInitSource;
    mockSystemDark(false);
    localStorage.setItem(THEME_STORAGE_KEY, 'dark');
    document.documentElement.className = '';
    new Function(src)();
    expect(document.documentElement.classList.contains('dark')).toBe(true);
    localStorage.removeItem(THEME_STORAGE_KEY);
    new Function(src)();
    expect(document.documentElement.classList.contains('dark')).toBe(false);
  });
});

const days = (n: number) => Array.from({ length: n }, (_, i) => ({ day: `2026-10-${String(i + 1).padStart(2, '0')}`, counts: {} as Record<string, number> }));

describe('Risk Center', () => {
  beforeEach(() => { mockSystemDark(false); vi.clearAllMocks(); });

  it('shows exactly the counts the API computed from records, prioritized findings, and evidence', async () => {
    const perDay = days(30); perDay[29].counts = { HIGH: 1, LOW: 1 };
    api.riskApi.summary.mockResolvedValue({
      window_days: 30, open_by_severity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 1, INFO: 0 },
      by_status: { OPEN: 2, ACKNOWLEDGED: 0, RESOLVED: 1 }, by_rule: { MFA_FAILURES: 1, EGRESS_BLOCKED: 1 },
      by_source: { 'securepam-detector': 3 }, new_findings_per_day: perDay,
      access_risk_by_level: { CRITICAL: 1, HIGH: 18, MEDIUM: 31, LOW: 50 }, access_risk_per_day: days(30),
      total_findings: 3, last_evaluated_at: new Date().toISOString(),
      rules: { MFA_FAILURES: 'MFA rule text' }, thresholds: { 'risk.mfa_failure_threshold': 3, 'risk.launch_denial_threshold': 5 },
    });
    api.riskApi.findings.mockResolvedValue({ items: [
      { id: 'f1', rule_code: 'MFA_FAILURES', source: 'securepam-detector', title: 'Repeated MFA failures', description: 'd',
        severity: 'HIGH', status: 'OPEN', subject: 'alice', asset_id: null, application_id: null, user_id: null, session_id: null,
        evidence: { references: ['EVT-1'], count: 3, max_in_60_min: 3 }, remediation: 'Reset the authenticator',
        first_seen: new Date().toISOString(), last_seen: new Date().toISOString(), occurrences: 3, status_changed_at: null, status_note: null },
    ], total: 1, page: 1, page_size: 20, pages: 1 });
    api.riskApi.finding.mockResolvedValue({
      ...(await api.riskApi.findings()).items[0], asset_name: null, application_name: null, username: 'alice',
      evidence_events: [{ reference: 'EVT-1', found: true, timestamp: new Date().toISOString(), action: 'MFA_FAILURE', actor: 'alice', result: 'FAILURE' }],
    });
    renderPage(<RiskCenter />);
    expect(await screen.findByText('Repeated MFA failures')).toBeInTheDocument();
    const high = screen.getByRole('button', { name: /high/i, pressed: false });
    expect(within(high).getByText('1')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument(); // open total = 1 HIGH + 1 LOW
    expect(screen.getByText(/1 resolved · 3 total/)).toBeInTheDocument();
    expect(screen.getByText(/1 critical · 18 high · 31 medium · 50 low/)).toBeInTheDocument();
    expect(screen.getByRole('img', { name: /New findings per day: 2 in 30 days/ })).toBeInTheDocument();

    fireEvent.click(high);
    await waitFor(() => expect(api.riskApi.findings).toHaveBeenLastCalledWith(expect.objectContaining({ severity: 'HIGH' })));

    fireEvent.click((await screen.findAllByText('Repeated MFA failures'))[0]);
    expect(await screen.findByText('Reset the authenticator')).toBeInTheDocument();
    expect(screen.getByText('MFA_FAILURE')).toBeInTheDocument();
    api.riskApi.setStatus.mockResolvedValue({});
    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge' }));
    await waitFor(() => expect(api.riskApi.setStatus).toHaveBeenCalledWith('f1', 'ACKNOWLEDGED', undefined));
  });

  it('says so honestly when nothing has been evaluated, and hides admin actions from readers', async () => {
    perms.set.delete('risk:manage');
    api.riskApi.summary.mockResolvedValue({
      window_days: 30, open_by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      by_status: { OPEN: 0, ACKNOWLEDGED: 0, RESOLVED: 0 }, by_rule: {}, by_source: {}, new_findings_per_day: days(30),
      access_risk_by_level: {}, access_risk_per_day: days(30), total_findings: 0, last_evaluated_at: null, rules: {}, thresholds: {},
    });
    api.riskApi.findings.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 20, pages: 0 });
    renderPage(<RiskCenter />);
    expect(await screen.findByText(/Not evaluated yet/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Evaluate now/ })).toBeNull();
    perms.set.add('risk:manage');
  });
});

describe('Users administration', () => {
  beforeEach(() => {
    mockSystemDark(false); vi.clearAllMocks();
    api.usersApi.list.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 25, pages: 0 });
    api.rolesApi.list.mockResolvedValue([{ id: 'r-op', name: 'OPERATOR', description: 'Operators', is_active: true, is_system: true, permissions: [], users: [] }]);
  });

  it('Keycloak mode asks for the Keycloak user ID, never a password', async () => {
    api.settingsApi.summary.mockResolvedValue({ dev_mode: false });
    api.usersApi.create.mockResolvedValue({ id: 'new' });
    renderPage(<Users />);
    const add = await screen.findByRole('button', { name: /Add user/ });
    await waitFor(() => expect(add).toBeEnabled());
    fireEvent.click(add);
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).queryByLabelText(/password/i)).toBeNull();
    fireEvent.change(within(dialog).getByLabelText(/Username/), { target: { value: 'kc.user' } });
    fireEvent.change(within(dialog).getByLabelText(/Full name/), { target: { value: 'KC User' } });
    fireEvent.change(within(dialog).getByLabelText(/Email/), { target: { value: 'kc@example.com' } });
    fireEvent.change(within(dialog).getByLabelText(/Keycloak user ID/), { target: { value: '0b6f3f3c-5d1e-4c1b-9a4e-2f8f3c1d2e10' } });
    fireEvent.click(within(dialog).getByRole('checkbox'));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Create user' }));
    await waitFor(() => expect(api.usersApi.create).toHaveBeenCalledWith({
      username: 'kc.user', email: 'kc@example.com', full_name: 'KC User', role_ids: ['r-op'],
      external_id: '0b6f3f3c-5d1e-4c1b-9a4e-2f8f3c1d2e10' }));
  });

  it('DEV mode requires a 12+ character initial password', async () => {
    api.settingsApi.summary.mockResolvedValue({ dev_mode: true });
    renderPage(<Users />);
    const add = await screen.findByRole('button', { name: /Add user/ });
    await waitFor(() => expect(add).toBeEnabled());
    fireEvent.click(add);
    const dialog = await screen.findByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText(/Username/), { target: { value: 'dev.user' } });
    fireEvent.change(within(dialog).getByLabelText(/Full name/), { target: { value: 'Dev' } });
    fireEvent.change(within(dialog).getByLabelText(/Email/), { target: { value: 'dev@example.com' } });
    fireEvent.change(within(dialog).getByLabelText(/Initial password/), { target: { value: 'short' } });
    expect(within(dialog).getByRole('button', { name: 'Create user' })).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText(/Initial password/), { target: { value: 'long-enough-pass' } });
    expect(within(dialog).getByRole('button', { name: 'Create user' })).toBeEnabled();
  });
});

describe('Assets credential provisioning', () => {
  const status = (configured: boolean) => ({
    configured, reason: configured ? 'ok' : 'No credential-writer identity is configured (OPENBAO_WRITER_TOKEN).',
    secret_provider: configured ? 'openbao' : 'mock', openbao_ui_url: configured ? 'https://bao.ops.example.com:8200/ui/' : null,
    references: [
      { name: 'win11-lab', path: 'securepam/assets/win11-lab', bound_asset_id: 'a-win', bound_asset_name: 'Windows 11 Lab' },
      { name: 'kali', path: 'securepam/assets/kali', bound_asset_id: null, bound_asset_name: null },
    ],
  });
  beforeEach(() => {
    mockSystemDark(false); vi.clearAllMocks();
    api.assetsApi.list.mockResolvedValue({ items: [], total: 0, page: 1, page_size: 10, pages: 0 });
  });

  it('fails closed when not configured: no "provision now", OpenBao button disabled', async () => {
    api.credentialProvisioningApi.status.mockResolvedValue(status(false));
    renderPage(<Assets />);
    expect(await screen.findByText('Credential provisioning is not configured')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Open OpenBao Vault/ })).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: /New Asset/ }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByLabelText(/Provision now in OpenBao/)).toBeDisabled();
  });

  it('sends only an approved reference name (never a path) and shows the verified version', async () => {
    api.credentialProvisioningApi.status.mockResolvedValue(status(true));
    api.credentialProvisioningApi.createAsset.mockResolvedValue({
      asset: { name: 'Kali' }, vault_path: 'securepam/assets/kali', version: 1, username: 'u', verified: true });
    renderPage(<Assets />);
    expect(await screen.findByRole('link', { name: /Open OpenBao Vault/ })).toHaveAttribute('href', 'https://bao.ops.example.com:8200/ui/');
    fireEvent.click(screen.getByRole('button', { name: /New Asset/ }));
    const dialog = await screen.findByRole('dialog');
    const select = within(dialog).getByLabelText(/Approved credential reference/) as HTMLSelectElement;
    expect(within(select).getByRole('option', { name: /win11-lab \(bound to Windows 11 Lab\)/ })).toBeDisabled();
    fireEvent.change(select, { target: { value: 'kali' } });
    fireEvent.change(within(dialog).getByLabelText(/^Username$/), { target: { value: 'kali-admin' } });
    fireEvent.change(within(dialog).getByLabelText(/^Password$/), { target: { value: 'pw-canary' } });
    const inputs = within(dialog).getAllByRole('textbox');
    fireEvent.change(inputs[0], { target: { value: 'Kali' } });
    await act(async () => { fireEvent.click(within(dialog).getByRole('button', { name: 'Create Asset' })); });
    await waitFor(() => expect(api.credentialProvisioningApi.createAsset).toHaveBeenCalled());
    const body = api.credentialProvisioningApi.createAsset.mock.calls[0][0];
    expect(body.credential).toEqual({ secret_name: 'kali', username: 'kali-admin', password: 'pw-canary', secret_type: 'PASSWORD' });
    expect(JSON.stringify(body)).not.toContain('securepam/assets');
    expect(await screen.findByText(/version 1\) and verified/)).toBeInTheDocument();
  });
});
