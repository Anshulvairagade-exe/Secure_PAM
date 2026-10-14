import { describe, expect, it, vi, beforeEach } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/react';
import { renderPage } from './render';

const api = vi.hoisted(() => ({
  assetsApi: { list: vi.fn() },
  credentialRefsApi: { get: vi.fn(), set: vi.fn(), deactivate: vi.fn(), check: vi.fn() },
}));
vi.mock('@/api', () => api);

const auth = vi.hoisted(() => ({ canManage: true }));
vi.mock('@/hooks/useAuth', () => ({
  useAuth: () => ({
    user: { id: 'u1', username: 'admin', roles: ['ADMIN'], permissions: ['vault:manage'] },
    hasRole: (role: string) => role === 'ADMIN',
    hasPermission: (perm: string) => (perm === 'vault:manage' ? auth.canManage : false),
  }),
}));

import VaultReferences from '@/pages/VaultReferences';

const page = <T,>(items: T[]) => ({ items, total: items.length, page: 1, page_size: 25, pages: 1 });
const asset = { id: 'a1', name: 'Kali Lab SSH', protocol: 'SSH', environment: 'TESTING' };
const ref = { id: 'r1', asset_id: 'a1', provider: 'openbao', vault_path: 'securepam/assets/kali', secret_type: 'PASSWORD', username: 'kali', is_active: true };
const axiosError = (status: number, detail: string) =>
  Object.assign(new Error(detail), { isAxiosError: true, response: { status, data: { detail } } });

beforeEach(() => {
  vi.resetAllMocks();
  auth.canManage = true;
  api.assetsApi.list.mockResolvedValue(page([asset]));
  api.credentialRefsApi.get.mockResolvedValue(ref);
});

describe('Vault credential-reference check', () => {
  it('shows Readable when the backend reports the secret is readable', async () => {
    api.credentialRefsApi.check.mockResolvedValue({ status: 'ok', message: 'The secret exists and the gateway can read it.' });
    renderPage(<VaultReferences />);
    await screen.findByText('securepam/assets/kali');
    fireEvent.click(screen.getByRole('button', { name: 'Check' }));
    expect(await screen.findByText('Readable')).toBeInTheDocument();
    expect(screen.getByText('The secret exists and the gateway can read it.')).toBeInTheDocument();
    expect(api.credentialRefsApi.check).toHaveBeenCalledWith('a1');
  });

  it('shows Secret missing without ever rendering the secret value', async () => {
    api.credentialRefsApi.check.mockResolvedValue({ status: 'secret_not_found', message: 'No secret exists at this reference.' });
    renderPage(<VaultReferences />);
    await screen.findByText('securepam/assets/kali');
    fireEvent.click(screen.getByRole('button', { name: 'Check' }));
    expect(await screen.findByText('Secret missing')).toBeInTheDocument();
    // Only safe status/reason text reaches the DOM.
    expect(document.body.textContent).not.toMatch(/kali-password|supersecret/i);
  });

  it('surfaces the authorization error when the caller lacks vault:manage', async () => {
    api.credentialRefsApi.check.mockRejectedValue(axiosError(403, 'Missing permission: vault:manage'));
    renderPage(<VaultReferences />);
    await screen.findByText('securepam/assets/kali');
    fireEvent.click(screen.getByRole('button', { name: 'Check' }));
    await waitFor(() => expect(screen.getByText(/vault:manage/)).toBeInTheDocument());
  });

  it('hides the Check action from users without vault:manage', async () => {
    auth.canManage = false;
    renderPage(<VaultReferences />);
    await screen.findByText('securepam/assets/kali');
    expect(screen.queryByRole('button', { name: 'Check' })).not.toBeInTheDocument();
  });
});
