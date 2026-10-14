import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Search, UserPlus } from 'lucide-react';
import { rolesApi, settingsApi, usersApi } from '@/api';
import Modal from '@/components/Modal';
import { getApiErrorMessage } from '@/api/errors';
import { EmptyState, ErrorBanner, Skeleton } from '@/components/Feedback';
import UserSessionsPanel from '@/components/UserSessionsPanel';
import { useAuth } from '@/hooks/useAuth';
import type { AdminUser } from '@/types';

export default function Users() {
  const { user: me, hasPermission } = useAuth();
  const canChange = hasPermission('users:update');
  const queryClient = useQueryClient();
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [active, setActive] = useState('');
  const [role, setRole] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const [sessionsFor, setSessionsFor] = useState<string | null>(null);
  const canTerminate = hasPermission('sessions:terminate');
  const [roleToAdd, setRoleToAdd] = useState('');
  const [actionError, setActionError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [editingProfile, setEditingProfile] = useState(false);
  const canCreate = hasPermission('users:create');
  const deployment = useQuery({ queryKey: ['settings-summary'], queryFn: settingsApi.summary });
  const devAccounts = deployment.data?.dev_mode ?? false;

  const params = { page, page_size: 25, search: search || undefined, active: active || undefined, role: role || undefined };
  const users = useQuery({ queryKey: ['users', params], queryFn: () => usersApi.list(params) });
  const roles = useQuery({ queryKey: ['roles'], queryFn: rolesApi.list });
  const detail = useQuery({
    queryKey: ['user', selected], queryFn: () => usersApi.get(selected!), enabled: selected !== null,
  });

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ['users'] });
    void queryClient.invalidateQueries({ queryKey: ['user'] });
    void queryClient.invalidateQueries({ queryKey: ['roles'] });
  };
  const change = useMutation({
    mutationFn: (fn: () => Promise<AdminUser>) => fn(),
    onSuccess: () => { setActionError(null); setRoleToAdd(''); refresh(); },
    onError: (error) => setActionError(getApiErrorMessage(error, 'The change was refused.')),
  });

  const u = detail.data;
  const isSelf = u?.id === me?.id;
  const available = (roles.data ?? []).filter((r) => r.is_active && !u?.roles.some((x) => x.id === r.id));

  return (
    <div className="space-y-6">
      <div className="page-header">
        <div>
          <h1 className="page-title">Users</h1>
          <p className="page-subtitle">
            Accounts known to SecurePAM and the application roles they hold. Every change is audited; you cannot
            change your own roles or state, and the last active administrator is protected.
          </p>
        </div>
        {canCreate && (
          <button className="btn-primary" onClick={() => setCreating(true)} disabled={deployment.isLoading}>
            <UserPlus size={16} /> Add user
          </button>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <label className="relative">
          <Search size={14} className="pointer-events-none absolute left-2 top-2.5 text-gray-500" />
          <input className="input w-60 pl-7" placeholder="Search name, username, email" aria-label="Search users"
            value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} />
        </label>
        <select className="input w-auto" aria-label="Filter by state" value={active} onChange={(e) => { setActive(e.target.value); setPage(1); }}>
          <option value="">All states</option><option value="true">Active</option><option value="false">Deactivated</option>
        </select>
        <select className="input w-auto" aria-label="Filter by role" value={role} onChange={(e) => { setRole(e.target.value); setPage(1); }}>
          <option value="">All roles</option>
          {roles.data?.map((r) => <option key={r.id} value={r.name}>{r.name}</option>)}
        </select>
      </div>

      {users.isError && <ErrorBanner message={getApiErrorMessage(users.error, 'Failed to load users.')} />}
      {actionError && <ErrorBanner message={actionError} />}

      <div className="card overflow-hidden">
        {users.isLoading ? (
          <div className="space-y-2 p-4">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-10" />)}</div>
        ) : !users.data || users.data.items.length === 0 ? (
          <EmptyState message={search || active || role ? 'No users match these filters.' : 'No users have signed in or been provisioned yet.'} />
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr><th>User</th><th>State</th><th>Roles</th><th>Identity</th><th>MFA</th><th>Last sign-in</th><th>Sessions</th></tr>
              </thead>
              <tbody>
                {users.data.items.map((row) => (
                  <tr key={row.id} className={selected === row.id ? 'bg-navy-800/40' : ''}>
                    <td>
                      <button className="text-left" onClick={() => { setSelected(row.id); setActionError(null); }}>
                        <span className="block text-blue-400 hover:underline">{row.full_name}</span>
                        <span className="block font-mono text-xs text-gray-500">{row.username} · {row.email}</span>
                      </button>
                    </td>
                    <td><span className={row.is_active ? 'badge-success' : 'badge-danger'}>{row.is_active ? 'active' : 'deactivated'}</span></td>
                    <td className="space-x-1">{row.roles.length ? row.roles.map((r) => <span key={r.id} className="badge-info">{r.name}</span>) : <span className="text-xs text-gray-500">none</span>}</td>
                    <td className="text-xs text-gray-400">
                      {row.identity_source}
                      {row.external_id && <span className="block font-mono text-gray-600" title="External identity reference">{row.external_id.slice(0, 8)}…</span>}
                    </td>
                    <td className="text-gray-400">
                      {row.identity_source === 'development account'
                        ? <span className="text-xs text-gray-500" title="Development accounts sign in with a local password only">not enforced (dev)</span>
                        : row.mfa_enabled ? 'enrolled' : 'not enrolled'}
                    </td>
                    <td className="whitespace-nowrap text-gray-500">{row.last_login ? new Date(row.last_login).toLocaleString() : 'never'}</td>
                    <td className="whitespace-nowrap">
                      <span className={row.active_sessions > 0 ? 'badge-success' : 'text-xs text-gray-500'}>{row.active_sessions} active</span>
                      {canTerminate && (
                        <button className="ml-2 text-xs text-blue-400 hover:underline" onClick={() => setSessionsFor(row.id)}>
                          View sessions
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {users.data && users.data.pages > 1 && (
        <div className="flex items-center justify-between text-sm text-gray-500">
          <span>Page {users.data.page} of {users.data.pages} · {users.data.total} users</span>
          <div className="flex gap-2">
            <button className="btn-secondary" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</button>
            <button className="btn-secondary" disabled={page >= users.data.pages} onClick={() => setPage((p) => p + 1)}>Next</button>
          </div>
        </div>
      )}

      {creating && (
        <CreateUserDialog devAccounts={devAccounts} roles={(roles.data ?? []).filter((r) => r.is_active)}
          onClose={() => setCreating(false)}
          onCreated={(id) => { setCreating(false); refresh(); setSelected(id); }} />
      )}
      {editingProfile && u && (
        <EditUserDialog user={u} isSelf={isSelf} onClose={() => setEditingProfile(false)}
          onSaved={() => { setEditingProfile(false); refresh(); }} />
      )}

      {sessionsFor && <UserSessionsPanel key={sessionsFor} userId={sessionsFor} onClose={() => setSessionsFor(null)} />}

      {selected && (
        <section className="card space-y-4 p-5" aria-label="User details">
          {detail.isLoading ? <Skeleton className="h-24" /> : detail.isError ? (
            <ErrorBanner message={getApiErrorMessage(detail.error, 'The user could not be loaded.')} />
          ) : u ? (
            <>
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-gray-100">{u.full_name} <span className="font-mono text-xs text-gray-500">({u.username})</span></h2>
                <div className="flex gap-2">
                  {canChange && <button className="btn-secondary px-3 py-1.5 text-sm" onClick={() => setEditingProfile(true)}>Edit profile</button>}
                  <button className="btn-ghost px-3 py-1.5 text-sm" onClick={() => setSelected(null)}>Close</button>
                </div>
              </div>
              <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-sm md:grid-cols-4">
                <div><dt className="text-xs text-gray-500">Last sign-in IP</dt><dd className="text-gray-300">{u.last_login_ip ?? '—'}</dd></div>
                <div><dt className="text-xs text-gray-500">Failed sign-ins</dt><dd className="text-gray-300">{u.failed_login_count}</dd></div>
                <div><dt className="text-xs text-gray-500">Live sessions</dt><dd className="text-gray-300">{u.live_sessions}</dd></div>
                <div><dt className="text-xs text-gray-500">Account type</dt><dd className="text-gray-300">{u.is_system_user ? 'system' : 'person'}</dd></div>
              </dl>
              <div>
                <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">Roles</h3>
                <div className="flex flex-wrap items-center gap-2">
                  {u.roles.map((r) => (
                    <span key={r.id} className="badge-info">
                      {r.name}
                      {canChange && !isSelf && (
                        <button className="ml-1 text-gray-400 hover:text-red-400" aria-label={`Remove ${r.name}`}
                          disabled={change.isPending}
                          onClick={() => window.confirm(`Remove ${r.name} from ${u.username}?`) && change.mutate(() => usersApi.removeRole(u.id, r.id))}>×</button>
                      )}
                    </span>
                  ))}
                  {u.roles.length === 0 && <span className="text-xs text-gray-500">No roles: this account cannot do anything.</span>}
                </div>
                {canChange && !isSelf && available.length > 0 && (
                  <div className="mt-2 flex items-center gap-2">
                    <select className="input w-auto" aria-label="Role to add" value={roleToAdd} onChange={(e) => setRoleToAdd(e.target.value)}>
                      <option value="">Add a role…</option>
                      {available.map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
                    </select>
                    <button className="btn-secondary px-3 py-1.5 text-sm" disabled={!roleToAdd || change.isPending}
                      onClick={() => change.mutate(() => usersApi.assignRole(u.id, roleToAdd))}>Assign</button>
                  </div>
                )}
                {isSelf && <p className="mt-2 text-xs text-gray-500">You cannot change your own roles or state.</p>}
              </div>
              <div>
                <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">Effective permissions ({u.permissions.length})</h3>
                <p className="font-mono text-xs text-gray-400">{u.permissions.join('  ') || 'none'}</p>
                {u.roles.some((r) => r.name === 'ADMIN') && <p className="text-xs text-gray-500">ADMIN also implies every permission.</p>}
              </div>
              {canChange && !isSelf && !u.is_system_user && (
                <div>
                  {u.is_active ? (
                    <button className="btn-secondary px-3 py-1.5 text-sm hover:text-red-400" disabled={change.isPending}
                      onClick={() => window.confirm(`Deactivate ${u.username}? Their live sessions will be ended.`) && change.mutate(() => usersApi.deactivate(u.id))}>
                      Deactivate account
                    </button>
                  ) : (
                    <button className="btn-secondary px-3 py-1.5 text-sm" disabled={change.isPending}
                      onClick={() => change.mutate(() => usersApi.reactivate(u.id))}>Reactivate account</button>
                  )}
                </div>
              )}
            </>
          ) : null}
        </section>
      )}
    </div>
  );
}


function FieldRow({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block space-y-1">
      <span className="text-xs font-medium text-gray-400">{label}</span>
      {children}
      {hint && <span className="block text-xs text-gray-500">{hint}</span>}
    </label>
  );
}

function CreateUserDialog({ devAccounts, roles, onClose, onCreated }: {
  devAccounts: boolean; roles: { id: string; name: string; description: string | null }[];
  onClose: () => void; onCreated: (id: string) => void;
}) {
  const [form, setForm] = useState({ username: '', email: '', full_name: '', external_id: '', password: '' });
  const [roleIds, setRoleIds] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: () => usersApi.create({
      username: form.username.trim(), email: form.email.trim(), full_name: form.full_name.trim(), role_ids: roleIds,
      ...(devAccounts ? { password: form.password } : { external_id: form.external_id.trim() }),
    }),
    onSuccess: (user) => onCreated(user.id),
    onError: (e) => setError(getApiErrorMessage(e, 'The account could not be created.')),
  });
  const valid = form.username.trim().length >= 2 && form.email.includes('@') && form.full_name.trim() &&
    (devAccounts ? form.password.length >= 12 : /^[0-9a-f-]{36}$/i.test(form.external_id.trim()));
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [k]: e.target.value });

  return (
    <Modal title="Add user" onClose={onClose}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); if (valid) create.mutate(); }}>
        <p className="rounded-md border border-navy-700/60 bg-navy-800/60 px-3 py-2 text-xs text-gray-400">
          {devAccounts
            ? 'This deployment uses development accounts: the user signs in with the username and the initial password below.'
            : 'Sign-in is through Keycloak. Enter the person\'s Keycloak user ID (Users → user → ID in the Keycloak admin console); SecurePAM matches sign-ins by that ID. Passwords and MFA are managed in Keycloak.'}
        </p>
        {error && <ErrorBanner message={error} />}
        <div className="grid grid-cols-2 gap-3">
          <FieldRow label="Username" hint="lowercase letters, digits, . _ -"><input className="input" autoFocus required value={form.username} onChange={set('username')} /></FieldRow>
          <FieldRow label="Full name"><input className="input" required value={form.full_name} onChange={set('full_name')} /></FieldRow>
        </div>
        <FieldRow label="Email"><input className="input" type="email" required value={form.email} onChange={set('email')} /></FieldRow>
        {devAccounts ? (
          <FieldRow label="Initial password" hint="At least 12 characters. Stored only as a hash.">
            <input className="input" type="password" autoComplete="new-password" required minLength={12} value={form.password} onChange={set('password')} />
          </FieldRow>
        ) : (
          <FieldRow label="Keycloak user ID" hint="UUID, e.g. 0b6f3f3c-5d1e-4c1b-9a4e-2f8f3c1d2e10">
            <input className="input font-mono" required value={form.external_id} onChange={set('external_id')} />
          </FieldRow>
        )}
        <fieldset>
          <legend className="mb-1 text-xs font-medium text-gray-400">Roles</legend>
          <div className="grid grid-cols-2 gap-2">
            {roles.map((r) => (
              <label key={r.id} className="flex items-start gap-2 rounded-md border border-navy-700/60 p-2 text-sm text-gray-300">
                <input type="checkbox" className="mt-0.5" checked={roleIds.includes(r.id)}
                  onChange={(e) => setRoleIds(e.target.checked ? [...roleIds, r.id] : roleIds.filter((x) => x !== r.id))} />
                <span><span className="font-medium">{r.name}</span>
                  {r.description && <span className="block text-xs text-gray-500">{r.description}</span>}</span>
              </label>
            ))}
          </div>
          {roleIds.length === 0 && <p className="mt-1 text-xs text-amber-400">Without a role the account can sign in but do nothing.</p>}
        </fieldset>
        <div className="flex justify-end gap-2 pt-2">
          <button type="button" className="btn-ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn-primary" disabled={!valid || create.isPending}>{create.isPending ? 'Creating…' : 'Create user'}</button>
        </div>
      </form>
    </Modal>
  );
}

function EditUserDialog({ user, isSelf, onClose, onSaved }: {
  user: AdminUser; isSelf: boolean; onClose: () => void; onSaved: () => void;
}) {
  const [form, setForm] = useState({ full_name: user.full_name, email: user.email, external_id: user.external_id ?? '' });
  const [error, setError] = useState<string | null>(null);
  const canLink = !user.external_id && !isSelf;
  const save = useMutation({
    mutationFn: () => usersApi.update(user.id, {
      ...(form.full_name !== user.full_name ? { full_name: form.full_name.trim() } : {}),
      ...(form.email !== user.email ? { email: form.email.trim() } : {}),
      ...(canLink && form.external_id.trim() ? { external_id: form.external_id.trim() } : {}),
    }),
    onSuccess: onSaved,
    onError: (e) => setError(getApiErrorMessage(e, 'The change was refused.')),
  });
  return (
    <Modal title={`Edit ${user.username}`} onClose={onClose}>
      <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
        {error && <ErrorBanner message={error} />}
        <FieldRow label="Full name"><input className="input" required value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} /></FieldRow>
        <FieldRow label="Email"><input className="input" type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></FieldRow>
        <FieldRow label="Keycloak user ID" hint={user.external_id ? 'Linked identities cannot be re-pointed; deactivate and create a new account instead.'
          : isSelf ? 'You cannot link your own account.' : 'Optional: link this account to a Keycloak identity (once).'}>
          <input className="input font-mono" disabled={!canLink} value={form.external_id} onChange={(e) => setForm({ ...form, external_id: e.target.value })} />
        </FieldRow>
        <div className="flex justify-end gap-2 pt-2">
          <button type="button" className="btn-ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="btn-primary" disabled={save.isPending}>{save.isPending ? 'Saving…' : 'Save changes'}</button>
        </div>
      </form>
    </Modal>
  );
}
