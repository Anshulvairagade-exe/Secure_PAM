import { useQuery } from '@tanstack/react-query';
import { ShieldCheck } from 'lucide-react';
import { rolesApi } from '@/api';
import { getApiErrorMessage } from '@/api/errors';
import { EmptyState, ErrorBanner, Skeleton } from '@/components/Feedback';
import type { AdminRole } from '@/types';

function groupByResource(permissions: AdminRole['permissions']): [string, string[]][] {
  const groups = new Map<string, string[]>();
  for (const { name } of permissions) {
    const [resource, action] = name.split(':');
    groups.set(resource, [...(groups.get(resource) ?? []), action]);
  }
  return [...groups.entries()];
}

export default function Roles() {
  const roles = useQuery({ queryKey: ['roles'], queryFn: rolesApi.list });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-gray-100">Roles</h1>
        <p className="mt-0.5 text-sm text-gray-500">
          SecurePAM application roles and the permissions they grant. Roles held in the identity provider (Keycloak)
          are not shown and carry no authority here: access is decided only by these assignments. Assign roles from
          the Users page.
        </p>
      </div>

      {roles.isError && <ErrorBanner message={getApiErrorMessage(roles.error, 'Failed to load roles.')} />}
      {roles.isLoading ? (
        <div className="grid gap-4 md:grid-cols-2">{[0, 1].map((i) => <Skeleton key={i} className="h-48" />)}</div>
      ) : roles.data && roles.data.length === 0 ? (
        <EmptyState message="No roles are defined." />
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {roles.data?.map((role) => (
            <section key={role.id} className="card space-y-3 p-5" aria-label={`Role ${role.name}`}>
              <div className="flex items-center justify-between">
                <h2 className="flex items-center gap-2 text-sm font-semibold text-gray-100">
                  <ShieldCheck size={16} /> {role.name}
                </h2>
                <div className="flex gap-2">
                  {role.is_system && <span className="badge-neutral">system</span>}
                  <span className={role.is_active ? 'badge-success' : 'badge-danger'}>{role.is_active ? 'active' : 'inactive'}</span>
                </div>
              </div>
              <p className="text-sm text-gray-400">{role.description ?? 'No description.'}</p>
              {role.name === 'ADMIN' && (
                <p className="text-xs text-gray-500">ADMIN holds every permission while the role is active.</p>
              )}
              <div>
                <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">
                  Permissions ({role.permissions.length})
                </h3>
                <dl className="space-y-1 text-xs">
                  {groupByResource(role.permissions).map(([resource, actions]) => (
                    <div key={resource} className="flex gap-2">
                      <dt className="w-32 shrink-0 font-mono text-gray-400">{resource}</dt>
                      <dd className="text-gray-300">{actions.join(', ')}</dd>
                    </div>
                  ))}
                </dl>
              </div>
              <div>
                <h3 className="mb-1 text-xs font-medium uppercase tracking-wide text-gray-500">
                  Assigned users ({role.users.length})
                </h3>
                {role.users.length === 0 ? (
                  <p className="text-xs text-gray-500">No users hold this role.</p>
                ) : (
                  <ul className="flex flex-wrap gap-2">
                    {role.users.map((u) => (
                      <li key={u.id} className={u.is_active ? 'badge-info' : 'badge-neutral'} title={u.is_active ? '' : 'deactivated'}>
                        {u.username}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </section>
          ))}
        </div>
      )}
    </div>
  );
}
