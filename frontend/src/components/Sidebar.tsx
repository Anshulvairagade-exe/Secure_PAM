import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  FileClock,
  MonitorPlay,
  MonitorCog,
  Server,
  Globe,
  CheckSquare,
  Video,
  ScrollText,
  Gauge,
  ShieldCheck,
  KeyRound,
  Users,
  UserCog,
  Settings,
  ShieldHalf,
} from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import clsx from 'clsx';

export interface NavItem {
  label: string;
  path: string;
  icon: React.ElementType;
  roles?: string[];
  group: string;
}

export const NAV_ITEMS: NavItem[] = [
  { label: 'Dashboard', path: '/', icon: LayoutDashboard, group: 'Overview' },
  { label: 'Risk Center', path: '/risk', icon: Gauge, roles: ['ADMIN', 'APPROVER', 'AUDITOR'], group: 'Overview' },
  { label: 'Access Requests', path: '/access-requests', icon: FileClock, group: 'Access' },
  { label: 'My Sessions', path: '/sessions', icon: MonitorPlay, group: 'Access' },
  { label: 'Approvals', path: '/approvals', icon: CheckSquare, roles: ['ADMIN', 'APPROVER', 'AUDITOR'], group: 'Access' },
  { label: 'Assets', path: '/assets', icon: Server, group: 'Inventory' },
  { label: 'Applications', path: '/applications', icon: Globe, group: 'Inventory' },
  { label: 'Vault', path: '/vault', icon: KeyRound, roles: ['ADMIN'], group: 'Inventory' },
  { label: 'All Sessions', path: '/admin/sessions', icon: MonitorCog, roles: ['ADMIN'], group: 'Oversight' },
  { label: 'Recordings', path: '/recordings', icon: Video, roles: ['ADMIN', 'AUDITOR'], group: 'Oversight' },
  { label: 'Audit Logs', path: '/audit', icon: ScrollText, roles: ['ADMIN', 'AUDITOR'], group: 'Oversight' },
  { label: 'Policies', path: '/policies', icon: ShieldCheck, roles: ['ADMIN', 'APPROVER', 'AUDITOR'], group: 'Administration' },
  { label: 'Users', path: '/users', icon: Users, roles: ['ADMIN'], group: 'Administration' },
  { label: 'Roles', path: '/roles', icon: UserCog, roles: ['ADMIN'], group: 'Administration' },
  { label: 'Settings', path: '/settings', icon: Settings, group: 'Administration' },
];

export default function Sidebar() {
  const { hasAnyRole } = useAuth();

  return (
    <aside className="flex h-screen w-60 flex-shrink-0 flex-col border-r border-navy-700/60 bg-navy-900 dark:border-navy-700/40 dark:bg-navy-900/60">
      <div className="flex items-center gap-2.5 px-5 py-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-500/15 text-blue-400">
          <ShieldHalf size={20} />
        </div>
        <div>
          <p className="text-sm font-bold leading-tight text-gray-100">SecurePAM</p>
          <p className="text-[11px] leading-tight text-gray-500">Risk-Adaptive PAM</p>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-2" aria-label="Main navigation">
        {[...new Set(NAV_ITEMS.map((i) => i.group))].map((group) => {
          const items = NAV_ITEMS.filter((item) => item.group === group && (!item.roles || hasAnyRole(item.roles)));
          if (items.length === 0) return null;
          return (
            <div key={group} className="mb-3">
              <p className="px-3 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-wider text-gray-500">{group}</p>
              <div className="space-y-0.5">
                {items.map((item) => (
                  <NavLink key={item.path} to={item.path} end={item.path === '/'}
                    className={({ isActive }) => clsx(isActive ? 'sidebar-link-active' : 'sidebar-link')}>
                    <item.icon size={16} strokeWidth={2} aria-hidden="true" />
                    <span>{item.label}</span>
                  </NavLink>
                ))}
              </div>
            </div>
          );
        })}
      </nav>

      <div className="border-t border-navy-700/60 px-5 py-3 text-[11px] text-gray-500 dark:border-navy-700/40">
        SecurePAM v0.1.0
      </div>
    </aside>
  );
}
