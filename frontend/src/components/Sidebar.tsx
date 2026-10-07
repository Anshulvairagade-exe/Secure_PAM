import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  FileClock,
  MonitorPlay,
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

interface NavItem {
  label: string;
  path: string;
  icon: React.ElementType;
  roles?: string[];
}

const NAV_ITEMS: NavItem[] = [
  { label: 'Dashboard', path: '/', icon: LayoutDashboard },
  { label: 'Access Requests', path: '/access-requests', icon: FileClock },
  { label: 'My Sessions', path: '/sessions', icon: MonitorPlay },
  { label: 'Assets', path: '/assets', icon: Server },
  { label: 'Applications', path: '/applications', icon: Globe },
  { label: 'Approvals', path: '/approvals', icon: CheckSquare, roles: ['ADMIN', 'APPROVER', 'AUDITOR'] },
  { label: 'Recordings', path: '/recordings', icon: Video, roles: ['ADMIN', 'AUDITOR'] },
  { label: 'Audit Logs', path: '/audit', icon: ScrollText, roles: ['ADMIN', 'AUDITOR'] },
  { label: 'Risk Center', path: '/risk', icon: Gauge, roles: ['ADMIN', 'APPROVER', 'AUDITOR'] },
  { label: 'Policies', path: '/policies', icon: ShieldCheck, roles: ['ADMIN', 'APPROVER', 'AUDITOR'] },
  { label: 'Vault', path: '/vault', icon: KeyRound, roles: ['ADMIN'] },
  { label: 'Users', path: '/users', icon: Users, roles: ['ADMIN'] },
  { label: 'Roles', path: '/roles', icon: UserCog, roles: ['ADMIN'] },
  { label: 'Settings', path: '/settings', icon: Settings },
];

export default function Sidebar() {
  const { hasAnyRole } = useAuth();

  return (
    <aside className="flex h-screen w-64 flex-shrink-0 flex-col border-r border-navy-700/40 bg-navy-900/60">
      <div className="flex items-center gap-2.5 px-5 py-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-500/15 text-blue-400">
          <ShieldHalf size={20} />
        </div>
        <div>
          <p className="text-sm font-bold leading-tight text-gray-100">SecurePAM</p>
          <p className="text-[11px] leading-tight text-gray-500">Risk-Adaptive PAM</p>
        </div>
      </div>

      <nav className="flex-1 space-y-0.5 overflow-y-auto px-3 py-2">
        {NAV_ITEMS.filter((item) => !item.roles || hasAnyRole(item.roles)).map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.path === '/'}
            className={({ isActive }) =>
              clsx(isActive ? 'sidebar-link-active' : 'sidebar-link')
            }
          >
            <item.icon size={17} strokeWidth={2} />
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-navy-700/40 px-5 py-3 text-[11px] text-gray-600">
        SecurePAM v0.1.0 · DEV_MODE
      </div>
    </aside>
  );
}
