import { useState } from 'react';
import { Search, Bell, ShieldCheck, ChevronDown, LogOut } from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';

export default function Topbar() {
  const { user, logout } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <header className="flex h-16 flex-shrink-0 items-center justify-between border-b border-navy-700/40 bg-navy-900/40 px-6">
      <div className="relative w-96 max-w-sm">
        <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
        <input
          type="text"
          placeholder="Search assets, requests, sessions..."
          className="input pl-9"
        />
      </div>

      <div className="flex items-center gap-4">
        <button className="relative rounded-lg p-2 text-gray-400 hover:bg-navy-800/60 hover:text-gray-200">
          <Bell size={18} />
        </button>

        <div className="relative">
          <button
            onClick={() => setMenuOpen((v) => !v)}
            className="flex items-center gap-2.5 rounded-lg px-2 py-1.5 hover:bg-navy-800/60"
          >
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-blue-500/15 text-sm font-semibold text-blue-400">
              {user?.full_name?.[0] ?? '?'}
            </div>
            <div className="text-left">
              <p className="text-sm font-medium leading-tight text-gray-200">{user?.full_name}</p>
              <p className="flex items-center gap-1 text-[11px] leading-tight text-gray-500">
                {user?.roles?.[0]}
                {user?.mfa_enabled && (
                  <span className="inline-flex items-center gap-0.5 text-green-400">
                    <ShieldCheck size={11} /> MFA
                  </span>
                )}
              </p>
            </div>
            <ChevronDown size={14} className="text-gray-500" />
          </button>

          {menuOpen && (
            <div className="absolute right-0 top-full z-20 mt-2 w-48 overflow-hidden rounded-lg border border-navy-700/50 bg-navy-800 shadow-xl">
              <button
                onClick={logout}
                className="flex w-full items-center gap-2 px-4 py-3 text-sm text-gray-300 hover:bg-navy-700/60"
              >
                <LogOut size={15} />
                Sign out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
