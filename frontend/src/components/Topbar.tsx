import { useEffect, useRef, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { ChevronDown, LogOut, Settings } from 'lucide-react';
import { Link } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import ThemeToggle from '@/theme/ThemeToggle';
import { NAV_ITEMS } from '@/components/Sidebar';

/** Shell header: current section, theme control, account menu. No decorative controls: every element works. */
export default function Topbar() {
  const { user, logout } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const { pathname } = useLocation();
  const section = [...NAV_ITEMS].sort((a, b) => b.path.length - a.path.length)
    .find((i) => (i.path === '/' ? pathname === '/' : pathname.startsWith(i.path)))?.label ?? '';

  useEffect(() => {
    if (!menuOpen) return;
    const close = (e: MouseEvent | KeyboardEvent) => {
      if (e instanceof KeyboardEvent ? e.key === 'Escape' : !menuRef.current?.contains(e.target as Node)) setMenuOpen(false);
    };
    document.addEventListener('mousedown', close);
    document.addEventListener('keydown', close);
    return () => { document.removeEventListener('mousedown', close); document.removeEventListener('keydown', close); };
  }, [menuOpen]);

  return (
    <header className="flex h-14 flex-shrink-0 items-center justify-between border-b border-navy-700/60 bg-navy-900/70 px-6 backdrop-blur dark:border-navy-700/40">
      <p className="text-sm font-medium text-gray-400" aria-live="polite">{section}</p>
      <div className="flex items-center gap-3">
        <ThemeToggle compact />
        <div className="relative" ref={menuRef}>
          <button
            onClick={() => setMenuOpen((v) => !v)}
            aria-haspopup="menu" aria-expanded={menuOpen}
            className="kbd-focus flex items-center gap-2.5 rounded-lg px-2 py-1.5 hover:bg-navy-800/60"
          >
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-blue-500/15 text-sm font-semibold text-blue-400">
              {user?.full_name?.[0] ?? '?'}
            </div>
            <div className="hidden text-left sm:block">
              <p className="text-sm font-medium leading-tight text-gray-200">{user?.full_name}</p>
              {/* No MFA badge here: the local flag is not proof of an enrolled authenticator (see Settings). */}
              <p className="text-[11px] leading-tight text-gray-500">{user?.roles?.join(', ')}</p>
            </div>
            <ChevronDown size={14} className="text-gray-500" />
          </button>
          {menuOpen && (
            <div role="menu" className="absolute right-0 top-full z-20 mt-2 w-52 overflow-hidden rounded-lg border border-navy-700/60 bg-navy-900 shadow-xl">
              <Link role="menuitem" to="/settings" onClick={() => setMenuOpen(false)}
                className="flex w-full items-center gap-2 px-4 py-2.5 text-sm text-gray-300 hover:bg-navy-800">
                <Settings size={15} /> Settings &amp; profile
              </Link>
              <button role="menuitem" onClick={logout}
                className="flex w-full items-center gap-2 border-t border-navy-700/60 px-4 py-2.5 text-sm text-gray-300 hover:bg-navy-800">
                <LogOut size={15} /> Sign out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
