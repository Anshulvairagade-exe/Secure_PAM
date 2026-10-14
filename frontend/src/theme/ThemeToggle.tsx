import { Monitor, Moon, Sun } from 'lucide-react';
import { useTheme, type ThemePreference } from './ThemeProvider';

const OPTIONS: { value: ThemePreference; label: string; Icon: typeof Sun }[] = [
  { value: 'light', label: 'Light', Icon: Sun },
  { value: 'dark', label: 'Dark', Icon: Moon },
  { value: 'system', label: 'System', Icon: Monitor },
];

/** Segmented Light / Dark / System control (radio semantics, keyboard accessible). */
export default function ThemeToggle({ compact = false }: { compact?: boolean }) {
  const { preference, setPreference } = useTheme();
  return (
    <div role="radiogroup" aria-label="Colour theme"
      className="inline-flex items-center rounded-lg border border-navy-700/60 bg-navy-800/60 p-0.5">
      {OPTIONS.map(({ value, label, Icon }) => {
        const active = preference === value;
        return (
          <button key={value} type="button" role="radio" aria-checked={active} title={`${label} theme`}
            onClick={() => setPreference(value)}
            className={`kbd-focus inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium transition-colors ${
              active ? 'bg-navy-900 text-gray-100 shadow-sm dark:bg-navy-700' : 'text-gray-500 hover:text-gray-200'}`}>
            <Icon size={14} aria-hidden="true" />
            {!compact && <span>{label}</span>}
            {compact && <span className="sr-only">{label}</span>}
          </button>
        );
      })}
    </div>
  );
}
