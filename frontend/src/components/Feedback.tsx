/**
 * Shared loading/error/empty-state primitives, so every page shows these
 * the same way instead of each hand-rolling its own markup.
 */
import { AlertCircle, Inbox } from 'lucide-react';

export function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
      <AlertCircle size={16} className="flex-shrink-0" />
      {message}
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center gap-2 py-10 text-center text-gray-500">
      <Inbox size={22} />
      <p className="max-w-sm text-sm">{message}</p>
    </div>
  );
}

export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`animate-pulse rounded-lg bg-navy-800/40 ${className}`} />;
}

export function Spinner({ size = 16 }: { size?: number }) {
  return (
    <div
      style={{ width: size, height: size }}
      className="animate-spin rounded-full border-2 border-navy-600 border-t-blue-500"
    />
  );
}
