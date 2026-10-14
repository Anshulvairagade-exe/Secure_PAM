import { X } from 'lucide-react';
import { useEffect, useId } from 'react';

interface ModalProps {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  width?: string;
}

export default function Modal({ title, onClose, children, width = 'max-w-lg' }: ModalProps) {
  const titleId = useId();
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 p-4 backdrop-blur-[2px] dark:bg-black/60">
      <div role="dialog" aria-modal="true" aria-labelledby={titleId}
        className={`card w-full ${width} max-h-[85vh] overflow-y-auto bg-navy-900 p-6 shadow-xl`}>
        <div className="mb-5 flex items-center justify-between">
          <h2 id={titleId} className="text-base font-semibold text-gray-100">{title}</h2>
          <button onClick={onClose} aria-label="Close dialog" className="kbd-focus rounded-lg p-1 text-gray-500 hover:bg-navy-800 hover:text-gray-300">
            <X size={18} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
