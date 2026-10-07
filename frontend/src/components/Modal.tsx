import { X } from 'lucide-react';
import { useEffect } from 'react';

interface ModalProps {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  width?: string;
}

export default function Modal({ title, onClose, children, width = 'max-w-lg' }: ModalProps) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className={`card w-full ${width} max-h-[85vh] overflow-y-auto bg-navy-900 p-6`}>
        <div className="mb-5 flex items-center justify-between">
          <h2 className="text-base font-semibold text-gray-100">{title}</h2>
          <button onClick={onClose} className="rounded-lg p-1 text-gray-500 hover:bg-navy-800 hover:text-gray-300">
            <X size={18} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
