import { Construction } from 'lucide-react';

export default function ComingSoon({ title, phase }: { title: string; phase: string }) {
  return (
    <div className="flex h-[70vh] flex-col items-center justify-center gap-3 text-center">
      <div className="flex h-14 w-14 items-center justify-center rounded-xl bg-navy-800/60 text-gray-500">
        <Construction size={26} />
      </div>
      <h1 className="text-lg font-semibold text-gray-200">{title}</h1>
      <p className="max-w-sm text-sm text-gray-500">
        This section is planned for <span className="text-gray-400">{phase}</span> of the
        SecurePAM build and is not implemented yet.
      </p>
    </div>
  );
}
