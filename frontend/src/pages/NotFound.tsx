import { Link } from 'react-router-dom';

export default function NotFound() {
  return (
    <div className="flex h-screen flex-col items-center justify-center gap-3 bg-navy-950 text-center">
      <p className="text-4xl font-bold text-gray-700">404</p>
      <p className="text-sm text-gray-500">Page not found.</p>
      <Link to="/" className="btn-secondary mt-2">
        Back to Dashboard
      </Link>
    </div>
  );
}
