import { useState, FormEvent } from 'react';
import { useNavigate, useLocation, Navigate } from 'react-router-dom';
import { ShieldHalf } from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { getApiErrorMessage } from '@/api/errors';
import { ErrorBanner } from '@/components/Feedback';

export default function Login() {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (isAuthenticated) {
    const from = (location.state as { from?: Location })?.from?.pathname ?? '/';
    return <Navigate to={from} replace />;
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(username, password);
      navigate('/', { replace: true });
    } catch (err) {
      setError(getApiErrorMessage(err, 'Login failed. Please try again.'));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-navy-950 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-blue-500/15 text-blue-400">
            <ShieldHalf size={26} />
          </div>
          <h1 className="text-xl font-bold text-gray-100">SecurePAM</h1>
          <p className="mt-1 text-sm text-gray-500">Risk-Adaptive Privileged Access Management</p>
        </div>

        <form onSubmit={handleSubmit} className="card space-y-4 p-6">
          {error && <ErrorBanner message={error} />}

          <div>
            <label className="mb-1.5 block text-xs font-medium text-gray-400">Username</label>
            <input
              className="input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoFocus
              autoComplete="username"
              required
            />
          </div>

          <div>
            <label className="mb-1.5 block text-xs font-medium text-gray-400">Password</label>
            <input
              type="password"
              className="input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </div>

          <button type="submit" disabled={submitting} className="btn-primary w-full">
            {submitting ? 'Signing in...' : 'Sign in'}
          </button>

          <p className="pt-1 text-center text-[11px] text-gray-600">
            DEV_MODE — try <code className="text-gray-500">admin / admin123</code>,{' '}
            <code className="text-gray-500">operator / operator123</code>,{' '}
            <code className="text-gray-500">approver / approver123</code>, or{' '}
            <code className="text-gray-500">auditor / auditor123</code>
          </p>
        </form>
      </div>
    </div>
  );
}
