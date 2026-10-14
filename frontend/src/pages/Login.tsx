
import { FormEvent, useEffect, useState } from 'react';
import { useNavigate, useLocation, Navigate } from 'react-router-dom';
import { ShieldHalf } from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { useKeycloak } from '@/auth/KeycloakProvider';
import { ErrorBanner } from '@/components/Feedback';

export default function Login() {
  const { isAuthenticated, isLoading, devMode, login: devLogin } = useAuth();
  const { login, initialized, authenticated } = useKeycloak();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [devError, setDevError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const submitDevLogin = async (event: FormEvent) => {
    event.preventDefault();
    setDevError(null);
    setSubmitting(true);
    try {
      await devLogin(username, password);
      setPassword('');
    } catch {
      setDevError('Sign-in failed. Check the username and password.');
    } finally {
      setSubmitting(false);
    }
  };
  const navigate = useNavigate();
  const location = useLocation();

  const from =
    (location.state as { from?: { pathname?: string } } | null)?.from?.pathname ?? '/';

  useEffect(() => {
    if (initialized && (authenticated || devMode) && !isLoading && isAuthenticated) {
      navigate(from, { replace: true });
    }
  }, [initialized, authenticated, devMode, isLoading, isAuthenticated, navigate, from]);

  if (isAuthenticated) {
    return <Navigate to={from} replace />;
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-navy-950 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center text-center">
          <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-blue-500/15 text-blue-400">
            <ShieldHalf size={26} />
          </div>

          <h1 className="text-xl font-bold text-gray-100">SecurePAM</h1>
          <p className="mt-1 text-sm text-gray-500">
            Risk-Adaptive Privileged Access Management
          </p>
        </div>

        <div className="card space-y-4 p-6">
          {!initialized ? (
            <p className="text-center text-sm text-gray-400">
              Initializing secure sign-in...
            </p>
          ) : devMode ? (
            <form onSubmit={submitDevLogin} className="space-y-3">
              <input
                className="input"
                placeholder="Username"
                autoComplete="username"
                value={username}
                onChange={e => setUsername(e.target.value)}
                required
              />
              <input
                className="input"
                type="password"
                placeholder="Password"
                autoComplete="current-password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
              />
              <button type="submit" className="btn-primary w-full" disabled={submitting}>
                {submitting ? 'Signing in...' : 'Sign in'}
              </button>
              {devError && <ErrorBanner message={devError} />}
            </form>
          ) : (
            <>
              <p className="text-center text-sm text-gray-400">
                Sign in securely through your organization's identity provider.
              </p>

              <button
                type="button"
                onClick={() => login()}
                className="btn-primary w-full"
              >
                Sign in with Keycloak
              </button>
            </>
          )}

          {initialized && authenticated && !isAuthenticated && !isLoading && (
            <ErrorBanner message="You are signed in to Keycloak, but your SecurePAM account could not be loaded. Contact your administrator." />
          )}
        </div>
      </div>
    </div>
  );
}
