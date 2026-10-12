
import { useEffect } from 'react';
import { useNavigate, useLocation, Navigate } from 'react-router-dom';
import { ShieldHalf } from 'lucide-react';
import { useAuth } from '@/hooks/useAuth';
import { useKeycloak } from '@/auth/KeycloakProvider';
import { ErrorBanner } from '@/components/Feedback';

export default function Login() {
  const { isAuthenticated, isLoading } = useAuth();
  const { login, initialized, authenticated } = useKeycloak();
  const navigate = useNavigate();
  const location = useLocation();

  const from =
    (location.state as { from?: { pathname?: string } } | null)?.from?.pathname ?? '/';

  useEffect(() => {
    if (initialized && authenticated && !isLoading && isAuthenticated) {
      navigate(from, { replace: true });
    }
  }, [initialized, authenticated, isLoading, isAuthenticated, navigate, from]);

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
