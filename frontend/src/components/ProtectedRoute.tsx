import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRoles?: string[];
}

export default function ProtectedRoute({ children, requiredRoles }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading, hasAnyRole } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center bg-navy-950">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-navy-600 border-t-blue-500" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (requiredRoles && requiredRoles.length > 0 && !hasAnyRole(requiredRoles)) {
    return (
      <div className="flex h-screen flex-col items-center justify-center gap-3 bg-navy-950 text-center">
        <p className="text-lg font-semibold text-gray-200">Access Denied</p>
        <p className="max-w-sm text-sm text-gray-500">
          You are not authorized to view this page. Required role: {requiredRoles.join(', ')}.
        </p>
      </div>
    );
  }

  return <>{children}</>;
}
