
/**
 * Authentication Context — manages SecurePAM authentication.
 *
 * Keycloak handles login and token management.
 * SecurePAM's backend supplies user information, roles, and permissions.
 */

import React, {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
} from 'react';
import type { UserInfo } from '@/types';
import { authApi } from '@/api';
import { useKeycloak } from '@/auth/KeycloakProvider';

interface AuthContextType {
  user: UserInfo | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (username?: string, password?: string) => Promise<void>;
  logout: () => void;
  hasRole: (role: string) => boolean;
  hasPermission: (permission: string) => boolean;
  hasAnyRole: (roles: string[]) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const {
    initialized,
    authenticated,
    login: keycloakLogin,
    logout: keycloakLogout,
    getToken,
  } = useKeycloak();

  const [user, setUser] = useState<UserInfo | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const fetchUser = useCallback(async () => {
    if (!initialized) return;

    if (!authenticated) {
      setUser(null);
      setIsLoading(false);
      return;
    }

    setIsLoading(true);

    try {
      const token = await getToken();

      if (!token) {
        setUser(null);
        return;
      }

      const userInfo = await authApi.me();
      setUser(userInfo);
    } catch (error) {
      console.error('Unable to load SecurePAM user profile:', error);
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  }, [initialized, authenticated, getToken]);

  useEffect(() => {
    void fetchUser();
  }, [fetchUser]);

  const login = async (_username?: string, _password?: string) => {
    keycloakLogin();
  };

  const logout = () => {
    setUser(null);
    keycloakLogout();
  };

  const hasRole = (role: string) => user?.roles?.includes(role) ?? false;
  const hasAnyRole = (roles: string[]) => roles.some(role => hasRole(role));

  const hasPermission = (permission: string) => {
    if (user?.roles?.includes('ADMIN')) return true;
    return user?.permissions?.includes(permission) ?? false;
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: authenticated && !!user,
        isLoading: !initialized || isLoading,
        login,
        logout,
        hasRole,
        hasPermission,
        hasAnyRole,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }

  return context;
}
