
/**
 * Authentication Context — manages SecurePAM authentication.
 *
 * Keycloak handles login and token management. Against a DEV_MODE backend
 * (no Keycloak) the seeded development accounts sign in through
 * POST /auth/login instead; see auth/devSession.
 * SecurePAM's backend supplies user information, roles, and permissions.
 */

import React, {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
} from 'react';
import axios from 'axios';
import type { UserInfo } from '@/types';
import { authApi } from '@/api';
import { useKeycloak } from '@/auth/KeycloakProvider';
import { clearDevToken, getDevToken, setDevToken } from '@/auth/devSession';

interface AuthContextType {
  user: UserInfo | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (username?: string, password?: string) => Promise<void>;
  /** True when signing in with DEV_MODE accounts rather than Keycloak. */
  devMode: boolean;
  logout: () => void;
  hasRole: (role: string) => boolean;
  hasPermission: (permission: string) => boolean;
  hasAnyRole: (roles: string[]) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const {
    initialized,
    authenticated: keycloakAuthenticated,
    devMode,
    login: keycloakLogin,
    logout: keycloakLogout,
    getToken,
  } = useKeycloak();

  const [user, setUser] = useState<UserInfo | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [hasDevToken, setHasDevToken] = useState(() => getDevToken() !== null);
  const authenticated = devMode ? hasDevToken : keycloakAuthenticated;

  const fetchUser = useCallback(async () => {
    if (!initialized) return;

    if (!authenticated) {
      setUser(null);
      setIsLoading(false);
      return;
    }

    setIsLoading(true);

    try {
      const token = devMode ? getDevToken() : await getToken();

      if (!token) {
        setUser(null);
        return;
      }

      const userInfo = await authApi.me();
      setUser(userInfo);
    } catch (error) {
      console.error('Unable to load SecurePAM user profile:', error);
      // Only an authentication failure ends the dev session; a transient
      // error (e.g. 429 rate limit, 503) must not sign the user out.
      if (devMode && axios.isAxiosError(error) && error.response?.status === 401) {
        clearDevToken();
        setHasDevToken(false);
      }
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  }, [initialized, authenticated, devMode, getToken]);

  useEffect(() => {
    void fetchUser();
  }, [fetchUser]);

  const login = async (username?: string, password?: string) => {
    if (!devMode) {
      keycloakLogin();
      return;
    }
    // Errors (e.g. 401 for a wrong password) propagate to the login form.
    const tokens = await authApi.login({ username: username ?? '', password: password ?? '' });
    setDevToken(tokens.access_token);
    setHasDevToken(true);
  };

  const logout = () => {
    setUser(null);
    if (devMode) {
      clearDevToken();
      setHasDevToken(false);
      window.location.href = '/login';
      return;
    }
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
        devMode,
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
