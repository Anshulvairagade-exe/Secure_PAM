
import React, {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
} from 'react';
import keycloak from './keycloak';

interface KeycloakContextValue {
  initialized: boolean;
  authenticated: boolean;
  /** Backend runs DEV_MODE: no Keycloak; sign in with the seeded dev accounts. */
  devMode: boolean;
  login: () => void;
  logout: () => void;
  getToken: () => Promise<string | undefined>;
}

const KeycloakContext = createContext<KeycloakContextValue | undefined>(
  undefined
);

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

// Share one initialization promise, including across React StrictMode effects.
let initializationPromise: Promise<{ devMode: boolean; authenticated: boolean }> | null = null;

async function backendDevMode(): Promise<boolean> {
  // Plain fetch: the API client's interceptors depend on this provider.
  const response = await fetch(`${API_BASE_URL}/api/v1/auth/config`);
  if (!response.ok) throw new Error(`GET /auth/config returned ${response.status}`);
  const config = (await response.json()) as { dev_mode?: boolean };
  return config.dev_mode === true;
}

function initializeKeycloak(): Promise<{ devMode: boolean; authenticated: boolean }> {
  if (!initializationPromise) {
    initializationPromise = (async () => {
      // A DEV_MODE backend has no Keycloak. Skip init entirely: check-sso
      // would otherwise redirect the whole page to an absent Keycloak server.
      if (await backendDevMode()) {
        return { devMode: true, authenticated: false };
      }
      const authenticated = await keycloak.init({
        onLoad: 'check-sso',
        pkceMethod: 'S256',
        checkLoginIframe: false,
      });
      return { devMode: false, authenticated };
    })();
  }

  return initializationPromise;
}

export function KeycloakProvider({
  children,
}: {
  children: React.ReactNode;
}) {
  const [initialized, setInitialized] = useState(false);
  const [authenticated, setAuthenticated] = useState(false);
  const [devMode, setDevMode] = useState(false);

  useEffect(() => {
    let active = true;

    initializeKeycloak()
      .then((result) => {
        if (active) {
          setDevMode(result.devMode);
          setAuthenticated(result.authenticated);
          setInitialized(true);
        }
      })
      .catch((error) => {
        console.error('Keycloak initialization failed:', error);

        if (active) {
          setAuthenticated(false);
          setInitialized(true);
        }
      });

    return () => {
      active = false;
    };
  }, []);

  const getToken = useCallback(async (): Promise<string | undefined> => {
    if (!keycloak.authenticated) return undefined;

    try {
      await keycloak.updateToken(30);
      return keycloak.token;
    } catch (error) {
      console.error('Unable to refresh Keycloak token:', error);
      return undefined;
    }
  }, []);

  const value: KeycloakContextValue = {
    initialized,
    authenticated,
    devMode,
    login: () => {
      void keycloak.login({
        redirectUri: `${window.location.origin}/login`,
      });
    },
    logout: () => {
      void keycloak.logout({
        redirectUri: `${window.location.origin}/login`,
      });
    },
    getToken,
  };

  return (
    <KeycloakContext.Provider value={value}>
      {children}
    </KeycloakContext.Provider>
  );
}

export function useKeycloak() {
  const context = useContext(KeycloakContext);

  if (!context) {
    throw new Error('useKeycloak must be used within KeycloakProvider');
  }

  return context;
}
