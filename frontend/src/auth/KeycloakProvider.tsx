
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
  login: () => void;
  logout: () => void;
  getToken: () => Promise<string | undefined>;
}

const KeycloakContext = createContext<KeycloakContextValue | undefined>(
  undefined
);

// Share one initialization promise, including across React StrictMode effects.
let initializationPromise: Promise<boolean> | null = null;

function initializeKeycloak(): Promise<boolean> {
  if (!initializationPromise) {
    initializationPromise = keycloak.init({
      onLoad: 'check-sso',
      pkceMethod: 'S256',
      checkLoginIframe: false,
    });
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

  useEffect(() => {
    let active = true;

    initializeKeycloak()
      .then((isAuthenticated) => {
        if (active) {
          setAuthenticated(isAuthenticated);
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
