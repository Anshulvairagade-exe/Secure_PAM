/**
 * Development-only session for DEV_MODE backends.
 *
 * When the backend reports `dev_mode: true` (GET /auth/config), there is no
 * Keycloak: the user signs in with POST /auth/login against the seeded
 * development accounts and the backend issues its own short-lived token.
 * The backend refuses DEV_MODE outside ENVIRONMENT=development|test, so
 * this path cannot be reached against a staging or production backend.
 *
 * The token is kept in memory and mirrored to sessionStorage (tab-scoped,
 * cleared when the tab closes) so a page reload does not sign the user out.
 */

const STORAGE_KEY = 'securepam_dev_access_token';

function readStored(): string | null {
  try {
    return window.sessionStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

let devToken: string | null = readStored();

export function getDevToken(): string | null {
  return devToken;
}

export function setDevToken(token: string): void {
  devToken = token;
  try {
    window.sessionStorage.setItem(STORAGE_KEY, token);
  } catch {
    // Storage unavailable (private mode): the in-memory token still works.
  }
}

export function clearDevToken(): void {
  devToken = null;
  try {
    window.sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // Nothing stored.
  }
}
