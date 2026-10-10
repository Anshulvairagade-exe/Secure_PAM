
/**
 * Axios API client with Keycloak authentication.
 *
 * Access tokens remain in memory and are attached to API requests.
 * SecurePAM's backend validates tokens and enforces permissions.
 */

import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios';
import keycloak from '@/auth/keycloak';

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

const apiClient = axios.create({
  baseURL: `${API_BASE_URL}/api/v1`,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
});

// Attach a current Keycloak access token to API requests.

apiClient.interceptors.request.use(
  async (config: InternalAxiosRequestConfig) => {
    if (keycloak.authenticated) {
      try {
        await keycloak.updateToken(30);

        if (keycloak.token && config.headers) {
          config.headers.Authorization = `Bearer ${keycloak.token}`;
        }
      } catch (error) {
        // Do not send a request with a token that could not be refreshed.
        if (window.location.pathname !== '/login') {
          window.location.href = '/login';
        }

        return Promise.reject(error);
      }
    }

    return config;
  },
  (error) => Promise.reject(error)
);

// Handle API authentication errors without creating redirect loops.
apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (
      error.response?.status === 401 &&
      window.location.pathname !== '/login'
    ) {
      window.location.href = '/login';
    }

    return Promise.reject(error);
  }
);

export default apiClient;
