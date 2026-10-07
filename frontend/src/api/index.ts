/**
 * API service functions — typed wrappers around the API client.
 */

import apiClient from './client';
import type {
  AuthConfig,
  LoginRequest,
  TokenResponse,
  UserInfo,
  DashboardSummary,
  DashboardActivity,
  Asset,
  Application,
  Policy,
  AuditLog,
  DetailedHealth,
} from '@/types';

// --- Auth ---

export const authApi = {
  getConfig: () =>
    apiClient.get<AuthConfig>('/auth/config').then(r => r.data),

  login: (data: LoginRequest) =>
    apiClient.post<TokenResponse>('/auth/login', data).then(r => r.data),

  me: () =>
    apiClient.get<UserInfo>('/auth/me').then(r => r.data),
};

// --- Dashboard ---

export const dashboardApi = {
  getSummary: () =>
    apiClient.get<DashboardSummary>('/dashboard/summary').then(r => r.data),

  getActivity: (limit = 20) =>
    apiClient.get<DashboardActivity[]>('/dashboard/activity', { params: { limit } }).then(r => r.data),
};

// --- Assets ---

export const assetsApi = {
  list: () =>
    apiClient.get<Asset[]>('/assets').then(r => r.data),

  get: (id: string) =>
    apiClient.get<Asset>(`/assets/${id}`).then(r => r.data),

  create: (data: Partial<Asset>) =>
    apiClient.post<Asset>('/assets', data).then(r => r.data),

  update: (id: string, data: Partial<Asset>) =>
    apiClient.put<Asset>(`/assets/${id}`, data).then(r => r.data),

  delete: (id: string) =>
    apiClient.delete(`/assets/${id}`).then(r => r.data),
};

// --- Applications ---

export const applicationsApi = {
  list: () =>
    apiClient.get<Application[]>('/applications').then(r => r.data),

  get: (id: string) =>
    apiClient.get<Application>(`/applications/${id}`).then(r => r.data),

  create: (data: Partial<Application>) =>
    apiClient.post<Application>('/applications', data).then(r => r.data),

  update: (id: string, data: Partial<Application>) =>
    apiClient.put<Application>(`/applications/${id}`, data).then(r => r.data),

  delete: (id: string) =>
    apiClient.delete(`/applications/${id}`).then(r => r.data),
};

// --- Policies ---

export const policiesApi = {
  list: () =>
    apiClient.get<Policy[]>('/policies').then(r => r.data),

  get: (id: string) =>
    apiClient.get<Policy>(`/policies/${id}`).then(r => r.data),

  create: (data: Partial<Policy>) =>
    apiClient.post<Policy>('/policies', data).then(r => r.data),

  update: (id: string, data: Partial<Policy>) =>
    apiClient.put<Policy>(`/policies/${id}`, data).then(r => r.data),
};

// --- Audit ---

export const auditApi = {
  list: (params?: Record<string, string | number>) =>
    apiClient.get<AuditLog[]>('/audit', { params }).then(r => r.data),
};

// --- Health ---

export const healthApi = {
  detailed: () =>
    apiClient.get<DetailedHealth>('/health/detailed', { baseURL: import.meta.env.VITE_API_URL || '' }).then(r => r.data),
};
