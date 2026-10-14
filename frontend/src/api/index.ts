/**
 * API service functions — typed wrappers around the API client.
 */

import apiClient from './client';
import type {
  UserCreateInput,
  UserUpdateInput,
  ProvisioningStatus,
  ProvisionedCredential,
  CredentialInput,
  RiskSummary,
  RiskFinding,
  RiskFindingDetail,
  AuthConfig,
  LoginRequest,
  TokenResponse,
  UserInfo,
  DashboardSummary,
  DashboardActivity,
  Asset,
  AssetInput,
  CredentialRef,
  CredentialRefCheck,
  CredentialRefInput,
  GrantRevokeResult,
  AdminRole,
  AdminUser,
  AdminUserDetail,
  SessionPolicy,
  TerminateAllResult,
  UserAccess,
  TranscriptResponse,
  Recording,
  Session,
  SSHLaunchResponse,
  SystemSettings,
  Application,
  ApplicationInput,
  Policy,
  PolicyInput,
  AccessRequest,
  AccessRequestInput,
  Approval,
  AuditLog,
  DetailedHealth,
  PaginatedResponse,
} from '@/types';

export interface ListParams {
  page?: number;
  page_size?: number;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
  [key: string]: string | number | boolean | undefined;
}

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
  list: (params?: ListParams) =>
    apiClient.get<PaginatedResponse<Asset>>('/assets', { params }).then(r => r.data),

  get: (id: string) =>
    apiClient.get<Asset>(`/assets/${id}`).then(r => r.data),

  create: (data: Partial<AssetInput>) =>
    apiClient.post<Asset>('/assets', data).then(r => r.data),

  update: (id: string, data: Partial<AssetInput>) =>
    apiClient.patch<Asset>(`/assets/${id}`, data).then(r => r.data),

  delete: (id: string) =>
    apiClient.delete(`/assets/${id}`).then(r => r.data),
};

// --- Applications ---

export const applicationsApi = {
  list: (params?: ListParams) =>
    apiClient.get<PaginatedResponse<Application>>('/applications', { params }).then(r => r.data),

  get: (id: string) =>
    apiClient.get<Application>(`/applications/${id}`).then(r => r.data),

  create: (data: Partial<ApplicationInput>) =>
    apiClient.post<Application>('/applications', data).then(r => r.data),

  update: (id: string, data: Partial<ApplicationInput>) =>
    apiClient.patch<Application>(`/applications/${id}`, data).then(r => r.data),

  delete: (id: string) =>
    apiClient.delete(`/applications/${id}`).then(r => r.data),
};

// --- Policies ---

export const policiesApi = {
  list: (params?: ListParams) =>
    apiClient.get<PaginatedResponse<Policy>>('/policies', { params }).then(r => r.data),

  get: (id: string) =>
    apiClient.get<Policy>(`/policies/${id}`).then(r => r.data),

  create: (data: Partial<PolicyInput>) =>
    apiClient.post<Policy>('/policies', data).then(r => r.data),

  update: (id: string, data: Partial<PolicyInput>) =>
    apiClient.patch<Policy>(`/policies/${id}`, data).then(r => r.data),

  delete: (id: string) =>
    apiClient.delete(`/policies/${id}`).then(r => r.data),
};

// --- Access Requests ---

export const accessRequestsApi = {
  list: (params?: ListParams) =>
    apiClient.get<PaginatedResponse<AccessRequest>>('/access-requests', { params }).then(r => r.data),

  get: (id: string) =>
    apiClient.get<AccessRequest>(`/access-requests/${id}`).then(r => r.data),

  create: (data: AccessRequestInput) =>
    apiClient.post<AccessRequest>('/access-requests', data).then(r => r.data),

  cancel: (id: string) =>
    apiClient.post<AccessRequest>(`/access-requests/${id}/cancel`).then(r => r.data),
};

// --- Approvals ---

export const approvalsApi = {
  list: (params?: ListParams) =>
    apiClient.get<PaginatedResponse<Approval>>('/approvals', { params }).then(r => r.data),

  get: (id: string) =>
    apiClient.get<Approval>(`/approvals/${id}`).then(r => r.data),

  approve: (id: string, comment?: string) =>
    apiClient.post<Approval>(`/approvals/${id}/approve`, { comment }).then(r => r.data),

  reject: (id: string, comment: string) =>
    apiClient.post<Approval>(`/approvals/${id}/reject`, { comment }).then(r => r.data),
};

// --- Credential references (pointers into OpenBao; no secret values) ---

export const credentialRefsApi = {
  /** Resolves to null when the asset has no active reference (404). */
  get: (assetId: string) =>
    apiClient
      .get<CredentialRef>(`/assets/${assetId}/credential-ref`)
      .then(r => r.data)
      .catch((error) => {
        if (error?.response?.status === 404) return null;
        throw error;
      }),

  set: (assetId: string, data: CredentialRefInput) =>
    apiClient.put<CredentialRef>(`/assets/${assetId}/credential-ref`, data).then(r => r.data),

  deactivate: (assetId: string) =>
    apiClient.delete(`/assets/${assetId}/credential-ref`).then(() => undefined),

  /** Admin-only readability probe. Returns safe status/reason only — never the secret. */
  check: (assetId: string) =>
    apiClient.post<CredentialRefCheck>(`/assets/${assetId}/credential-ref/check`).then(r => r.data),
};

// --- Audit ---

export const auditApi = {
  list: (params?: ListParams) =>
    apiClient
      .get<PaginatedResponse<AuditLog>>('/audit/', { params })
      .then(r => r.data),
};

// --- Health ---

// --- Sessions ---

export const sessionsApi = {
  list: (params?: ListParams) =>
    apiClient.get<PaginatedResponse<Session>>('/sessions/', { params }).then(r => r.data),

  get: (id: string) =>
    apiClient.get<Session>(`/sessions/${id}`).then(r => r.data),

  /** Isolated browser for a registered HTTP/HTTPS application (the destination comes from the server). */
  launchWeb: (requestId: string, applicationId: string) =>
    apiClient
      .post<SSHLaunchResponse>('/sessions/web/launch', { request_id: requestId, application_id: applicationId })
      .then(r => r.data),

  launchRDP: (requestId: string, assetId: string) =>
    apiClient
      .post<SSHLaunchResponse>('/sessions/rdp/launch', { request_id: requestId, asset_id: assetId })
      .then(r => r.data),

  launchSSH: (requestId: string, assetId: string) =>
    apiClient
      .post<SSHLaunchResponse>('/sessions/ssh/launch', { request_id: requestId, asset_id: assetId })
      .then(r => r.data),

  /** Admin terminations also revoke the bound grant. HTTP 207 means the teardown was incomplete: check `complete`. */
  terminate: (id: string, reason?: string) =>
    apiClient.post(`/sessions/${id}/terminate`, reason ? { reason } : undefined).then(r => r.data),
};

// --- JIT grants (terminate + revoke ends access entirely) ---

export const jitGrantsApi = {
  /** Admin-only. Ends live sessions bound to the grant; idempotent. */
  revoke: (grantId: string) =>
    apiClient.post<GrantRevokeResult>(`/jit-grants/${grantId}/revoke`).then(r => r.data),
};

// --- Recordings (evidence; AUDITOR and ADMIN only, enforced server-side) ---

export const recordingsApi = {
  list: (params?: ListParams) =>
    apiClient.get<PaginatedResponse<Recording>>('/recordings/', { params }).then(r => r.data),

  /** Raw asciicast text; the server re-verifies the SHA-256 before serving. */
  terminalCast: (id: string) =>
    apiClient
      .get<string>(`/recordings/${id}/stream`, { responseType: 'text', transformResponse: r => r })
      .then(r => r.data),

  /** RDP screen recording (Guacamole format); the server re-verifies the SHA-256 before serving. */
  guacamoleRecording: (id: string) =>
    apiClient.get<Blob>(`/recordings/${id}/stream`, { responseType: 'blob' }).then(r => r.data),

  /** Activity transcript (audited server-side). `available: false` carries the reason. */
  transcript: (id: string) =>
    apiClient.get<TranscriptResponse>(`/recordings/${id}/transcript`).then(r => r.data),

  /** Audited export; needs recordings:download. Returns the JSON text. */
  exportTranscript: (id: string) =>
    apiClient
      .get<string>(`/recordings/${id}/transcript/export`, { responseType: 'text', transformResponse: r => r })
      .then(r => r.data),
};

// --- Users & roles (users:read to view, users:update to change; enforced server-side) ---

export const usersApi = {
  list: (params?: Record<string, unknown>) =>
    apiClient.get<PaginatedResponse<AdminUser>>('/users', { params }).then(r => r.data),
  get: (id: string) => apiClient.get<AdminUserDetail>(`/users/${id}`).then(r => r.data),
  deactivate: (id: string) => apiClient.post<AdminUser>(`/users/${id}/deactivate`).then(r => r.data),
  reactivate: (id: string) => apiClient.post<AdminUser>(`/users/${id}/reactivate`).then(r => r.data),
  assignRole: (id: string, roleId: string) =>
    apiClient.post<AdminUser>(`/users/${id}/roles`, { role_id: roleId }).then(r => r.data),
  /** ADMIN: a user's sessions and, separately, approved grants that are not in use. */
  access: (id: string) => apiClient.get<UserAccess>(`/users/${id}/sessions`).then(r => r.data),
  terminateAll: (id: string, reason?: string) =>
    apiClient
      .post<TerminateAllResult>(`/users/${id}/sessions/terminate-all`, reason ? { reason } : undefined)
      .then(r => r.data),
  removeRole: (id: string, roleId: string) =>
    apiClient.delete<AdminUser>(`/users/${id}/roles/${roleId}`).then(r => r.data),
  create: (body: UserCreateInput) => apiClient.post<AdminUser>('/users', body).then(r => r.data),
  update: (id: string, body: UserUpdateInput) => apiClient.patch<AdminUser>(`/users/${id}`, body).then(r => r.data),
};

export const rolesApi = {
  list: () => apiClient.get<AdminRole[]>('/roles').then(r => r.data),
};

// --- Settings ---

export const sessionPolicyApi = {
  get: () => apiClient.get<SessionPolicy>('/settings/session-policy').then(r => r.data),
  update: (max: number) =>
    apiClient.put<SessionPolicy>('/settings/session-policy', { max_concurrent_sessions: max }).then(r => r.data),
};

export const settingsApi = {
  summary: () => apiClient.get<SystemSettings>('/settings/summary').then(r => r.data),
};

export const healthApi = {
  detailed: () =>
    apiClient.get<DetailedHealth>('/health/detailed', { baseURL: import.meta.env.VITE_API_URL || '' }).then(r => r.data),
};

// --- Integrated asset credential provisioning (ADMIN) ---

export const credentialProvisioningApi = {
  status: () => apiClient.get<ProvisioningStatus>('/credential-provisioning/status').then(r => r.data),
  createAsset: (body: { asset: AssetInput; credential: CredentialInput }) =>
    apiClient.post<ProvisionedCredential>('/credential-provisioning/assets', body).then(r => r.data),
  setCredential: (assetId: string, credential: CredentialInput) =>
    apiClient.put<ProvisionedCredential>(`/assets/${assetId}/credential`, credential).then(r => r.data),
};

// --- Risk Centre ---

export const riskApi = {
  summary: (days = 30) => apiClient.get<RiskSummary>('/risk/summary', { params: { days } }).then(r => r.data),
  findings: (params?: Record<string, unknown>) =>
    apiClient.get<PaginatedResponse<RiskFinding>>('/risk/findings', { params }).then(r => r.data),
  finding: (id: string) => apiClient.get<RiskFindingDetail>(`/risk/findings/${id}`).then(r => r.data),
  setStatus: (id: string, status: RiskFinding['status'], note?: string) =>
    apiClient.patch<RiskFinding>(`/risk/findings/${id}`, { status, note }).then(r => r.data),
  evaluate: () => apiClient.post<Record<string, number>>('/risk/evaluate').then(r => r.data),
  setThresholds: (t: { mfa_failure_threshold: number; launch_denial_threshold: number }) =>
    apiClient.put('/risk/thresholds', t).then(r => r.data),
};
