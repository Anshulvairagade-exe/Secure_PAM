/**
 * SecurePAM TypeScript Type Definitions.
 *
 * Shared types for API responses, entities, and UI state.
 */

// --- Auth ---
export interface UserInfo {
  id: string;
  username: string;
  email: string;
  full_name: string;
  roles: string[];
  permissions: string[];
  mfa_enabled: boolean;
  is_active: boolean;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface AuthConfig {
  dev_mode: boolean;
  auth_url?: string;
  client_id?: string;
  realm?: string;
}

// --- Dashboard ---
export interface DashboardSummary {
  active_sessions: number;
  pending_requests: number;
  high_risk_sessions: number;
  today_sessions: number;
  failed_mfa_attempts: number;
  jit_grants_active: number;
  registered_assets: number;
  recording_storage_mb: number;
}

export interface DashboardActivity {
  event_id: string;
  timestamp: string;
  severity: Severity;
  action: string;
  actor: string;
  target?: string;
  details?: string;
}

// --- Assets ---
export type AssetType =
  | 'WINDOWS_SERVER'
  | 'WINDOWS_WORKSTATION'
  | 'LINUX_SERVER'
  | 'UNIX_SERVER'
  | 'NETWORK_DEVICE'
  | 'OTHER';

export interface Asset {
  id: string;
  name: string;
  hostname: string;
  ip_address: string;
  port: number;
  protocol: 'RDP' | 'SSH' | 'HTTPS' | 'HTTP';
  asset_type: AssetType;
  environment: Environment;
  criticality: Criticality;
  description?: string;
  status: EntityStatus;
  enabled: boolean;
  owner?: string;
  recording_required: boolean;
  approval_required: boolean;
  jit_required: boolean;
  policy_id?: string;
  created_at: string;
  updated_at: string;
  created_by?: string;
  updated_by?: string;
}

export type AssetInput = Omit<Asset, 'id' | 'status' | 'created_at' | 'updated_at' | 'created_by' | 'updated_by'>;

// --- Applications ---
export type AccessMode = 'STANDARD_PROXY' | 'ISOLATED_BROWSER';

export interface Application {
  id: string;
  name: string;
  description?: string;
  target_url: string; // Always server-derived — never sent by the client
  protocol: 'HTTP' | 'HTTPS';
  hostname: string;
  port: number;
  environment: Environment;
  criticality: Criticality;
  access_mode: AccessMode;
  enabled: boolean;
  approval_required: boolean;
  mfa_required: boolean;
  recording_required: boolean;
  download_allowed: boolean;
  upload_allowed: boolean;
  clipboard_allowed: boolean;
  session_timeout: number;
  policy_id?: string;
  status: EntityStatus;
  created_at: string;
  updated_at: string;
  created_by?: string;
  updated_by?: string;
}

export type ApplicationInput = Omit<
  Application,
  'id' | 'target_url' | 'status' | 'created_at' | 'updated_at' | 'created_by' | 'updated_by'
>;

// --- Access Requests ---
export interface AccessRequest {
  id: string;
  request_number: string;
  user_id: string;
  asset_id?: string;
  application_id?: string;
  protocol: string;
  reason: string;
  requested_duration: number;
  status: RequestStatus;
  risk_score?: number;
  risk_level?: RiskLevel;
  risk_factors?: RiskFactor[];
  source_ip?: string;
  created_at: string;
  updated_at: string;
  // Joined fields
  asset_name?: string;
  application_name?: string;
  user_name?: string;
}

export interface RiskFactor {
  factor: string;
  score: number;
  description?: string;
}

export interface RiskEvaluation {
  risk_score: number;
  risk_level: RiskLevel;
  risk_factors: RiskFactor[];
}

// --- Approvals ---
export interface Approval {
  id: string;
  request_id: string;
  approver_id: string;
  decision: 'APPROVED' | 'REJECTED';
  comment?: string;
  decided_at: string;
  source_ip?: string;
}

// --- JIT Grants ---
export interface JITGrant {
  id: string;
  request_id: string;
  user_id: string;
  asset_id?: string;
  application_id?: string;
  granted_at: string;
  expires_at: string;
  revoked_at?: string;
  status: 'ACTIVE' | 'EXPIRED' | 'REVOKED';
}

// --- Sessions ---
export interface Session {
  id: string;
  session_number: string;
  user_id: string;
  asset_id?: string;
  application_id?: string;
  protocol: string;
  status: SessionStatus;
  start_time?: string;
  end_time?: string;
  source_ip?: string;
  risk_score?: number;
  request_id: string;
  jit_grant_id?: string;
  recording_id?: string;
  created_at: string;
  // Joined fields
  asset_name?: string;
  application_name?: string;
  user_name?: string;
}

// --- Recordings ---
export interface Recording {
  id: string;
  session_id: string;
  recording_type: 'VIDEO' | 'TERMINAL' | 'HTTP';
  status: 'PENDING' | 'RECORDING' | 'COMPLETED' | 'FAILED' | 'DELETED';
  file_size?: number;
  duration_seconds?: number;
  retention_date?: string;
  created_at: string;
}

// --- Audit ---
export interface AuditLog {
  id: string;
  event_id: string;
  timestamp: string;
  actor_id?: string;
  actor_username: string;
  action: string;
  target_type?: string;
  target_id?: string;
  session_id?: string;
  request_id?: string;
  source_ip?: string;
  result: 'SUCCESS' | 'FAILURE' | 'DENIED';
  severity: Severity;
  details?: Record<string, unknown>;
}

// --- Policies ---
export type RoleName = 'ADMIN' | 'OPERATOR' | 'APPROVER' | 'AUDITOR';
export type DayOfWeek = 'MON' | 'TUE' | 'WED' | 'THU' | 'FRI' | 'SAT' | 'SUN';

export interface Policy {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;

  allowed_roles?: RoleName[] | null;
  allowed_asset_types?: AssetType[] | null;
  allowed_environments?: Environment[] | null;
  allowed_protocols?: string[] | null;
  allowed_days?: DayOfWeek[] | null;
  business_hours_only: boolean;

  risk_threshold: RiskLevel;
  min_risk_score: number;

  require_approval: boolean;
  jit_required: boolean;
  require_mfa: boolean;
  require_recording: boolean;

  max_session_duration: number;
  download_allowed: boolean;
  upload_allowed: boolean;
  clipboard_allowed: boolean;

  auto_approve: boolean;
  deny_access: boolean;

  created_at: string;
  updated_at: string;
  created_by?: string;
  updated_by?: string;
}

export type PolicyInput = Omit<Policy, 'id' | 'created_at' | 'updated_at' | 'created_by' | 'updated_by'>;

// --- Health ---
export interface HealthCheck {
  status: string;
  version: string;
  environment: string;
  dev_mode: boolean;
}

export interface ServiceHealth {
  service: string;
  status: 'healthy' | 'unhealthy' | 'degraded';
  latency_ms?: number;
  details?: string;
}

export interface DetailedHealth {
  status: string;
  version: string;
  environment: string;
  dev_mode: boolean;
  services: ServiceHealth[];
}

// --- Enums ---
export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type Criticality = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type Environment = 'PRODUCTION' | 'STAGING' | 'DEVELOPMENT' | 'TESTING';
export type EntityStatus = 'ACTIVE' | 'INACTIVE' | 'MAINTENANCE';
export type RequestStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED' | 'CANCELLED' | 'ACTIVE' | 'COMPLETED';
export type SessionStatus = 'CREATED' | 'STARTING' | 'ACTIVE' | 'TERMINATING' | 'COMPLETED' | 'FAILED' | 'EXPIRED';

// --- Pagination ---
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}
