/**
 * Sample data for the static portfolio demo (VITE build with vite.demo.config.ts).
 * Everything here is fictional and lives only in the visitor's browser tab.
 */

import type {
  AccessRequest, AdminRole, AdminUser, Application, Approval, Asset, AuditLog, CredentialRef,
  Policy, Recording, RiskFinding, Session,
} from '@/types';

const now = Date.now();
export const ago = (minutes: number) => new Date(now - minutes * 60_000).toISOString();
export const ahead = (minutes: number) => new Date(now + minutes * 60_000).toISOString();

export const newId = () => crypto.randomUUID();

// --- Roles & permissions (mirrors the backend's seed) ---

const ALL_PERMISSIONS = [
  'users:read', 'users:create', 'users:update', 'users:delete',
  'assets:read', 'assets:create', 'assets:update', 'assets:delete',
  'applications:read', 'applications:create', 'applications:update', 'applications:delete',
  'access_requests:read', 'access_requests:create', 'access_requests:read_own',
  'approvals:read', 'approvals:approve', 'approvals:reject',
  'sessions:read', 'sessions:read_own', 'sessions:create', 'sessions:terminate',
  'recordings:read', 'recordings:download', 'recordings:delete',
  'audit:read', 'audit:export',
  'policies:read', 'policies:create', 'policies:update', 'policies:delete',
  'vault:read', 'vault:manage', 'risk:read', 'risk:manage', 'dashboard:read',
  'settings:read', 'settings:update',
];

export const ROLE_PERMISSIONS: Record<string, string[]> = {
  ADMIN: ALL_PERMISSIONS,
  OPERATOR: ['assets:read', 'applications:read', 'access_requests:create', 'access_requests:read_own',
    'sessions:read_own', 'sessions:create', 'dashboard:read'],
  APPROVER: ['assets:read', 'applications:read', 'policies:read', 'access_requests:read', 'approvals:read',
    'approvals:approve', 'approvals:reject', 'risk:read', 'dashboard:read'],
  AUDITOR: ['audit:read', 'audit:export', 'recordings:read', 'sessions:read', 'access_requests:read', 'risk:read',
    'dashboard:read', 'assets:read', 'applications:read', 'policies:read', 'approvals:read'],
};

const ROLE_DESCRIPTIONS: Record<string, string> = {
  ADMIN: 'Full system administrator with all privileges',
  OPERATOR: 'Standard operator who can request and use privileged access',
  APPROVER: 'Can review and approve/reject access requests',
  AUDITOR: 'Can view audit logs, recordings, and generate reports',
};

export const roleIds: Record<string, string> = {
  ADMIN: 'role-admin', OPERATOR: 'role-operator', APPROVER: 'role-approver', AUDITOR: 'role-auditor',
};

// --- Users (demo sign-in: password is "demo" for every account) ---

export const DEMO_PASSWORD = 'demo';

const user = (id: string, username: string, full_name: string, role: string, mfa: boolean): AdminUser => ({
  id, username, full_name, email: `${username}@securepam.demo`, is_active: true, is_system_user: false,
  mfa_enabled: mfa, external_id: null, identity_source: 'LOCAL', roles: [{ id: roleIds[role], name: role }],
  last_login: ago(30), created_at: ago(60 * 24 * 20), active_sessions: 0,
});

export const users: AdminUser[] = [
  user('user-admin', 'admin', 'Asha Admin', 'ADMIN', true),
  user('user-operator', 'operator', 'Omar Operator', 'OPERATOR', true),
  user('user-approver', 'approver', 'Priya Approver', 'APPROVER', true),
  user('user-auditor', 'auditor', 'Arjun Auditor', 'AUDITOR', false),
  user('user-ravi', 'ravi.ops', 'Ravi Kumar', 'OPERATOR', true),
];

export const roles = (): AdminRole[] =>
  Object.keys(ROLE_PERMISSIONS).map((name) => ({
    id: roleIds[name], name, description: ROLE_DESCRIPTIONS[name], is_system: true, is_active: true,
    permissions: ROLE_PERMISSIONS[name].map((p) => ({ name: p, description: null })),
    users: users.filter((u) => u.roles.some((r) => r.name === name))
      .map((u) => ({ id: u.id, username: u.username, is_active: u.is_active })),
  }));

// --- Policies ---

const policy = (p: Partial<Policy> & Pick<Policy, 'id' | 'name'>): Policy => ({
  enabled: true, allowed_roles: null, allowed_asset_types: null, allowed_environments: null,
  allowed_protocols: null, allowed_days: null, business_hours_only: false, risk_threshold: 'HIGH',
  min_risk_score: 0, require_approval: false, jit_required: true, require_mfa: false, require_recording: true,
  max_session_duration: 120, download_allowed: false, upload_allowed: false, clipboard_allowed: false,
  auto_approve: false, deny_access: false, created_at: ago(60 * 24 * 14), updated_at: ago(60 * 24 * 3), ...p,
});

export const policies: Policy[] = [
  policy({ id: 'pol-prod-linux', name: 'Production Linux Access',
    description: 'Operators may SSH to production Linux servers with approval, MFA and recording.',
    allowed_roles: ['OPERATOR', 'ADMIN'], allowed_asset_types: ['LINUX_SERVER'], allowed_environments: ['PRODUCTION'],
    allowed_protocols: ['SSH'], require_approval: true, require_mfa: true, max_session_duration: 60 }),
  policy({ id: 'pol-windows', name: 'Windows Server Administration',
    description: 'RDP to Windows servers during business hours; clipboard and file transfer blocked.',
    allowed_roles: ['OPERATOR', 'ADMIN'], allowed_asset_types: ['WINDOWS_SERVER', 'WINDOWS_WORKSTATION'],
    allowed_protocols: ['RDP'], allowed_days: ['MON', 'TUE', 'WED', 'THU', 'FRI'], business_hours_only: true,
    require_approval: true, max_session_duration: 90 }),
  policy({ id: 'pol-dev', name: 'Development Self-Service',
    description: 'Low-risk development targets are auto-approved for a short JIT window.',
    allowed_environments: ['DEVELOPMENT', 'TESTING'], auto_approve: true, risk_threshold: 'MEDIUM',
    max_session_duration: 240 }),
  policy({ id: 'pol-web', name: 'Internal Web Apps (Isolated Browser)',
    description: 'Sensitive internal apps open only in a disposable isolated browser.',
    allowed_protocols: ['HTTPS', 'HTTP'], require_approval: true, max_session_duration: 60 }),
  policy({ id: 'pol-network', name: 'Network Devices — Deny', enabled: true,
    description: 'Direct access to core network devices is denied; use the change-management process.',
    allowed_asset_types: ['NETWORK_DEVICE'], deny_access: true }),
];

// --- Assets ---

const asset = (a: Partial<Asset> & Pick<Asset, 'id' | 'name' | 'hostname' | 'ip_address' | 'protocol' | 'asset_type'>): Asset => ({
  port: a.protocol === 'RDP' ? 3389 : 22, environment: 'PRODUCTION', criticality: 'HIGH', status: 'ACTIVE',
  enabled: true, owner: 'Platform Team', recording_required: true, approval_required: true, jit_required: true,
  created_at: ago(60 * 24 * 12), updated_at: ago(60 * 24 * 2), created_by: 'admin', ...a,
});

export const assets: Asset[] = [
  asset({ id: 'asset-db', name: 'prod-db-01', hostname: 'prod-db-01.corp.demo', ip_address: '10.20.1.15',
    protocol: 'SSH', asset_type: 'LINUX_SERVER', criticality: 'CRITICAL', policy_id: 'pol-prod-linux',
    description: 'Primary PostgreSQL cluster node' }),
  asset({ id: 'asset-web', name: 'prod-web-02', hostname: 'prod-web-02.corp.demo', ip_address: '10.20.2.22',
    protocol: 'SSH', asset_type: 'LINUX_SERVER', policy_id: 'pol-prod-linux', description: 'Public web tier' }),
  asset({ id: 'asset-dc', name: 'win-dc-01', hostname: 'win-dc-01.corp.demo', ip_address: '10.20.5.10',
    protocol: 'RDP', asset_type: 'WINDOWS_SERVER', criticality: 'CRITICAL', policy_id: 'pol-windows',
    description: 'Active Directory domain controller' }),
  asset({ id: 'asset-win', name: 'win11-lab', hostname: 'win11-lab.corp.demo', ip_address: '10.30.5.40',
    protocol: 'RDP', asset_type: 'WINDOWS_WORKSTATION', environment: 'TESTING', criticality: 'LOW',
    approval_required: false, policy_id: 'pol-dev', description: 'Windows 11 test workstation' }),
  asset({ id: 'asset-kali', name: 'kali-dev', hostname: 'kali-dev.corp.demo', ip_address: '10.30.1.50',
    protocol: 'SSH', asset_type: 'LINUX_SERVER', environment: 'DEVELOPMENT', criticality: 'LOW',
    approval_required: false, policy_id: 'pol-dev', description: 'Security tooling sandbox' }),
  asset({ id: 'asset-fw', name: 'core-fw-01', hostname: 'core-fw-01.corp.demo', ip_address: '10.0.0.1',
    protocol: 'SSH', asset_type: 'NETWORK_DEVICE', criticality: 'CRITICAL', policy_id: 'pol-network',
    description: 'Core perimeter firewall' }),
];

// --- Applications ---

const app = (a: Partial<Application> & Pick<Application, 'id' | 'name' | 'hostname'>): Application => ({
  protocol: 'HTTPS', port: 443, target_url: `https://${a.hostname}/`, environment: 'PRODUCTION', criticality: 'HIGH',
  access_mode: 'ISOLATED_BROWSER', enabled: true, approval_required: true, mfa_required: true,
  recording_required: true, download_allowed: false, upload_allowed: false, clipboard_allowed: false,
  session_timeout: 30, policy_id: 'pol-web', status: 'ACTIVE', created_at: ago(60 * 24 * 10),
  updated_at: ago(60 * 24 * 1), created_by: 'admin', ...a,
});

export const applications: Application[] = [
  app({ id: 'app-hr', name: 'HR Portal', hostname: 'hr.corp.demo', description: 'Employee records and payroll' }),
  app({ id: 'app-grafana', name: 'Grafana', hostname: 'grafana.corp.demo', port: 3000, criticality: 'MEDIUM',
    target_url: 'https://grafana.corp.demo:3000/', description: 'Infrastructure dashboards' }),
  app({ id: 'app-jenkins', name: 'Jenkins CI', hostname: 'ci.corp.demo', environment: 'STAGING',
    criticality: 'MEDIUM', description: 'Build and deployment pipelines' }),
];

// --- Credential references (pointers only — no secrets exist in the demo) ---

export const credentialRefs: CredentialRef[] = ['asset-db', 'asset-web', 'asset-dc', 'asset-kali', 'asset-win'].map((assetId) => {
  const a = assets.find((x) => x.id === assetId)!;
  return {
    id: `cref-${assetId}`, asset_id: assetId, provider: 'openbao', vault_path: `secret/securepam/assets/${a.name}`,
    secret_type: a.protocol === 'SSH' ? 'SSH_KEY' : 'PASSWORD', username: a.protocol === 'SSH' ? 'pamsvc' : 'CORP\\pamsvc',
    secret_version: 3, is_active: true, last_rotated: ago(60 * 24 * 5), created_at: ago(60 * 24 * 12), updated_at: ago(60 * 24 * 5),
  };
});

// --- Access requests, approvals, sessions ---

const request = (r: Partial<AccessRequest> & Pick<AccessRequest, 'id' | 'request_number' | 'user_id' | 'protocol' | 'reason' | 'status'>): AccessRequest => ({
  requested_duration: 60, approval_required: true, jit_required: true, mfa_required: true, recording_required: true,
  created_at: ago(120), updated_at: ago(110), ...r,
});

export const accessRequests: AccessRequest[] = [
  request({ id: 'req-1', request_number: 'REQ-2026-0041', user_id: 'user-operator', asset_id: 'asset-db', protocol: 'SSH',
    reason: 'INC-4821: investigate slow queries on the orders table', status: 'APPROVAL_REQUIRED', policy_id: 'pol-prod-linux',
    risk_score: 65, risk_level: 'HIGH', created_at: ago(18), updated_at: ago(18),
    risk_factors: [
      { code: 'PRODUCTION_ASSET', points: 30, reason: 'Target is in the PRODUCTION environment' },
      { code: 'CRITICAL_ASSET', points: 25, reason: 'Target criticality is CRITICAL' },
      { code: 'LONG_DURATION', points: 10, reason: 'Requested 90 minutes (> 60)' },
    ],
    requested_duration: 90,
    policy_decision: { allowed: true, policy_id: 'pol-prod-linux', policy_name: 'Production Linux Access', approval_required: true,
      mfa_required: true, jit_required: true, recording_required: true, max_duration: 60, auto_approve: false,
      reasons: ['Role OPERATOR is allowed', 'Asset type LINUX_SERVER is allowed', 'Policy requires approval'] } }),
  request({ id: 'req-2', request_number: 'REQ-2026-0040', user_id: 'user-ravi', asset_id: 'asset-dc', protocol: 'RDP',
    reason: 'CHG-1180: apply group policy update', status: 'APPROVAL_REQUIRED', policy_id: 'pol-windows',
    risk_score: 55, risk_level: 'MEDIUM', created_at: ago(45), updated_at: ago(45),
    risk_factors: [
      { code: 'PRODUCTION_ASSET', points: 30, reason: 'Target is in the PRODUCTION environment' },
      { code: 'CRITICAL_ASSET', points: 25, reason: 'Target criticality is CRITICAL' },
    ],
    policy_decision: { allowed: true, policy_id: 'pol-windows', policy_name: 'Windows Server Administration', approval_required: true,
      mfa_required: false, jit_required: true, recording_required: true, max_duration: 90, auto_approve: false,
      reasons: ['Role OPERATOR is allowed', 'Policy requires approval'] } }),
  request({ id: 'req-3', request_number: 'REQ-2026-0039', user_id: 'user-operator', asset_id: 'asset-kali', protocol: 'SSH',
    reason: 'Run nightly vulnerability scan', status: 'ACTIVE', policy_id: 'pol-dev', approval_required: false, mfa_required: false,
    risk_score: 0, risk_level: 'LOW', risk_factors: [], created_at: ago(25), updated_at: ago(24), decided_at: ago(24),
    expires_at: ahead(35),
    policy_decision: { allowed: true, policy_id: 'pol-dev', policy_name: 'Development Self-Service', approval_required: false,
      mfa_required: false, jit_required: true, recording_required: true, max_duration: 240, auto_approve: true,
      reasons: ['Environment DEVELOPMENT is allowed', 'Policy auto-approves'] },
    jit_grant: { id: 'grant-3', protocol: 'SSH', status: 'ACTIVE', granted_at: ago(24), expires_at: ahead(35) } }),
  request({ id: 'req-4', request_number: 'REQ-2026-0038', user_id: 'user-operator', asset_id: 'asset-web', protocol: 'SSH',
    reason: 'Rotate TLS certificate on web tier', status: 'EXPIRED', policy_id: 'pol-prod-linux', risk_score: 30,
    risk_level: 'MEDIUM', created_at: ago(60 * 26), updated_at: ago(60 * 24), decided_at: ago(60 * 25.5), decided_by: 'user-approver',
    risk_factors: [{ code: 'PRODUCTION_ASSET', points: 30, reason: 'Target is in the PRODUCTION environment' }],
    jit_grant: { id: 'grant-4', protocol: 'SSH', status: 'EXPIRED', granted_at: ago(60 * 25.5), expires_at: ago(60 * 24.5) } }),
  request({ id: 'req-5', request_number: 'REQ-2026-0037', user_id: 'user-ravi', asset_id: 'asset-fw', protocol: 'SSH',
    reason: 'Check firewall rule hits', status: 'DENIED', policy_id: 'pol-network', risk_score: 75, risk_level: 'HIGH',
    created_at: ago(60 * 30), updated_at: ago(60 * 30), decided_at: ago(60 * 30),
    risk_factors: [
      { code: 'PRODUCTION_ASSET', points: 30, reason: 'Target is in the PRODUCTION environment' },
      { code: 'CRITICAL_ASSET', points: 25, reason: 'Target criticality is CRITICAL' },
      { code: 'OUTSIDE_BUSINESS_HOURS', points: 20, reason: 'Requested outside business hours' },
    ],
    policy_decision: { allowed: false, policy_id: 'pol-network', policy_name: 'Network Devices — Deny', approval_required: false,
      mfa_required: false, jit_required: true, recording_required: true, max_duration: 0, auto_approve: false,
      reasons: ['Policy denies access to NETWORK_DEVICE targets'] } }),
  request({ id: 'req-6', request_number: 'REQ-2026-0036', user_id: 'user-operator', application_id: 'app-hr', protocol: 'HTTPS',
    reason: 'Verify payroll export for audit', status: 'REJECTED', policy_id: 'pol-web', risk_score: 50, risk_level: 'MEDIUM',
    created_at: ago(60 * 50), updated_at: ago(60 * 49), decided_at: ago(60 * 49), decided_by: 'user-approver',
    risk_factors: [
      { code: 'PRODUCTION_ASSET', points: 30, reason: 'Target is in the PRODUCTION environment' },
      { code: 'SENSITIVE_APPLICATION', points: 20, reason: 'Application handles sensitive data' },
    ] }),
];

export const approvals: Approval[] = [
  { id: 'appr-1', request_id: 'req-1', status: 'PENDING', created_at: ago(18) },
  { id: 'appr-2', request_id: 'req-2', status: 'PENDING', created_at: ago(45) },
  { id: 'appr-4', request_id: 'req-4', approver_id: 'user-approver', status: 'APPROVED', comment: 'Approved for change window',
    decided_at: ago(60 * 25.5), created_at: ago(60 * 26) },
  { id: 'appr-6', request_id: 'req-6', approver_id: 'user-approver', status: 'REJECTED',
    comment: 'Use the read-only report instead', decided_at: ago(60 * 49), created_at: ago(60 * 50) },
];

export const sessions: Session[] = [
  { id: 'sess-1', session_number: 'SES-2026-0112', user_id: 'user-operator', user_name: 'operator', asset_id: 'asset-kali',
    asset_name: 'kali-dev', protocol: 'SSH', status: 'ACTIVE', start_time: ago(22), source_ip: '192.168.1.24', risk_score: 0,
    request_id: 'req-3', jit_grant_id: 'grant-3', recording_id: 'rec-live', recording_status: 'RECORDING', created_at: ago(22) },
  { id: 'sess-2', session_number: 'SES-2026-0108', user_id: 'user-operator', user_name: 'operator', asset_id: 'asset-web',
    asset_name: 'prod-web-02', protocol: 'SSH', status: 'COMPLETED', start_time: ago(60 * 25.4), end_time: ago(60 * 25),
    source_ip: '192.168.1.24', risk_score: 30, request_id: 'req-4', jit_grant_id: 'grant-4', recording_id: 'rec-1',
    recording_status: 'COMPLETED', created_at: ago(60 * 25.4) },
  { id: 'sess-3', session_number: 'SES-2026-0101', user_id: 'user-ravi', user_name: 'ravi.ops', asset_id: 'asset-win',
    asset_name: 'win11-lab', protocol: 'RDP', status: 'TERMINATED', start_time: ago(60 * 48), end_time: ago(60 * 47.5),
    source_ip: '192.168.1.31', risk_score: 0, request_id: 'req-old', recording_id: 'rec-2', recording_status: 'COMPLETED',
    created_at: ago(60 * 48) },
  { id: 'sess-4', session_number: 'SES-2026-0097', user_id: 'user-operator', user_name: 'operator', asset_id: 'asset-db',
    asset_name: 'prod-db-01', protocol: 'SSH', status: 'FAILED', source_ip: '192.168.1.24', risk_score: 55, request_id: 'req-old2',
    failure_reason: 'HOST_KEY_MISMATCH', failure_message: 'The server host key does not match the pinned key; session refused.',
    created_at: ago(60 * 72) },
];

// --- Recordings (terminal casts play back in the browser) ---

export const recordings: Recording[] = [
  { id: 'rec-1', session_id: 'sess-2', recording_type: 'TERMINAL', status: 'COMPLETED', file_size: 18_432, duration_seconds: 12,
    created_at: ago(60 * 25.4), session_number: 'SES-2026-0108', operator_username: 'operator', asset_name: 'prod-web-02',
    protocol: 'SSH', started_at: ago(60 * 25.4), ended_at: ago(60 * 25), integrity: 'verified', transcript_available: true,
    format: 'asciicast', sha256: '9f2c4e1b7a6d3f8e0c5b2a19d7e4f6a3b8c1d0e9f2a5b7c4d6e8f0a1b3c5d7e9', retention_date: ahead(60 * 24 * 85) },
  { id: 'rec-2', session_id: 'sess-3', recording_type: 'VIDEO', status: 'COMPLETED', file_size: 4_812_330, duration_seconds: 1_740,
    created_at: ago(60 * 48), session_number: 'SES-2026-0101', operator_username: 'ravi.ops', asset_name: 'win11-lab',
    protocol: 'RDP', started_at: ago(60 * 48), ended_at: ago(60 * 47.5), integrity: 'not_available', transcript_available: false,
    format: 'guacamole', sha256: null, retention_date: ahead(60 * 24 * 60) },
];

const castLines: [number, string, string][] = [];
let t = 0.4;
const type = (text: string) => { for (const ch of text) { castLines.push([+(t += 0.07).toFixed(2), 'o', ch]); } };
const out = (text: string, pause = 0.4) => castLines.push([+(t += pause).toFixed(2), 'o', text]);
out('\x1b[1;32mpamsvc@prod-web-02\x1b[0m:\x1b[1;34m~\x1b[0m$ ', 0.2);
type('uptime'); out('\r\n 10:42:07 up 41 days,  3:12,  1 user,  load average: 0.21, 0.18, 0.15\r\n');
out('\x1b[1;32mpamsvc@prod-web-02\x1b[0m:\x1b[1;34m~\x1b[0m$ ', 0.6);
type('sudo certbot renew --nginx'); out('\r\nCongratulations, all renewals succeeded:\r\n  /etc/letsencrypt/live/www.corp.demo/fullchain.pem (success)\r\n', 1.6);
out('\x1b[1;32mpamsvc@prod-web-02\x1b[0m:\x1b[1;34m~\x1b[0m$ ', 0.6);
type('sudo systemctl reload nginx && systemctl is-active nginx'); out('\r\nactive\r\n', 1.0);
out('\x1b[1;32mpamsvc@prod-web-02\x1b[0m:\x1b[1;34m~\x1b[0m$ ', 0.6);
type('exit'); out('\r\nlogout\r\n', 0.5);

export const demoCast = [
  JSON.stringify({ version: 2, width: 100, height: 24, title: 'SES-2026-0108 prod-web-02' }),
  ...castLines.map((e) => JSON.stringify(e)),
].join('\n');

export const demoTranscriptEvents = [
  ['uptime', ' 10:42:07 up 41 days,  3:12,  1 user,  load average: 0.21, 0.18, 0.15'],
  ['sudo certbot renew --nginx', 'Congratulations, all renewals succeeded'],
  ['sudo systemctl reload nginx && systemctl is-active nginx', 'active'],
  ['exit', 'logout'],
].map(([input, output], i) => ({
  seq: i + 1, t: [1, 3.5, 7.5, 12][i], input, output, output_truncated: false, masked: false, redacted: false,
  edited: false, confidence: 'high' as const, source: 'terminal', execution_verified: false,
}));

// --- Audit trail ---

const audit = (minutesAgo: number, actor: string, action: string, result: AuditLog['result'], severity: AuditLog['severity'],
  target_type?: string, details?: Record<string, unknown>): AuditLog => ({
  id: newId(), event_id: newId(), timestamp: ago(minutesAgo), actor_username: actor, action, result, severity,
  target_type, source_ip: '192.168.1.24', details,
});

export const auditLogs: AuditLog[] = [
  audit(2, 'auditor', 'RECORDING_VIEWED', 'SUCCESS', 'INFO', 'recording', { recording: 'SES-2026-0108' }),
  audit(18, 'operator', 'ACCESS_REQUEST_CREATED', 'SUCCESS', 'MEDIUM', 'access_request', { request: 'REQ-2026-0041', risk_score: 65 }),
  audit(22, 'operator', 'SESSION_STARTED', 'SUCCESS', 'INFO', 'session', { session: 'SES-2026-0112', asset: 'kali-dev' }),
  audit(22, 'system', 'CREDENTIAL_RETRIEVED', 'SUCCESS', 'INFO', 'credential', { asset: 'kali-dev', provider: 'openbao' }),
  audit(24, 'system', 'JIT_GRANT_CREATED', 'SUCCESS', 'INFO', 'jit_grant', { request: 'REQ-2026-0039', minutes: 60 }),
  audit(45, 'ravi.ops', 'ACCESS_REQUEST_CREATED', 'SUCCESS', 'MEDIUM', 'access_request', { request: 'REQ-2026-0040' }),
  audit(95, 'ravi.ops', 'MFA_FAILURE', 'FAILURE', 'HIGH', 'user', { reason: 'invalid TOTP code' }),
  audit(97, 'ravi.ops', 'MFA_FAILURE', 'FAILURE', 'HIGH', 'user', { reason: 'invalid TOTP code' }),
  audit(99, 'ravi.ops', 'MFA_FAILURE', 'FAILURE', 'HIGH', 'user', { reason: 'invalid TOTP code' }),
  audit(60 * 24, 'system', 'JIT_GRANT_EXPIRED', 'SUCCESS', 'INFO', 'jit_grant', { request: 'REQ-2026-0038' }),
  audit(60 * 25, 'operator', 'SESSION_ENDED', 'SUCCESS', 'INFO', 'session', { session: 'SES-2026-0108' }),
  audit(60 * 25.5, 'approver', 'ACCESS_APPROVED', 'SUCCESS', 'MEDIUM', 'approval', { request: 'REQ-2026-0038' }),
  audit(60 * 30, 'ravi.ops', 'ACCESS_DENIED', 'DENIED', 'HIGH', 'access_request', { request: 'REQ-2026-0037', policy: 'Network Devices — Deny' }),
  audit(60 * 47.5, 'admin', 'SESSION_TERMINATED', 'SUCCESS', 'HIGH', 'session', { session: 'SES-2026-0101', reason: 'Suspicious clipboard use' }),
  audit(60 * 72, 'system', 'SSH_HOST_KEY_MISMATCH', 'FAILURE', 'CRITICAL', 'asset', { asset: 'prod-db-01' }),
];

// --- Risk Centre findings ---

const finding = (f: Partial<RiskFinding> & Pick<RiskFinding, 'id' | 'rule_code' | 'title' | 'severity' | 'subject'>): RiskFinding => ({
  source: 'SECUREPAM', description: '', status: 'OPEN', asset_id: null, application_id: null, user_id: null, session_id: null,
  evidence: {}, remediation: '', first_seen: ago(100), last_seen: ago(95), occurrences: 1, status_changed_at: null,
  status_note: null, ...f,
});

export const riskFindings: RiskFinding[] = [
  finding({ id: 'find-1', rule_code: 'MFA_FAILURE_BURST', source: 'KEYCLOAK', title: 'Repeated MFA failures for ravi.ops',
    severity: 'HIGH', subject: 'ravi.ops', user_id: 'user-ravi', occurrences: 3, evidence: { count: 3 },
    description: '3 failed TOTP attempts within 5 minutes.', remediation: 'Confirm with the user; reset the OTP device if it was not them.' }),
  finding({ id: 'find-2', rule_code: 'HOST_KEY_MISMATCH', source: 'SSH_GATEWAY', title: 'SSH host key mismatch on prod-db-01',
    severity: 'CRITICAL', subject: 'prod-db-01', asset_id: 'asset-db', session_id: 'sess-4', first_seen: ago(60 * 72),
    last_seen: ago(60 * 72), description: 'The server presented a different host key than the pinned one. The session was refused.',
    remediation: 'Verify the server out of band before re-pinning its key.' }),
  finding({ id: 'find-3', rule_code: 'HIGH_RISK_ACCESS', title: 'High-risk request to a critical production asset',
    severity: 'MEDIUM', subject: 'REQ-2026-0041', asset_id: 'asset-db', user_id: 'user-operator', first_seen: ago(18),
    last_seen: ago(18), description: 'Risk score 65 (HIGH) for SSH to prod-db-01.', remediation: 'Approver review required.' }),
  finding({ id: 'find-4', rule_code: 'EGRESS_BLOCKED', source: 'BROWSER_ISOLATION', title: 'Isolated browser blocked an off-target request',
    severity: 'LOW', subject: 'HR Portal', application_id: 'app-hr', status: 'RESOLVED', first_seen: ago(60 * 50),
    last_seen: ago(60 * 50), status_changed_at: ago(60 * 40), status_note: 'Expected third-party analytics call.',
    description: 'The egress proxy refused a connection to an unregistered host.', remediation: 'None needed if expected.' }),
];
