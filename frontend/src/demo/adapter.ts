/**
 * In-browser stand-in for the SecurePAM API, used only by the static portfolio demo.
 * It answers the same routes as backend/app/api/v1 from the sample data in ./data,
 * so the real pages render unchanged. State resets on every page load.
 */

import { AxiosError, type AxiosAdapter, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios';
import type { AccessRequest, AdminUser, RiskFactor, RiskLevel } from '@/types';
import * as db from './data';

const LIVE_SESSION_MESSAGE =
  'Live SSH, RDP and isolated-browser sessions need the full SecurePAM backend, vault and gateways. ' +
  'This static demo shows the control plane only — try a recording in Recordings to see a replayed session.';

type Handler = (ctx: { params: Record<string, unknown>; body: any; match: string[]; me: AdminUser | null }) => unknown;

// Persist demo changes for this browser tab, so switching users (which reloads the page) keeps them.
const STORAGE_KEY = 'securepam_demo_state';
const collections = {
  users: db.users, assets: db.assets, applications: db.applications, policies: db.policies,
  credentialRefs: db.credentialRefs, accessRequests: db.accessRequests, approvals: db.approvals,
  sessions: db.sessions, auditLogs: db.auditLogs, riskFindings: db.riskFindings,
} as Record<string, unknown[]>;

try {
  const saved = JSON.parse(window.sessionStorage.getItem(STORAGE_KEY) ?? 'null') as Record<string, unknown[]> | null;
  if (saved) Object.entries(collections).forEach(([key, items]) => { if (saved[key]) items.splice(0, items.length, ...saved[key]); });
} catch {
  // Start from the sample data.
}

function saveState() {
  try {
    window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(collections));
  } catch {
    // Storage unavailable: changes last until the next reload.
  }
}

class HttpError {
  constructor(public status: number, public detail: string) {}
}

const fail = (status: number, detail: string): never => { throw new HttpError(status, detail); };

function permissionsOf(u: AdminUser): string[] {
  return [...new Set(u.roles.flatMap((r) => db.ROLE_PERMISSIONS[r.name] ?? []))];
}

const can = (me: AdminUser | null, permission: string) =>
  !!me && (me.roles.some((r) => r.name === 'ADMIN') || permissionsOf(me).includes(permission));

function requireUser(me: AdminUser | null): AdminUser {
  return me ?? fail(401, 'Not authenticated');
}

function require(me: AdminUser | null, permission: string) {
  if (!can(requireUser(me), permission)) fail(403, 'You are not authorized to do that.');
}

const PAGING_KEYS = new Set(['page', 'page_size', 'sort_by', 'sort_order', 'days']);

function paginate<T extends object>(items: T[], params: Record<string, unknown>) {
  let rows = items.filter((item) =>
    Object.entries(params).every(([key, value]) => {
      if (PAGING_KEYS.has(key) || value === undefined || value === '') return true;
      if (key === 'search' || key === 'q') {
        return JSON.stringify(item).toLowerCase().includes(String(value).toLowerCase());
      }
      const field = (item as Record<string, unknown>)[key];
      return field === undefined || String(value).split(',').includes(String(field));
    }));
  const sortBy = params.sort_by as string | undefined;
  if (sortBy) {
    const dir = params.sort_order === 'asc' ? 1 : -1;
    rows = [...rows].sort((a, b) =>
      String((a as Record<string, unknown>)[sortBy] ?? '') > String((b as Record<string, unknown>)[sortBy] ?? '') ? dir : -dir);
  }
  const page = Number(params.page ?? 1);
  const pageSize = Number(params.page_size ?? 20);
  return {
    items: rows.slice((page - 1) * pageSize, page * pageSize),
    total: rows.length, page, page_size: pageSize, pages: Math.max(1, Math.ceil(rows.length / pageSize)),
  };
}

const find = <T extends { id: string }>(items: T[], id: string, what: string): T =>
  items.find((x) => x.id === id) ?? fail(404, `${what} not found`);

function audit(me: AdminUser | null, action: string, details?: Record<string, unknown>, severity: 'INFO' | 'MEDIUM' | 'HIGH' = 'INFO') {
  db.auditLogs.unshift({
    id: db.newId(), event_id: db.newId(), timestamp: new Date().toISOString(), actor_username: me?.username ?? 'system',
    action, result: 'SUCCESS', severity, source_ip: '192.168.1.24', details,
  });
}

const riskLevel = (score: number): RiskLevel => (score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 30 ? 'MEDIUM' : 'LOW');

/** Same factors and weights as backend/app/risk/engine.py. */
function evaluateRequest(me: AdminUser, body: { asset_id?: string; application_id?: string; protocol: string; reason: string; requested_duration: number }): AccessRequest {
  const target = body.asset_id ? find(db.assets, body.asset_id, 'Asset') : find(db.applications, body.application_id ?? '', 'Application');
  const policy = db.policies.find((p) => p.id === target.policy_id && p.enabled);
  const factors: RiskFactor[] = [];
  if (target.environment === 'PRODUCTION') factors.push({ code: 'PRODUCTION_ASSET', points: 30, reason: 'Target is in the PRODUCTION environment' });
  if (target.criticality === 'CRITICAL') factors.push({ code: 'CRITICAL_ASSET', points: 25, reason: 'Target criticality is CRITICAL' });
  else if (target.criticality === 'HIGH') factors.push({ code: 'HIGH_CRITICALITY', points: 15, reason: 'Target criticality is HIGH' });
  if (!body.asset_id && target.criticality !== 'LOW') factors.push({ code: 'SENSITIVE_APPLICATION', points: 20, reason: 'Application handles sensitive data' });
  const hour = new Date().getHours();
  const day = new Date().getDay();
  if (hour < 8 || hour >= 18 || day === 0 || day === 6) factors.push({ code: 'OUTSIDE_BUSINESS_HOURS', points: 20, reason: 'Requested outside business hours' });
  if (body.requested_duration > 60) factors.push({ code: 'LONG_DURATION', points: 10, reason: `Requested ${body.requested_duration} minutes (> 60)` });
  const score = Math.min(100, factors.reduce((sum, f) => sum + f.points, 0));
  const level = riskLevel(score);

  const reasons: string[] = [];
  let allowed = true;
  if (!policy) { allowed = false; reasons.push('No enabled policy covers this target (fail-safe deny)'); }
  else {
    if (policy.deny_access) { allowed = false; reasons.push(`Policy "${policy.name}" denies access`); }
    const roleNames = me.roles.map((r) => r.name);
    if (policy.allowed_roles?.length && !policy.allowed_roles.some((r) => roleNames.includes(r))) {
      allowed = false; reasons.push('Your role is not allowed by the policy');
    } else reasons.push('Role is allowed');
    if (policy.allowed_protocols?.length && !policy.allowed_protocols.includes(body.protocol)) {
      allowed = false; reasons.push(`Protocol ${body.protocol} is not allowed`);
    }
    if (policy.require_approval) reasons.push('Policy requires approval');
    if (policy.auto_approve) reasons.push('Policy auto-approves');
  }

  let status: AccessRequest['status'];
  if (!allowed || (level === 'CRITICAL' && !policy)) status = 'DENIED';
  else if (level === 'CRITICAL' || level === 'HIGH' || (policy?.require_approval && !policy.auto_approve)) status = 'APPROVAL_REQUIRED';
  else status = 'ACTIVE';

  const maxDuration = policy?.max_session_duration ?? 30;
  const duration = Math.min(body.requested_duration, maxDuration, 480);
  const id = db.newId();
  const nowIso = new Date().toISOString();
  const req: AccessRequest = {
    id, request_number: `REQ-2026-${String(42 + db.accessRequests.length).padStart(4, '0')}`, user_id: me.id,
    asset_id: body.asset_id, application_id: body.application_id, protocol: body.protocol, reason: body.reason,
    requested_duration: body.requested_duration, status, risk_score: score, risk_level: level, risk_factors: factors,
    policy_id: policy?.id, approval_required: status === 'APPROVAL_REQUIRED', jit_required: true,
    mfa_required: policy?.require_mfa ?? false, recording_required: policy?.require_recording ?? true,
    created_at: nowIso, updated_at: nowIso,
    policy_decision: {
      allowed, policy_id: policy?.id ?? null, policy_name: policy?.name ?? null, approval_required: status === 'APPROVAL_REQUIRED',
      mfa_required: policy?.require_mfa ?? false, jit_required: true, recording_required: policy?.require_recording ?? true,
      max_duration: maxDuration, auto_approve: policy?.auto_approve ?? false, reasons,
    },
  };
  if (status === 'ACTIVE') grant(req, duration);
  if (status === 'APPROVAL_REQUIRED') db.approvals.unshift({ id: db.newId(), request_id: id, status: 'PENDING', created_at: nowIso });
  if (status === 'DENIED') req.decided_at = nowIso;
  return req;
}

function grant(req: AccessRequest, minutes: number) {
  const nowIso = new Date().toISOString();
  req.status = 'ACTIVE';
  req.decided_at = nowIso;
  req.expires_at = new Date(Date.now() + minutes * 60_000).toISOString();
  req.jit_grant = { id: db.newId(), protocol: req.protocol, status: 'ACTIVE', granted_at: nowIso, expires_at: req.expires_at };
}

function decorateApproval(a: (typeof db.approvals)[number]) {
  const req = db.accessRequests.find((r) => r.id === a.request_id);
  return { ...a, request: req };
}

function riskSummary() {
  const open = db.riskFindings.filter((f) => f.status === 'OPEN');
  const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  open.forEach((f) => { bySeverity[f.severity] += 1; });
  const byStatus = { OPEN: 0, ACKNOWLEDGED: 0, RESOLVED: 0 };
  db.riskFindings.forEach((f) => { byStatus[f.status] += 1; });
  const count = (key: 'rule_code' | 'source') =>
    db.riskFindings.reduce<Record<string, number>>((acc, f) => ({ ...acc, [f[key]]: (acc[f[key]] ?? 0) + 1 }), {});
  const days = Array.from({ length: 14 }, (_, i) => new Date(Date.now() - (13 - i) * 86_400_000).toISOString().slice(0, 10));
  const levels = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 } as Record<string, number>;
  db.accessRequests.forEach((r) => { if (r.risk_level) levels[r.risk_level] += 1; });
  return {
    window_days: 30, open_by_severity: bySeverity, by_status: byStatus, by_rule: count('rule_code'), by_source: count('source'),
    new_findings_per_day: days.map((day, i) => ({ day, counts: i % 4 === 0 ? { HIGH: 1 } : i % 3 === 0 ? { MEDIUM: 1, LOW: 1 } : {} })),
    access_risk_by_level: levels,
    access_risk_per_day: days.map((day, i) => ({ day, counts: { LOW: 2 + (i % 3), MEDIUM: 1 + (i % 2), HIGH: i % 5 === 0 ? 1 : 0 } })),
    total_findings: db.riskFindings.length, last_evaluated_at: db.ago(5),
    rules: {
      MFA_FAILURE_BURST: 'Repeated MFA failures for one user', HOST_KEY_MISMATCH: 'SSH host key differs from the pinned key',
      HIGH_RISK_ACCESS: 'High or critical risk access request', EGRESS_BLOCKED: 'Isolated browser egress was blocked',
    },
    thresholds: { mfa_failure_threshold: 3, launch_denial_threshold: 5 },
  };
}

const routes: [string, RegExp, Handler][] = [
  // --- Auth ---
  ['get', /^\/auth\/config$/, () => ({ dev_mode: true })],
  ['post', /^\/auth\/login$/, ({ body }) => {
    const u = db.users.find((x) => x.username === body?.username && x.is_active);
    if (!u || body?.password !== db.DEMO_PASSWORD) fail(401, 'Invalid username or password');
    return { access_token: `demo.${u!.username}`, refresh_token: '', token_type: 'bearer', expires_in: 3600 };
  }],
  ['get', /^\/auth\/me$/, ({ me }) => {
    const u = requireUser(me);
    return { id: u.id, username: u.username, email: u.email, full_name: u.full_name, roles: u.roles.map((r) => r.name),
      permissions: permissionsOf(u), mfa_enabled: u.mfa_enabled, is_active: u.is_active };
  }],

  // --- Dashboard ---
  ['get', /^\/dashboard\/summary$/, () => ({
    active_sessions: db.sessions.filter((s) => s.status === 'ACTIVE').length,
    pending_requests: db.accessRequests.filter((r) => r.status === 'APPROVAL_REQUIRED').length,
    high_risk_sessions: 1, today_sessions: 3, failed_mfa_attempts: 3,
    jit_grants_active: db.accessRequests.filter((r) => r.jit_grant?.status === 'ACTIVE').length,
    registered_assets: db.assets.length, recording_storage_mb: 4.8,
  })],
  ['get', /^\/dashboard\/activity$/, ({ params }) => db.auditLogs.slice(0, Number(params.limit ?? 20)).map((a) => ({
    event_id: a.event_id, timestamp: a.timestamp, severity: a.severity, action: a.action, actor: a.actor_username,
    target: a.target_type, details: a.details ? Object.values(a.details).join(' · ') : undefined,
  }))],

  // --- Assets / applications / policies (CRUD) ---
  ...crud('assets', db.assets, 'Asset', (body) => ({ status: 'ACTIVE', ...body })),
  ...crud('applications', db.applications, 'Application', (body) => ({
    status: 'ACTIVE', ...body, target_url: `${String(body.protocol ?? 'https').toLowerCase()}://${body.hostname}:${body.port ?? 443}/`,
  })),
  ...crud('policies', db.policies, 'Policy', (body) => body),

  // --- Credential references & provisioning (no secrets exist here) ---
  ['get', /^\/assets\/([^/]+)\/credential-ref$/, ({ match }) =>
    db.credentialRefs.find((c) => c.asset_id === match[1] && c.is_active) ?? fail(404, 'No credential reference')],
  ['post', /^\/assets\/([^/]+)\/credential-ref\/check$/, ({ match }) =>
    db.credentialRefs.some((c) => c.asset_id === match[1] && c.is_active)
      ? { status: 'ok', message: 'The reference resolves and is readable (demo).' }
      : { status: 'no_reference', message: 'This asset has no active credential reference.' }],
  ['put', /^\/assets\/([^/]+)\/credential-ref$/, ({ match, body }) => upsertRef(match[1], body.secret_name, body.username)],
  ['delete', /^\/assets\/([^/]+)\/credential-ref$/, ({ match }) => {
    db.credentialRefs.forEach((c) => { if (c.asset_id === match[1]) c.is_active = false; });
    return null;
  }],
  ['put', /^\/assets\/([^/]+)\/credential$/, ({ match, body, me }) => {
    require(me, 'vault:manage');
    const ref = upsertRef(match[1], body.secret_name, body.username);
    return { asset: find(db.assets, match[1], 'Asset'), vault_path: ref.vault_path, version: ref.secret_version, username: body.username, verified: true };
  }],
  ['get', /^\/credential-provisioning\/status$/, () => ({
    configured: true, reason: 'Demo mode: credentials are simulated and never stored.', secret_provider: 'openbao',
    references: db.assets.map((a) => ({ name: a.name, path: `secret/securepam/assets/${a.name}`, bound_asset_id: a.id, bound_asset_name: a.name })),
    openbao_ui_url: null,
  })],
  ['post', /^\/credential-provisioning\/assets$/, ({ body, me }) => {
    require(me, 'assets:create');
    const nowIso = new Date().toISOString();
    const asset = { ...body.asset, id: db.newId(), status: 'ACTIVE', created_at: nowIso, updated_at: nowIso, created_by: me!.username };
    db.assets.unshift(asset);
    const ref = upsertRef(asset.id, body.credential.secret_name, body.credential.username);
    return { asset, vault_path: ref.vault_path, version: ref.secret_version, username: body.credential.username, verified: true };
  }],

  // --- Access requests & approvals ---
  ['get', /^\/access-requests$/, ({ params, me }) => {
    const u = requireUser(me);
    const visible = can(u, 'access_requests:read') ? db.accessRequests : db.accessRequests.filter((r) => r.user_id === u.id);
    return paginate(visible, params);
  }],
  ['get', /^\/access-requests\/([^/]+)$/, ({ match, me }) => {
    const u = requireUser(me);
    const req = find(db.accessRequests, match[1], 'Access request');
    if (req.user_id !== u.id && !can(u, 'access_requests:read')) fail(404, 'Access request not found');
    return req;
  }],
  ['post', /^\/access-requests$/, ({ body, me }) => {
    require(me, 'access_requests:create');
    const req = evaluateRequest(me!, body);
    db.accessRequests.unshift(req);
    audit(me, 'ACCESS_REQUEST_CREATED', { request: req.request_number, risk_score: req.risk_score, decision: req.status }, 'MEDIUM');
    return req;
  }],
  ['post', /^\/access-requests\/([^/]+)\/cancel$/, ({ match, me }) => {
    const req = find(db.accessRequests, match[1], 'Access request');
    if (req.user_id !== requireUser(me).id) fail(403, 'Only the requester can cancel this request.');
    req.status = 'CANCELLED';
    db.approvals.filter((a) => a.request_id === req.id && a.status === 'PENDING').forEach((a) => { a.status = 'REJECTED'; });
    return req;
  }],
  ['get', /^\/approvals$/, ({ params, me }) => { require(me, 'approvals:read'); return paginate(db.approvals.map(decorateApproval), params); }],
  ['get', /^\/approvals\/([^/]+)$/, ({ match }) => decorateApproval(find(db.approvals, match[1], 'Approval'))],
  ['post', /^\/approvals\/([^/]+)\/(approve|reject)$/, ({ match, body, me }) => {
    require(me, `approvals:${match[2]}`);
    const approval = find(db.approvals, match[1], 'Approval');
    const req = find(db.accessRequests, approval.request_id, 'Access request');
    if (req.user_id === me!.id) fail(403, 'You cannot approve or reject your own request.');
    if (approval.status !== 'PENDING') fail(409, 'This approval has already been decided.');
    approval.status = match[2] === 'approve' ? 'APPROVED' : 'REJECTED';
    approval.approver_id = me!.id;
    approval.comment = body?.comment;
    approval.decided_at = new Date().toISOString();
    req.decided_by = me!.id;
    if (match[2] === 'approve') grant(req, Math.min(req.requested_duration, req.policy_decision?.max_duration ?? 60));
    else { req.status = 'REJECTED'; req.decided_at = approval.decided_at; }
    audit(me, match[2] === 'approve' ? 'ACCESS_APPROVED' : 'ACCESS_REJECTED', { request: req.request_number }, 'MEDIUM');
    return approval;
  }],

  // --- Sessions & JIT grants ---
  ['get', /^\/sessions\/?$/, ({ params, me }) => {
    const u = requireUser(me);
    return paginate(can(u, 'sessions:read') ? db.sessions : db.sessions.filter((s) => s.user_id === u.id), params);
  }],
  ['post', /^\/sessions\/(ssh|rdp|web)\/launch$/, () => fail(503, LIVE_SESSION_MESSAGE)],
  ['get', /^\/sessions\/([^/]+)$/, ({ match }) => find(db.sessions, match[1], 'Session')],
  ['post', /^\/sessions\/([^/]+)\/terminate$/, ({ match, me }) => {
    require(me, 'sessions:terminate');
    const s = find(db.sessions, match[1], 'Session');
    s.status = 'TERMINATED';
    s.end_time = new Date().toISOString();
    if (s.recording_status === 'RECORDING') s.recording_status = 'COMPLETED';
    const req = db.accessRequests.find((r) => r.id === s.request_id);
    if (req?.jit_grant) { req.jit_grant.status = 'REVOKED'; req.jit_grant.revoked_at = s.end_time; req.status = 'EXPIRED'; }
    audit(me, 'SESSION_TERMINATED', { session: s.session_number }, 'HIGH');
    return { session_id: s.id, session_number: s.session_number, ok: true, status: s.status, gateway: 'closed',
      recording: 'COMPLETED', grant_revoked: true, errors: [], complete: true };
  }],
  ['post', /^\/jit-grants\/([^/]+)\/revoke$/, ({ match, me }) => {
    require(me, 'sessions:terminate');
    const req = db.accessRequests.find((r) => r.jit_grant?.id === match[1]) ?? fail(404, 'Grant not found');
    const revokedAt = new Date().toISOString();
    req!.jit_grant!.status = 'REVOKED';
    req!.jit_grant!.revoked_at = revokedAt;
    req!.status = 'EXPIRED';
    let ended = 0;
    db.sessions.filter((s) => s.request_id === req!.id && s.status === 'ACTIVE').forEach((s) => {
      s.status = 'TERMINATED'; s.end_time = revokedAt; ended += 1;
    });
    return { id: match[1], status: 'REVOKED', revoked_at: revokedAt, sessions_ended: ended };
  }],

  // --- Recordings ---
  ['get', /^\/recordings\/?$/, ({ params, me }) => { require(me, 'recordings:read'); return paginate(db.recordings, params); }],
  ['get', /^\/recordings\/([^/]+)\/stream$/, ({ match }) => {
    const rec = find(db.recordings, match[1], 'Recording');
    return rec.format === 'asciicast' ? db.demoCast : fail(503, 'RDP screen recordings are not included in the static demo.');
  }],
  ['get', /^\/recordings\/([^/]+)\/transcript$/, ({ match }) => {
    const rec = find(db.recordings, match[1], 'Recording');
    return rec.transcript_available
      ? { available: true, reason: null, recording_id: rec.id, session_number: rec.session_number, transcript: {
          limitations: 'Derived from the terminal stream: shows observed input, not proof of execution.',
          events_truncated: false, events: db.demoTranscriptEvents } }
      : { available: false, reason: 'No transcript for this recording type.', recording_id: rec.id, session_number: rec.session_number, transcript: null };
  }],
  ['get', /^\/recordings\/([^/]+)\/transcript\/export$/, () => JSON.stringify(db.demoTranscriptEvents, null, 2)],

  // --- Audit ---
  ['get', /^\/audit\/?$/, ({ params, me }) => { require(me, 'audit:read'); return paginate(db.auditLogs, params); }],

  // --- Users & roles ---
  ['get', /^\/users$/, ({ params, me }) => { require(me, 'users:read'); return paginate(db.users, params); }],
  ['post', /^\/users$/, ({ body, me }) => {
    require(me, 'users:create');
    const u: AdminUser = {
      id: db.newId(), username: body.username, full_name: body.full_name, email: body.email, is_active: true, is_system_user: false,
      mfa_enabled: false, external_id: body.external_id ?? null, identity_source: 'LOCAL',
      roles: db.roles().filter((r) => body.role_ids?.includes(r.id)).map((r) => ({ id: r.id, name: r.name })),
      last_login: null, created_at: new Date().toISOString(), active_sessions: 0,
    };
    db.users.push(u);
    return u;
  }],
  ['get', /^\/users\/([^/]+)\/sessions$/, ({ match }) => {
    const u = find(db.users, match[1], 'User');
    const own = db.sessions.filter((s) => s.user_id === u.id);
    return {
      user_id: u.id, username: u.username, session_limit: 3, active_sessions: own.filter((s) => s.status === 'ACTIVE').length,
      sessions: own.map((s) => ({ id: s.id, session_number: s.session_number, asset_name: s.asset_name ?? null, protocol: s.protocol,
        status: s.status, start_time: s.start_time ?? null, end_time: s.end_time ?? null, created_at: s.created_at,
        recording_status: s.recording_status ?? null, jit_grant_id: s.jit_grant_id ?? null })),
      ready_grants: [],
    };
  }],
  ['post', /^\/users\/([^/]+)\/sessions\/terminate-all$/, ({ match, me }) => {
    require(me, 'sessions:terminate');
    const live = db.sessions.filter((s) => s.user_id === match[1] && s.status === 'ACTIVE');
    live.forEach((s) => { s.status = 'TERMINATED'; s.end_time = new Date().toISOString(); });
    return { user_id: match[1], complete: true, terminated: live.length, results: live.map((s) => ({
      session_id: s.id, session_number: s.session_number, ok: true, status: s.status, gateway: 'closed', recording: 'COMPLETED',
      grant_revoked: true, errors: [] })) };
  }],
  ['get', /^\/users\/([^/]+)$/, ({ match }) => {
    const u = find(db.users, match[1], 'User');
    return { ...u, last_login_ip: '192.168.1.24', failed_login_count: u.username === 'ravi.ops' ? 3 : 0, permissions: permissionsOf(u),
      live_sessions: db.sessions.filter((s) => s.user_id === u.id && s.status === 'ACTIVE').length };
  }],
  ['patch', /^\/users\/([^/]+)$/, ({ match, body, me }) => { require(me, 'users:update'); return Object.assign(find(db.users, match[1], 'User'), body); }],
  ['post', /^\/users\/([^/]+)\/(deactivate|reactivate)$/, ({ match, me }) => {
    require(me, 'users:update');
    const u = find(db.users, match[1], 'User');
    if (u.id === me!.id) fail(409, 'You cannot deactivate your own account.');
    u.is_active = match[2] === 'reactivate';
    return u;
  }],
  ['post', /^\/users\/([^/]+)\/roles$/, ({ match, body, me }) => {
    require(me, 'users:update');
    const u = find(db.users, match[1], 'User');
    const role = db.roles().find((r) => r.id === body.role_id) ?? fail(404, 'Role not found');
    if (!u.roles.some((r) => r.id === role!.id)) u.roles.push({ id: role!.id, name: role!.name });
    return u;
  }],
  ['delete', /^\/users\/([^/]+)\/roles\/([^/]+)$/, ({ match, me }) => {
    require(me, 'users:update');
    const u = find(db.users, match[1], 'User');
    u.roles = u.roles.filter((r) => r.id !== match[2]);
    return u;
  }],
  ['get', /^\/roles$/, () => db.roles()],

  // --- Settings & health ---
  ['get', /^\/settings\/session-policy$/, () => sessionPolicy],
  ['put', /^\/settings\/session-policy$/, ({ body, me }) => {
    require(me, 'settings:update');
    sessionPolicy.max_concurrent_sessions = Number(body.max_concurrent_sessions);
    return sessionPolicy;
  }],
  ['get', /^\/settings\/summary$/, () => ({
    environment: 'demo', version: '1.0.0', dev_mode: true, authentication: 'Demo accounts (Keycloak OIDC + TOTP in the full system)',
    secret_provider: 'openbao', jit_default_minutes: 30, jit_max_minutes: 480, session_default_timeout_minutes: 60,
    session_max_timeout_minutes: 480, rate_limit_per_minute: 120, rate_limit_login_per_minute: 10, recording_storage_writable: true,
    recording_retention_days: 90, ssh_recording_format: 'asciicast v2', managed_by: 'Static portfolio demo',
    mfa_provider: 'Keycloak TOTP', mfa_self_service: true, mfa_failure_sync_enabled: true, siem_forwarding_enabled: false,
    credential_provisioning_configured: true, openbao_ui_configured: false,
  })],
  ['get', /^\/health\/detailed$/, () => ({
    status: 'healthy', version: '1.0.0', environment: 'demo', dev_mode: true,
    services: ['database', 'redis', 'openbao', 'keycloak', 'guacd', 'browser_isolation'].map((service) => ({
      service, status: 'mock', details: 'Simulated in the static demo',
    })),
  })],

  // --- Risk Centre ---
  ['get', /^\/risk\/summary$/, () => riskSummary()],
  ['get', /^\/risk\/findings$/, ({ params }) => paginate(db.riskFindings, params)],
  ['get', /^\/risk\/findings\/([^/]+)$/, ({ match }) => {
    const f = find(db.riskFindings, match[1], 'Finding');
    return { ...f, asset_name: db.assets.find((a) => a.id === f.asset_id)?.name ?? null,
      application_name: db.applications.find((a) => a.id === f.application_id)?.name ?? null,
      username: db.users.find((u) => u.id === f.user_id)?.username ?? null,
      evidence_events: db.auditLogs.filter((a) => a.action === 'MFA_FAILURE' && f.rule_code === 'MFA_FAILURE_BURST')
        .map((a) => ({ reference: a.event_id, found: true, timestamp: a.timestamp, action: a.action, actor: a.actor_username, result: a.result })) };
  }],
  ['patch', /^\/risk\/findings\/([^/]+)$/, ({ match, body, me }) => {
    require(me, 'risk:manage');
    const f = find(db.riskFindings, match[1], 'Finding');
    f.status = body.status;
    f.status_note = body.note ?? null;
    f.status_changed_at = new Date().toISOString();
    return f;
  }],
  ['post', /^\/risk\/evaluate$/, () => ({ evaluated: db.riskFindings.length, new: 0 })],
  ['put', /^\/risk\/thresholds$/, ({ body }) => body],
];

const sessionPolicy = { max_concurrent_sessions: 3, min_allowed: 1, max_allowed: 10, default: 3 };

function upsertRef(assetId: string, secretName: string, username?: string) {
  const asset = find(db.assets, assetId, 'Asset');
  db.credentialRefs.forEach((c) => { if (c.asset_id === assetId) c.is_active = false; });
  const nowIso = new Date().toISOString();
  const ref = {
    id: db.newId(), asset_id: assetId, provider: 'openbao', vault_path: `secret/securepam/assets/${secretName || asset.name}`,
    secret_type: 'PASSWORD' as const, username: username ?? null, secret_version: 1, is_active: true, last_rotated: nowIso,
    created_at: nowIso, updated_at: nowIso,
  };
  db.credentialRefs.push(ref);
  return ref;
}

function crud<T extends { id: string; created_at: string; updated_at: string }>(
  resource: string, items: T[], label: string, prepare: (body: Record<string, any>) => Record<string, unknown>,
): [string, RegExp, Handler][] {
  const one = new RegExp(`^/${resource}/([^/]+)$`);
  return [
    ['get', new RegExp(`^/${resource}$`), ({ params }) => paginate(items, params)],
    ['get', one, ({ match }) => find(items, match[1], label)],
    ['post', new RegExp(`^/${resource}$`), ({ body, me }) => {
      require(me, `${resource}:create`);
      const nowIso = new Date().toISOString();
      const item = { ...prepare(body), id: db.newId(), created_at: nowIso, updated_at: nowIso, created_by: me!.username } as unknown as T;
      items.unshift(item);
      audit(me, `${label.toUpperCase()}_CREATED`, { name: (item as Record<string, unknown>).name });
      return item;
    }],
    ['patch', one, ({ match, body, me }) => {
      require(me, `${resource}:update`);
      return Object.assign(find(items, match[1], label), body, { updated_at: new Date().toISOString() });
    }],
    ['delete', one, ({ match, me }) => {
      require(me, `${resource}:delete`);
      const index = items.findIndex((x) => x.id === match[1]);
      if (index < 0) fail(404, `${label} not found`);
      items.splice(index, 1);
      return null;
    }],
  ];
}

function currentUser(config: InternalAxiosRequestConfig): AdminUser | null {
  const header = String(config.headers?.Authorization ?? config.headers?.get?.('Authorization') ?? '');
  const username = header.startsWith('Bearer demo.') ? header.slice('Bearer demo.'.length) : null;
  return db.users.find((u) => u.username === username && u.is_active) ?? null;
}

export const demoAdapter: AxiosAdapter = async (config) => {
  await new Promise((resolve) => setTimeout(resolve, 120)); // feel like a network call
  const method = (config.method ?? 'get').toLowerCase();
  const path = (config.url ?? '').replace(/^https?:\/\/[^/]+/, '').replace(/^\/api\/v1/, '').split('?')[0];
  const body = typeof config.data === 'string' && config.data ? JSON.parse(config.data) : config.data;
  const respond = (status: number, data: unknown): AxiosResponse =>
    ({ data, status, statusText: String(status), headers: {}, config, request: {} });

  try {
    for (const [verb, pattern, handler] of routes) {
      const match = verb === method ? path.match(pattern) : null;
      if (match) {
        const data = handler({ params: config.params ?? {}, body, match, me: currentUser(config) });
        if (method !== 'get') saveState();
        return respond(data === null ? 204 : 200, data ?? '');
      }
    }
    fail(404, `Not available in the demo: ${method.toUpperCase()} ${path}`);
  } catch (error) {
    if (!(error instanceof HttpError)) throw error;
    const response = respond(error.status, { detail: error.detail, error_code: null, errors: null });
    throw new AxiosError(error.detail, AxiosError.ERR_BAD_REQUEST, config, {}, response);
  }
  throw new Error('unreachable');
};
