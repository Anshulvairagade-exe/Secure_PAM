import { useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { formatDistanceToNow } from 'date-fns';
import { RefreshCw, Search } from 'lucide-react';
import { riskApi } from '@/api';
import { getApiErrorMessage } from '@/api/errors';
import { EmptyState, ErrorBanner, Skeleton } from '@/components/Feedback';
import Modal from '@/components/Modal';
import { useAuth } from '@/hooks/useAuth';
import type { FindingSeverity, RiskDayPoint, RiskFinding } from '@/types';

const SEVERITIES: FindingSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const SEV_BADGE: Record<FindingSeverity, string> = {
  CRITICAL: 'badge-critical', HIGH: 'badge-danger', MEDIUM: 'badge-warning', LOW: 'badge-success', INFO: 'badge-info',
};
const SEV_BAR: Record<string, string> = {
  CRITICAL: 'bg-red-600', HIGH: 'bg-orange-500', MEDIUM: 'bg-amber-500', LOW: 'bg-green-500', INFO: 'bg-blue-500',
};
const STATUS_BADGE: Record<RiskFinding['status'], string> = {
  OPEN: 'badge-danger', ACKNOWLEDGED: 'badge-warning', RESOLVED: 'badge-success',
};
const RULE_LABEL: Record<string, string> = {
  MFA_FAILURES: 'MFA failures', LAUNCH_DENIALS: 'Launch denials', CREDENTIAL_DENIED: 'Credential denied',
  CREDENTIAL_FAILED: 'Credential failed', CREDENTIAL_REF_BROKEN: 'Credential reference', RECORDING_FAILED: 'Recording failed',
  TLS_VALIDATION: 'TLS validation', EGRESS_BLOCKED: 'Egress blocked', HIGH_RISK_ACCESS: 'High-risk access', EXTERNAL: 'External',
};

/** Stacked daily bars from real counts; a day without records is drawn as an empty column, never interpolated. */
function DailyBars({ points, keys, label }: { points: RiskDayPoint[]; keys: string[]; label: string }) {
  const max = Math.max(1, ...points.map((p) => keys.reduce((n, k) => n + (p.counts[k] ?? 0), 0)));
  const total = points.reduce((n, p) => n + keys.reduce((m, k) => m + (p.counts[k] ?? 0), 0), 0);
  return (
    <figure aria-label={label}>
      <div className="flex h-28 items-end gap-[2px]" role="img"
        aria-label={`${label}: ${total} in ${points.length} days`}>
        {points.map((p) => {
          const sum = keys.reduce((n, k) => n + (p.counts[k] ?? 0), 0);
          return (
            <div key={p.day} className="flex h-full flex-1 flex-col justify-end" title={`${p.day}: ${sum}`}>
              {keys.map((k) => (p.counts[k] ? (
                <div key={k} className={SEV_BAR[k] ?? 'bg-gray-500'} style={{ height: `${(p.counts[k] / max) * 100}%` }} />
              ) : null))}
              {sum === 0 && <div className="h-px bg-navy-700" />}
            </div>
          );
        })}
      </div>
      <figcaption className="mt-1 flex justify-between text-[10px] text-gray-500">
        <span>{points[0]?.day}</span><span>{total} total</span><span>{points[points.length - 1]?.day}</span>
      </figcaption>
    </figure>
  );
}

export default function RiskCenter() {
  const { hasPermission } = useAuth();
  const canManage = hasPermission('risk:manage');
  const queryClient = useQueryClient();
  const [params] = useSearchParams();
  const [days, setDays] = useState(30);
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('OPEN,ACKNOWLEDGED');
  const [rule, setRule] = useState('');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<string | null>(null);
  const assetId = params.get('asset_id') ?? undefined;
  const applicationId = params.get('application_id') ?? undefined;

  const summary = useQuery({ queryKey: ['risk-summary', days], queryFn: () => riskApi.summary(days) });
  const listParams = { page, page_size: 20, days, severity: severity || undefined, status: status || undefined,
    rule: rule || undefined, search: search || undefined, asset_id: assetId, application_id: applicationId };
  const findings = useQuery({ queryKey: ['risk-findings', listParams], queryFn: () => riskApi.findings(listParams) });
  const evaluate = useMutation({
    mutationFn: riskApi.evaluate,
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ['risk-summary'] }); void queryClient.invalidateQueries({ queryKey: ['risk-findings'] }); },
  });

  const s = summary.data;
  const openTotal = s ? SEVERITIES.reduce((n, k) => n + (s.open_by_severity[k] ?? 0), 0) : 0;
  const accessLevels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

  return (
    <div className="space-y-6">
      <div className="page-header">
        <div>
          <h1 className="page-title">Risk Center</h1>
          <p className="page-subtitle">
            Findings derived from SecurePAM's own records by fixed, documented rules (audit events, risk-engine evaluations),
            plus any external findings ingested through the API. Nothing here is estimated or synthetic.
          </p>
          <p className="mt-1 text-xs text-gray-500">
            Sources: {s ? Object.keys(s.by_source).join(', ') || 'none yet' : '…'} · Last evaluated{' '}
            {s?.last_evaluated_at ? formatDistanceToNow(new Date(s.last_evaluated_at), { addSuffix: true }) : 'never'} (automatic every 5 minutes)
          </p>
        </div>
        <div className="flex items-center gap-2">
          <select className="input w-auto" aria-label="Time period" value={days} onChange={(e) => { setDays(Number(e.target.value)); setPage(1); }}>
            <option value={7}>Last 7 days</option><option value={30}>Last 30 days</option><option value={90}>Last 90 days</option>
          </select>
          {canManage && (
            <button className="btn-secondary" onClick={() => evaluate.mutate()} disabled={evaluate.isPending}>
              <RefreshCw size={15} className={evaluate.isPending ? 'animate-spin' : ''} /> Evaluate now
            </button>
          )}
        </div>
      </div>

      {summary.isError && <ErrorBanner message={getApiErrorMessage(summary.error, 'Risk data is unavailable.')} />}
      {evaluate.isError && <ErrorBanner message={getApiErrorMessage(evaluate.error, 'Evaluation failed.')} />}
      {evaluate.data && (
        <p role="status" className="text-xs text-gray-500">
          Evaluation: {evaluate.data.created} new, {evaluate.data.updated} updated, {evaluate.data.auto_resolved} auto-resolved, {evaluate.data.reopened} reopened.
        </p>
      )}

      <div className="grid grid-cols-2 gap-3 md:grid-cols-6">
        <div className="card p-4">
          <p className="eyebrow">Open findings</p>
          {summary.isLoading ? <Skeleton className="mt-2 h-7" /> : <p className="mt-1 text-2xl font-semibold text-gray-100">{openTotal}</p>}
          {s && <p className="text-xs text-gray-500">{s.by_status.RESOLVED} resolved · {s.total_findings} total</p>}
        </div>
        {SEVERITIES.map((k) => (
          <button key={k} type="button" aria-pressed={severity === k}
            onClick={() => { setSeverity(severity === k ? '' : k); setPage(1); }}
            className={`card kbd-focus p-4 text-left transition-colors hover:border-navy-500 ${severity === k ? 'ring-2 ring-blue-500' : ''}`}>
            <p className="eyebrow flex items-center gap-1.5"><span className={`h-2 w-2 rounded-full ${SEV_BAR[k]}`} />{k.toLowerCase()}</p>
            {summary.isLoading ? <Skeleton className="mt-2 h-7" /> : <p className="mt-1 text-2xl font-semibold text-gray-100">{s?.open_by_severity[k] ?? 0}</p>}
            <p className="text-xs text-gray-500">open</p>
          </button>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <section className="card p-5">
          <h2 className="section-title">New findings per day</h2>
          <p className="mb-3 text-xs text-gray-500">By first-seen date, stacked by severity.</p>
          {s ? <DailyBars points={s.new_findings_per_day} keys={SEVERITIES} label="New findings per day" /> : <Skeleton className="h-28" />}
        </section>
        <section className="card p-5">
          <h2 className="section-title">Access-request risk (risk engine)</h2>
          <p className="mb-3 text-xs text-gray-500">
            Evaluations in the period: {s ? accessLevels.map((l) => `${s.access_risk_by_level[l] ?? 0} ${l.toLowerCase()}`).join(' · ') : '…'}
          </p>
          {s ? <DailyBars points={s.access_risk_per_day} keys={accessLevels} label="Access-request risk evaluations per day" /> : <Skeleton className="h-28" />}
        </section>
      </div>

      <section className="card overflow-hidden">
        <div className="flex flex-wrap items-center gap-2 border-b border-navy-700/60 p-4">
          <label className="relative">
            <Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-500" />
            <input className="input w-56 pl-8" placeholder="Search title or subject" aria-label="Search findings"
              value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} />
          </label>
          <select className="input w-auto" aria-label="Status" value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}>
            <option value="OPEN,ACKNOWLEDGED">Open + acknowledged</option><option value="OPEN">Open</option>
            <option value="ACKNOWLEDGED">Acknowledged</option><option value="RESOLVED">Resolved</option><option value="">All statuses</option>
          </select>
          <select className="input w-auto" aria-label="Rule" value={rule} onChange={(e) => { setRule(e.target.value); setPage(1); }}>
            <option value="">All rules</option>
            {s && Object.keys(s.rules).concat(s.by_source && Object.keys(s.by_source).some((x) => x !== 'securepam-detector') ? ['EXTERNAL'] : [])
              .map((r) => <option key={r} value={r}>{RULE_LABEL[r] ?? r}</option>)}
          </select>
          {(assetId || applicationId) && (
            <Link to="/risk" className="badge-info">Filtered to one {assetId ? 'asset' : 'application'} · clear</Link>
          )}
        </div>
        {findings.isError && <div className="p-4"><ErrorBanner message={getApiErrorMessage(findings.error, 'Findings could not be loaded.')} /></div>}
        {findings.isLoading ? (
          <div className="space-y-2 p-4">{Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-10" />)}</div>
        ) : !findings.data || findings.data.items.length === 0 ? (
          <EmptyState message={s && s.total_findings === 0
            ? (s.last_evaluated_at ? 'No findings: the records evaluated so far match no rule.' : 'Not evaluated yet. Findings appear after the first evaluation.')
            : 'No findings match these filters.'} />
        ) : (
          <div className="table-container">
            <table className="table">
              <thead><tr><th>Severity</th><th>Finding</th><th>Rule</th><th>Status</th><th>Seen</th><th>Last seen</th><th>Source</th></tr></thead>
              <tbody>
                {findings.data.items.map((f) => (
                  <tr key={f.id} className="cursor-pointer" onClick={() => setSelected(f.id)}>
                    <td><span className={SEV_BADGE[f.severity]}>{f.severity}</span></td>
                    <td>
                      <button className="kbd-focus text-left" onClick={(e) => { e.stopPropagation(); setSelected(f.id); }}>
                        <span className="block font-medium text-gray-100">{f.title}</span>
                        <span className="block text-xs text-gray-500">{f.subject}</span>
                      </button>
                    </td>
                    <td className="text-xs text-gray-400">{RULE_LABEL[f.rule_code] ?? f.rule_code}</td>
                    <td><span className={STATUS_BADGE[f.status]}>{f.status.toLowerCase()}</span></td>
                    <td className="text-gray-400">{f.occurrences}×</td>
                    <td className="whitespace-nowrap text-xs text-gray-500">{formatDistanceToNow(new Date(f.last_seen), { addSuffix: true })}</td>
                    <td className="text-xs text-gray-500">{f.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {findings.data && findings.data.pages > 1 && (
          <div className="flex items-center justify-between border-t border-navy-700/60 p-3 text-sm text-gray-500">
            <span>Page {findings.data.page} of {findings.data.pages} · {findings.data.total} findings</span>
            <div className="flex gap-2">
              <button className="btn-secondary px-3 py-1.5" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</button>
              <button className="btn-secondary px-3 py-1.5" disabled={page >= findings.data.pages} onClick={() => setPage((p) => p + 1)}>Next</button>
            </div>
          </div>
        )}
      </section>

      {s && (
        <details className="card p-5 text-sm">
          <summary className="cursor-pointer font-semibold text-gray-200">How findings are produced</summary>
          <ul className="mt-3 space-y-1.5 text-gray-400">
            {Object.entries(s.rules).map(([code, text]) => (
              <li key={code}><span className="font-mono text-xs text-gray-300">{code}</span> — {text}</li>
            ))}
          </ul>
          <p className="mt-3 text-xs text-gray-500">
            Thresholds: {s.thresholds['risk.mfa_failure_threshold']} MFA failures / {s.thresholds['risk.launch_denial_threshold']} launch
            denials within 60 minutes (Settings). Look-back: 30 days. New evidence after a resolution reopens a finding.
          </p>
        </details>
      )}

      {selected && <FindingDialog id={selected} canManage={canManage} onClose={() => setSelected(null)} />}
    </div>
  );
}

function FindingDialog({ id, canManage, onClose }: { id: string; canManage: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const detail = useQuery({ queryKey: ['risk-finding', id], queryFn: () => riskApi.finding(id) });
  const [note, setNote] = useState('');
  const update = useMutation({
    mutationFn: (status: RiskFinding['status']) => riskApi.setStatus(id, status, note || undefined),
    onSuccess: () => {
      setNote('');
      void queryClient.invalidateQueries({ queryKey: ['risk-finding', id] });
      void queryClient.invalidateQueries({ queryKey: ['risk-findings'] });
      void queryClient.invalidateQueries({ queryKey: ['risk-summary'] });
    },
  });
  const f = detail.data;
  const extra = useMemo(() => Object.entries(f?.evidence ?? {}).filter(([k]) => !['references', 'rule'].includes(k)), [f]);

  return (
    <Modal title={f?.title ?? 'Finding'} onClose={onClose} width="max-w-3xl">
      {detail.isLoading ? <Skeleton className="h-48" /> : detail.isError ? (
        <ErrorBanner message={getApiErrorMessage(detail.error, 'The finding could not be loaded.')} />
      ) : f ? (
        <div className="space-y-5 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <span className={SEV_BADGE[f.severity]}>{f.severity}</span>
            <span className={STATUS_BADGE[f.status]}>{f.status.toLowerCase()}</span>
            <span className="text-xs text-gray-500">{RULE_LABEL[f.rule_code] ?? f.rule_code} · {f.source}</span>
          </div>
          <p className="text-gray-300">{f.description}</p>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-2 md:grid-cols-4">
            <div><dt className="eyebrow">Subject</dt><dd className="text-gray-200">{f.subject}</dd></div>
            <div><dt className="eyebrow">Occurrences</dt><dd className="text-gray-200">{f.occurrences}</dd></div>
            <div><dt className="eyebrow">First seen</dt><dd className="text-gray-200">{new Date(f.first_seen).toLocaleString()}</dd></div>
            <div><dt className="eyebrow">Last seen</dt><dd className="text-gray-200">{new Date(f.last_seen).toLocaleString()}</dd></div>
          </dl>
          <div className="flex flex-wrap gap-2 text-xs">
            {f.asset_id && <Link className="badge-info" to={`/assets?search=${encodeURIComponent(f.asset_name ?? '')}`}>Asset: {f.asset_name ?? f.asset_id}</Link>}
            {f.application_id && <Link className="badge-info" to="/applications">Application: {f.application_name ?? f.application_id}</Link>}
            {f.session_id && <Link className="badge-info" to="/admin/sessions">Session {f.subject}</Link>}
            {f.username && <Link className="badge-info" to="/users">User: {f.username}</Link>}
            {f.asset_id && <Link className="badge-neutral" to={`/risk?asset_id=${f.asset_id}`}>All findings for this asset</Link>}
          </div>
          {extra.length > 0 && (
            <div>
              <h3 className="eyebrow mb-1">Evidence summary</h3>
              <pre className="surface-terminal max-h-40 overflow-auto p-3 font-mono text-xs">{JSON.stringify(Object.fromEntries(extra), null, 2)}</pre>
            </div>
          )}
          <div>
            <h3 className="eyebrow mb-1">Evidence records ({f.evidence_events.length}{f.occurrences > f.evidence_events.length ? ` of ${f.occurrences}, most recent` : ''})</h3>
            <div className="max-h-56 overflow-auto rounded-lg border border-navy-700/60">
              <table className="table">
                <thead><tr><th>Reference</th><th>Time</th><th>Action</th><th>Actor</th><th>Result</th></tr></thead>
                <tbody>
                  {f.evidence_events.map((e) => (
                    <tr key={e.reference}>
                      <td className="font-mono text-xs text-gray-400">{e.reference}</td>
                      {e.found ? (<>
                        <td className="whitespace-nowrap text-xs text-gray-500">{e.timestamp ? new Date(e.timestamp).toLocaleString() : '—'}</td>
                        <td className="text-xs text-gray-300">{e.action}</td>
                        <td className="text-xs text-gray-400">{e.actor}</td>
                        <td className="text-xs text-gray-400">{e.result}</td>
                      </>) : <td colSpan={4} className="text-xs text-gray-500">access request / external reference (not an audit event)</td>}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="mt-1 text-xs text-gray-500">Full records: <Link className="text-blue-400 hover:underline" to="/audit">Audit Logs</Link>.</p>
          </div>
          <div>
            <h3 className="eyebrow mb-1">Remediation</h3>
            <p className="text-gray-300">{f.remediation}</p>
          </div>
          {f.status_note && <p className="text-xs text-gray-500">Status note: {f.status_note}</p>}
          {canManage && (
            <div className="space-y-2 border-t border-navy-700/60 pt-4">
              <input className="input" placeholder="Optional note (audited)" maxLength={500} value={note} onChange={(e) => setNote(e.target.value)} />
              <div className="flex flex-wrap gap-2">
                {f.status !== 'ACKNOWLEDGED' && <button className="btn-secondary" disabled={update.isPending} onClick={() => update.mutate('ACKNOWLEDGED')}>Acknowledge</button>}
                {f.status !== 'RESOLVED' && <button className="btn-success" disabled={update.isPending} onClick={() => update.mutate('RESOLVED')}>Mark resolved</button>}
                {f.status !== 'OPEN' && <button className="btn-ghost" disabled={update.isPending} onClick={() => update.mutate('OPEN')}>Reopen</button>}
              </div>
              {update.isError && <ErrorBanner message={getApiErrorMessage(update.error, 'The status could not be changed.')} />}
            </div>
          )}
        </div>
      ) : null}
    </Modal>
  );
}
