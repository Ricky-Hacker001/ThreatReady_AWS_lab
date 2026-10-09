import { useEffect, useState } from 'react';
import { api, fmt } from './api';
import { useLab, PageHeader, Panel, Badge, Note, Field, KV, StatusDot, Tabs, Empty, DataTable, Link } from './ui';
import { describeTest } from './App';

export const sevTone = (s: string) => ({ Critical: 'red', High: 'red', Medium: 'orange', Low: 'blue', Resolved: 'green' } as any)[s] || 'grey';
export const statusTone = (s: string) => (s === 'Verified' ? 'green' : s === 'Open' ? 'red' : s.startsWith('Remediated') ? 'orange' : 'grey');

export function ObjectiveList({ objectives }: { objectives: any[] }) {
  const { act, busy, status } = useLab(); const [open, setOpen] = useState<string | null>(null);
  return <ul className="objs">{objectives.map(o => <li key={o.id} className={o.done ? 'done' : o.locked ? 'locked' : ''}>
    <div className="obj-row"><span className="tick" aria-hidden>{o.done ? '✓' : o.locked ? '🔒' : o.partial ? '◐' : ''}</span>
      <div className="obj-t"><span>{o.title}</span><small>{o.done && o.id === 'L4.triage' && !status.complete ? `${o.points} pts · scored when the report is submitted` : o.done ? `${o.awarded} / ${o.points} pts` : o.partial ? `Fixed — run a verification test (${o.awarded} / ${o.points} pts)` : `${o.points} pts`}{o.hints.length > 0 && ` · ${o.hints.length} hint${o.hints.length > 1 ? 's' : ''} used`}</small></div>
      {!o.locked && !o.done && <button className="btn sm" aria-expanded={open === o.id} onClick={() => setOpen(open === o.id ? null : o.id)}>Hints</button>}</div>
    {open === o.id && !o.done && <div className="hints">{o.hints.map((h: string, i: number) => { const lines = h.split('\n'); return <div key={i} className="hint"><span className="hint-k">{i === 0 ? 'Tip' : 'Step by step'}</span>{lines.length > 1 ? <ol>{lines.map(l => <li key={l}>{l}</li>)}</ol> : h}</div>; })}
      {o.hintsRemaining > 0 ? <button className="btn sm" disabled={busy} onClick={() => act('hint.request', { objectiveId: o.id }, { silent: true, confirm: { title: 'Reveal a hint?', body: `This reduces the points for this objective by 25% (${o.hintsRemaining} hint${o.hintsRemaining > 1 ? 's' : ''} available).`, label: 'Reveal hint' } })}>Reveal {o.hints.length ? 'next' : 'a'} hint (−25%)</button> : <span className="muted">No more hints.</span>}</div>}
  </li>)}</ul>;
}

export function Home() {
  const { cloud, status, nav, def } = useLab();
  const bad = status.health.filter((h: any) => !h.ok).length;
  return <div className="page"><PageHeader crumbs={[{ label: 'Console Home' }]} title="Console Home" desc={`Account ${cloud.account.alias} (${cloud.account.id}) · ${cloud.account.region} · ${cloud.account.environment}`} />
    <div className="grid2">
      <Panel title="Account status"><KV items={[['Security status', <Badge tone="red">At risk</Badge>], ['Incident', <><Badge tone={sevTone(status.incident.severity)}>{status.incident.severity}</Badge> {status.incident.id} — {status.incident.status}</>], ['Containment', status.incident.containment], ['Operating as', <code>ThreatReady-SecurityAnalyst</code>], ['Findings verified', `${status.posture.resolved} of ${status.posture.total}`]]} />
        <button className="btn primary" onClick={() => nav('incident')}>{status.incident.acknowledged ? 'Open Incident Center' : 'Open incident ticket'}</button></Panel>
      <Panel title="NovaCart application health" actions={bad ? <Badge tone="red">{bad} failing</Badge> : <Badge tone="green">All healthy</Badge>}><table className="plain"><tbody>{status.health.map((h: any) => <tr key={h.id}><td><StatusDot ok={h.ok} label={h.label} /></td></tr>)}</tbody></table><p className="muted">Production is live. Health is re-evaluated after every change you make.</p></Panel>
      <Panel title="Services in this environment"><div className="svc-grid">{[['iam', 'IAM', `${Object.keys(cloud.iam.users).length} users · ${Object.keys(cloud.iam.roles).length} roles`], ['s3', 'S3', `${Object.keys(cloud.s3.buckets).length} buckets`], ['ec2', 'EC2', `${Object.keys(cloud.ec2.instances).length} instances`], ['vpc', 'VPC', cloud.vpc.name], ['lambda', 'Lambda', `${Object.keys(cloud.lambda.functions).length} function`], ['cloudtrail', 'CloudTrail', `${cloud.cloudtrail.eventCount} events`], ['cloudwatch', 'CloudWatch', `${Object.keys(cloud.cloudwatch.alarms).length} alarm(s)`], ['kms', 'KMS', `${Object.keys(cloud.kms.keys).length} key`], ['secrets', 'Secrets Manager', `${Object.keys(cloud.secrets.secrets).length} secret(s)`], ['org', 'Governance', `${Object.keys(cloud.org.accounts).length} accounts`]].map(([id, l, d]) => <button key={id} onClick={() => nav(id)}><b>{l}</b><small>{d}</small></button>)}</div></Panel>
      <Panel title="Open alerts">{status.alerts.length ? status.alerts.map((a: any) => <div key={a.id} className="alertrow"><Badge tone={sevTone(a.severity)}>{a.severity}</Badge> <b>{a.title}</b><p>{a.detail}</p></div>) : <Empty title="No open alerts">Monitoring is quiet — which is not the same as safe.</Empty>}</Panel>
    </div></div>;
}

export function FindingsPage() {
  const { status, nav } = useLab(); const [sel, setSel] = useState<string | null>(null); const f = status.findings.find((x: any) => x.id === sel);
  return <div className="page"><PageHeader crumbs={[{ label: 'Security Findings' }]} title="Security Findings" desc="Ten vulnerabilities exist in this environment. Each is marked when you record it and again when the fix is verified." />
    <div className="split"><Panel pad={false}><DataTable search={false} rows={status.findings} rowKey={r => r.id} selected={sel} onRow={r => setSel(r.id)} cols={[{ key: 'id', label: 'ID' }, { key: 'title', label: 'Vulnerability' }, { key: 'service', label: 'Service', render: r => r.service || '—' }, { key: 'severity', label: 'Severity', render: r => r.severity ? <Badge tone={sevTone(r.severity)}>{r.severity}</Badge> : '—' }, { key: 'status', label: 'Status', render: r => <Badge tone={statusTone(r.status)}>{r.status}</Badge> }]} /></Panel>
      {f && <Panel title={`${f.id} · ${f.title}`}>{!f.service ? <Empty title="Not found yet">Investigate the environment. When you see the misconfiguration, use "Report finding" on that resource.</Empty> : <>
        <KV items={[['Status', <Badge tone={statusTone(f.status)}>{f.status}</Badge>], ['Severity', <><Badge tone={sevTone(f.severity)}>{f.severity}</Badge> {f.severityWhy}</>], ['Resource', <code>{f.resource}</code>], ['Recorded', fmt(f.discoveredAt)], ['Business impact', f.business], ['Technical impact', f.technical]]} />
        <h4>Verification</h4>{f.checks.map((c: any) => <div key={c.label} className={`vline ${c.passed ? 'pass' : ''}`}>{c.passed ? '✓' : '○'} {c.label}</div>)}
        {f.explanation ? <Note tone="ok"><b>Why this fix works.</b> {f.explanation}</Note> : <p className="muted">A technical explanation is shown once the fix is verified.</p>}
        <button className="btn" onClick={() => { const [s, t, ...id] = f.resource.split('/'); nav({ service: s, type: t, id: id.join('/') }); }}>Go to resource</button></>}</Panel>}</div></div>;
}

export function ObjectivesPage() {
  const { status, def } = useLab();
  return <div className="page"><PageHeader crumbs={[{ label: 'Lab Objectives' }]} title="Lab Objectives" desc={`Score ${status.score.total} / ${status.score.max} · ${status.progress}% of objectives complete`} />
    {def.briefing.levels.map((l: any) => <Panel key={l.n} title={<>Level {l.n} — {l.name} {status.level > l.n || (status.complete && l.n === 4) ? <Badge tone="green">Complete</Badge> : status.level === l.n ? <Badge tone="blue">In progress</Badge> : <Badge tone="grey">Locked</Badge>}</>}>
      {status.level >= l.n ? <ObjectiveList objectives={status.objectives.filter((o: any) => o.level === l.n)} /> : <p className="muted">Complete Level {l.n - 1} to unlock {status.objectives.filter((o: any) => o.level === l.n).length} objectives.</p>}</Panel>)}</div>;
}

export function IncidentCenter() {
  const { status, cloud, def, act, busy, route, nav, openReport } = useLab(); const tab = route.tab || 'ticket';
  const keys = Object.values<any>(cloud.iam.users).flatMap(u => u.accessKeys.map((k: any) => ({ ...k, user: u.name }))); const [key, setKey] = useState('');
  return <div className="page"><PageHeader crumbs={[{ label: 'Incident Center' }]} title="Incident Center" desc="Ticket, alerts, evidence, company policies and reporting for INC-2041." />
    <Tabs value={tab} onChange={t => nav({ service: 'incident', tab: t })} tabs={[{ id: 'ticket', label: 'Ticket & alerts' }, { id: 'policies', label: 'Company policies' }, { id: 'evidence', label: `Evidence locker (${status.evidence.length})` }, { id: 'regression', label: 'Regression suite' }, { id: 'report', label: 'Incident report' }, { id: 'story', label: 'Story' }]} />
    {tab === 'ticket' && <>
      <Panel title={<>INC-2041 · Suspicious access patterns in novacart-training <Badge tone={sevTone(status.incident.severity)}>{status.incident.severity}</Badge></>} actions={!status.incident.acknowledged && <button className="btn primary" disabled={busy} onClick={() => act('incident.acknowledge')}>Acknowledge ticket</button>}>
        <KV items={[['Status', status.incident.status], ['Containment', status.incident.containment], ['Assigned to', status.incident.acknowledged ? 'You (Cloud Security Analyst)' : 'Unassigned — acknowledge to take ownership'], ['Compromised credential', status.incident.declaredKey ? <code>{status.incident.declaredKey}</code> : 'Not identified']]} />
        <p>{def.briefing.intro}</p><p className="muted">Reported by: internal security review. Affected: storefront application identity, storage, audit logging (suspected).</p></Panel>
      <Panel title="Alerts">{!status.alerts.length && <Empty title="No alerts">Alerts appear here as the incident develops.</Empty>}
        {status.alerts.map((a: any) => <div key={a.id} className="alertrow"><div><Badge tone={sevTone(a.severity)}>{a.severity}</Badge> <b>{a.id} · {a.title}</b> <small className="muted">{fmt(a.at)}{a.source ? ` · ${a.source}` : ''}</small></div><p>{a.detail}</p>
          {a.triage && <div className="inline"><Field label="Classification"><select value={a.classification || ''} disabled={busy || status.complete} onChange={e => e.target.value && act('l4.triage', { alertId: a.id, classification: e.target.value })}><option value="">Select…</option>{def.triageOptions.map((o: string) => <option key={o} value={o}>{o.replace(/-/g, ' ')}</option>)}</select></Field>{a.correct !== undefined && <Badge tone={a.correct ? 'green' : 'red'}>{a.correct ? 'Supported by evidence' : 'Not supported by evidence'}</Badge>}</div>}
          {a.id === 'AL-0' && <div className="inline"><Field label="Declare the compromised credential" hint="Base this on audit evidence: access key ID, source IP and user agent."><select value={status.incident.declaredKey || key} disabled={!!status.incident.declaredKey} onChange={e => setKey(e.target.value)}><option value="">Select access key…</option>{keys.map((k: any) => <option key={k.id} value={k.id}>{k.id} ({k.user})</option>)}</select></Field>
            {!status.incident.declaredKey && <button className="btn primary" disabled={!key || busy} onClick={() => act('incident.declareCompromisedKey', { accessKeyId: key }, { confirm: { title: 'Declare compromised credential', body: `Record ${key} as the credential used by the intruder? This is entered in the incident record.`, label: 'Declare' } })}>Declare</button>}</div>}</div>)}</Panel></>}
    {tab === 'policies' && def.briefing.policies.map((p: any) => <Panel key={p.title} title={p.title}><p>{p.body}</p></Panel>)}
    {tab === 'evidence' && <Panel title="Evidence locker" pad={false}><DataTable search={false} empty="No evidence preserved. Add events from CloudTrail → Event history." rows={status.evidence} rowKey={r => r.id} cols={[{ key: 'time', label: 'Event time', render: r => fmt(r.time) }, { key: 'name', label: 'Event' }, { key: 'actor', label: 'Actor' }, { key: 'accessKeyId', label: 'Access key', render: r => r.accessKeyId || '—' }, { key: 'sourceIp', label: 'Source IP' }, { key: 'resource', label: 'Resource' }, { key: 'x', label: '', render: r => <button className="btn sm" disabled={busy} onClick={() => act('evidence.remove', { eventId: r.id })}>Remove</button> }]} /></Panel>}
    {tab === 'regression' && <Panel title="Regression suite" actions={<button className="btn primary" disabled={busy || status.level < 3} onClick={() => act('l3.regression')}>Run regression suite</button>}>
      {status.level < 3 ? <Empty title="Unlocks at Level 3">The suite re-checks application health and every finding after hardening.</Empty> : !status.regression ? <p className="muted">Not run yet. The suite checks NovaCart application health and the verification state of all ten findings.</p> : <>
        <Note tone={status.regression.passed ? 'ok' : 'warn'}>Last run {fmt(status.regression.at)}: {status.regression.passed ? 'all checks passed' : 'some checks are failing'}.</Note>
        <table className="plain"><tbody>{status.regression.results.map((r: any) => <tr key={r.label}><td><StatusDot ok={r.ok} label={r.label} /></td><td className="muted">{r.detail}</td></tr>)}</tbody></table></>}</Panel>}
    {tab === 'report' && (status.level < 4 ? <Panel><Empty title="Unlocks at Level 4">The final incident report is written once the environment is hardened. A draft generated from your session so far is always available.</Empty><button className="btn" onClick={openReport}>View draft report</button></Panel> : status.complete ? <Panel><Note tone="ok">Report submitted.</Note><button className="btn primary" onClick={openReport}>Open final incident report</button></Panel> : <ReportForm />)}
    {tab === 'story' && status.chapters.map((c: any) => <Panel key={c.n} title={`Chapter ${c.n} — ${c.title}`}><p>{c.text}</p></Panel>)}
  </div>;
}

function ReportForm() {
  const { def, cloud, act, busy, status, setDirty } = useLab(); const F = def.reportForm;
  const [v, setV] = useState<any>({ rootCause: '', credential: '', timeline: F.timeline.map((t: any) => t.id), affected: [], residual: [], hardening: [], summary: '', containmentRationale: '' });
  const set = (k: string, x: any) => { setV((o: any) => ({ ...o, [k]: x })); setDirty('report', true); };
  useEffect(() => () => setDirty('report', false), []);
  const tog = (k: string, id: string) => set(k, v[k].includes(id) ? v[k].filter((x: string) => x !== id) : [...v[k], id]);
  const move = (i: number, d: number) => { const t = [...v.timeline]; const j = i + d; if (j < 0 || j >= t.length) return; [t[i], t[j]] = [t[j], t[i]]; set('timeline', t); };
  const keys = Object.values<any>(cloud.iam.users).flatMap(u => u.accessKeys.map((k: any) => k.id));
  const untriaged = status.alerts.filter((a: any) => a.triage && !a.classification).length;
  const ready = v.rootCause && v.credential && v.summary.trim().length >= 80 && v.containmentRationale.trim().length > 0 && !untriaged;
  const Multi = ({ k, label }: { k: string; label: string }) => <fieldset className="checks"><legend>{label}</legend>{F[k].map((o: any) => <label key={o.id}><input type="checkbox" checked={v[k].includes(o.id)} onChange={() => tog(k, o.id)} /> {o.label}</label>)}</fieldset>;
  return <Panel title="Incident report — INC-2041">
    <p className="muted">Your structured answers are scored against the evidence in this session. Narrative fields are included in the report as written.</p>
    {untriaged > 0 && <Note tone="warn">Triage the {untriaged} open alert(s) on the Ticket & alerts tab before submitting.</Note>}
    <Field label="Executive summary" hint={`${v.summary.trim().length} / 80 characters minimum`}><textarea rows={4} value={v.summary} onChange={e => set('summary', e.target.value)} maxLength={4000} /></Field>
    <Field label="Root cause — how was access obtained?"><select value={v.rootCause} onChange={e => set('rootCause', e.target.value)}><option value="">Select…</option>{F.rootCause.map((o: any) => <option key={o.id} value={o.id}>{o.label}</option>)}</select></Field>
    <Field label="Credential used by the intruder"><select value={v.credential} onChange={e => set('credential', e.target.value)}><option value="">Select…</option>{keys.map((k: string) => <option key={k}>{k}</option>)}</select></Field>
    <fieldset className="checks"><legend>Incident timeline — put the events in chronological order</legend><ol className="order">{v.timeline.map((id: string, i: number) => <li key={id}><span>{F.timeline.find((t: any) => t.id === id).label}</span><span><button type="button" className="btn sm" aria-label="Move earlier" disabled={i === 0} onClick={() => move(i, -1)}>↑</button><button type="button" className="btn sm" aria-label="Move later" disabled={i === v.timeline.length - 1} onClick={() => move(i, 1)}>↓</button></span></li>)}</ol></fieldset>
    <Multi k="affected" label="Affected resources — select those with evidence of unauthorized access" />
    <Field label="Containment decisions and rationale"><textarea rows={3} value={v.containmentRationale} onChange={e => set('containmentRationale', e.target.value)} maxLength={2000} /></Field>
    <Multi k="residual" label="Residual risks" /><Multi k="hardening" label="Post-incident hardening plan" />
    <button className="btn primary" disabled={!ready || busy} onClick={async () => { const r = await act('l4.submitReport', v, { confirm: { title: 'Submit incident report', body: 'Submitting closes the incident and ends the lab. The report cannot be edited afterwards.', label: 'Submit report' } }); if (r?.ok) setDirty('report', false); }}>Submit incident report</button>
  </Panel>;
}

export function ReportScreen({ onBack }: { onBack: () => void }) {
  const { session, status } = useLab(); const [r, setR] = useState<any>(null); const [err, setErr] = useState('');
  useEffect(() => { api(`/sessions/${session.id}/report`).then(setR).catch(e => setErr(e.message)); }, [session.id, status.minutes]);
  if (err) return <div className="page"><Note tone="bad">{err}</Note></div>;
  if (!r) return <div className="page"><div className="spinner" /></div>;
  const sc = r.performance.score; const A = r.reportAssessment;
  const yn = (b: any) => b === null ? '—' : b ? <Badge tone="green">Yes</Badge> : <Badge tone="grey">No</Badge>;
  return <div className="page report"><PageHeader crumbs={[{ label: 'Incident Center', to: 'incident' }, { label: 'Incident report' }]} title={`Incident report — INC-2041 ${r.meta.final ? '' : '(draft)'}`} desc={`${r.meta.lab} · ${r.meta.learner} · run ${r.meta.run} · generated from session event history`} actions={<><button className="btn" onClick={onBack}>Back to console</button><button className="btn" onClick={() => window.print()}>Print</button></>} />
    {!r.meta.final && <Note tone="warn">Draft: the incident is still open. This reflects what you have done and verified so far — nothing more.</Note>}
    <Panel title="Executive summary"><KV items={[['Outcome', <><Badge tone={sevTone(r.summary.severity)}>{r.summary.severity}</Badge> · {r.summary.containment}</>], ['Findings verified', `${r.summary.findingsVerified} of ${r.summary.findingsTotal}`], ['Simulated duration', `${Math.floor(r.meta.simulatedMinutes / 60)}h ${r.meta.simulatedMinutes % 60}m`], ['Final score', <b>{sc.total} / {sc.max} ({sc.percent}%)</b>]]} />
      {r.summary.learnerText ? <><h4>Analyst summary</h4><p className="quote">{r.summary.learnerText}</p><h4>Containment rationale</h4><p className="quote">{r.summary.containmentRationale}</p></> : <p className="muted">The analyst's written summary is added when the report is submitted at Level 4.</p>}</Panel>
    <Panel title="Findings" pad={false}><div className="dt-scroll"><table><thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>Discovered</th><th>Root cause remediated</th><th>Verified</th><th>Statement</th></tr></thead><tbody>{r.findings.map((f: any) => <tr key={f.id}><td>{f.id}</td><td>{f.title}</td><td>{f.severity}</td><td>{yn(f.discovered)}</td><td>{yn(f.remediated)}</td><td>{yn(f.verified)}</td><td>{f.statement}</td></tr>)}</tbody></table></div></Panel>
    <div className="grid2">
      <Panel title="Intruder impact during this session"><KV items={[['Successful intruder actions after the alert', String(r.intruder.successfulActions)], ['Confidential downloads on record', String(r.intruder.documentsAccessed)], ['Backdoor IAM user created', r.intruder.backdoorUserCreated ? 'Yes' : 'No'], ['Payment credential disclosed', r.intruder.paymentCredentialDisclosed ? 'Yes' : 'No'], ['Fraudulent charges', r.intruder.fraudulentCharges ? 'Yes' : 'No']]} /></Panel>
      <Panel title="Availability"><table className="plain"><tbody>{r.availability.current.map((h: any) => <tr key={h.label}><td><StatusDot ok={h.ok} label={h.label} /></td></tr>)}</tbody></table>{r.availability.outages.length ? <ul>{r.availability.outages.map((o: any, i: number) => <li key={i}>{fmt(o.at)} — {o.label} failed after {o.cause}</li>)}</ul> : <p className="muted">No outages were caused.</p>}</Panel></div>
    <Panel title="Evidence preserved" pad={false}><DataTable search={false} empty="No evidence was preserved." rows={r.evidence} rowKey={x => x.id} cols={[{ key: 'time', label: 'Time', render: x => fmt(x.time) }, { key: 'name', label: 'Event' }, { key: 'actor', label: 'Actor' }, { key: 'accessKeyId', label: 'Access key', render: x => x.accessKeyId || '—' }, { key: 'sourceIp', label: 'Source IP' }]} /></Panel>
    <div className="grid2">
      <Panel title="Containment actions">{r.containmentActions.length ? <ul className="acts">{r.containmentActions.map((e: any) => <li key={e.seq}><time>{fmt(e.at)}</time> {e.message}</li>)}</ul> : <p className="muted">None recorded.</p>}</Panel>
      <Panel title="Remediation actions">{r.remediationActions.length ? <ul className="acts">{r.remediationActions.map((e: any) => <li key={e.seq}><time>{fmt(e.at)}</time> {e.message}</li>)}</ul> : <p className="muted">None recorded.</p>}</Panel></div>
    <Panel title="Verification results">{r.verificationTests.length ? <ul className="acts">{r.verificationTests.map((t: any, i: number) => <li key={i}><time>{fmt(t.at)}</time> {describeTest(t)}</li>)}</ul> : <p className="muted">No verification tests were run.</p>}{r.regression && <p>Regression suite ({fmt(r.regression.at)}): <b>{r.regression.passed ? 'passed' : 'failing'}</b></p>}</Panel>
    <Panel title="Incident timeline"><ul className="tl">{r.timeline.map((t: any, i: number) => <li key={i} className={`tl-${t.kind}`}><time>{fmt(t.at)}</time><span>{t.text}</span></li>)}</ul></Panel>
    <Panel title="Remaining risks"><ul>{r.remainingRisks.map((x: string) => <li key={x}>{x}</li>)}</ul></Panel>
    {A && <Panel title="Report assessment (rule-based)"><table className="plain"><tbody>{A.parts.map((p: any) => <tr key={p.id}><td><b>{p.label}</b><br /><span className="muted">{p.evidence}</span></td><td className="num">{p.awarded} / {p.max}</td></tr>)}</tbody></table>
      <h4>Alert triage</h4><ul>{A.triage.map((t: any) => <li key={t.id}>{t.id} {t.title}: {String(t.chosen).replace(/-/g, ' ')} — {t.correct ? 'supported by evidence' : 'not supported by evidence'}</li>)}</ul>
      <h4>Recommendations selected</h4><ul>{A.input.hardening.map((h: string) => <li key={h}>{h}</li>)}</ul></Panel>}
    <Panel title="Learner performance"><table className="plain"><tbody>{Object.entries<any>(sc.categories).map(([k, v]) => <tr key={k}><td style={{ textTransform: 'capitalize' }}>{k}</td><td className="num">{v.awarded} / {v.max}</td></tr>)}{sc.penalties.map((p: any) => <tr key={p.label} className="pen"><td>{p.label}</td><td className="num">−{p.points}</td></tr>)}<tr><td><b>Total</b></td><td className="num"><b>{sc.total} / {sc.max}</b></td></tr></tbody></table>
      <p className="muted">Hints used: {r.performance.hintsUsed} · Failed actions: {r.performance.failedActions} · Unsupported finding reports: {r.performance.unsupportedReports} · Actions recorded: {r.performance.actions}</p>
      <details><summary>Objective-by-objective breakdown</summary><table className="plain"><tbody>{r.performance.objectives.map((o: any) => <tr key={o.id}><td>L{o.level}</td><td>{o.done ? '✓' : '○'} {o.title}</td><td className="muted">{o.at ? fmt(o.at) : 'not completed'}{o.hints ? ` · ${o.hints} hint(s)` : ''}</td><td className="num">{o.awarded} / {o.points}</td></tr>)}</tbody></table></details></Panel>
  </div>;
}
