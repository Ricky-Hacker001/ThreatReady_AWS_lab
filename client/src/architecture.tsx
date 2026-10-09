import { useEffect, useRef, useState } from 'react';
import { store } from './api';
import { Badge, useLab } from './ui';
import { statusTone } from './pages';

// Beginner-friendly NovaCart architecture window: drag by the title bar, resize from the edges, click a box to learn what it is.
// Finding markers appear only for findings the learner has already discovered.
type Node = { id: string; x: number; y: number; w?: number; h?: number; title: string; sub: string; svc?: string; findings?: string[]; external?: boolean; what: string; ask?: string };
const W = 130, H = 56;
const NODES: Node[] = [
  { id: 'org', x: 10, y: 8, w: 790, h: 28, title: 'Account guardrails', sub: 'Governance', svc: 'org', findings: ['V10'],
    what: 'Organization-wide rules (service control policies). They can forbid an action for everyone in the account, even administrators.', ask: 'Is anything stopping a powerful user from switching off the audit log?' },
  { id: 'users', x: 20, y: 78, title: 'Customers', sub: 'Internet', external: true,
    what: 'People shopping on NovaCart from their browsers. They are outside AWS, on the public internet.', ask: 'Customers should only ever reach the load balancer, nothing behind it.' },
  { id: 'alb', x: 180, y: 78, title: 'Load balancer', sub: 'nc-storefront-alb', svc: 'ec2',
    what: 'The front door. It receives every customer request over HTTPS and passes it on to the app server. It is meant to be public.' },
  { id: 'app', x: 340, y: 78, title: 'App server', sub: 'nc-app-server', svc: 'ec2', findings: ['V3'],
    what: 'The virtual computer (EC2 instance) that runs the storefront code. Its security group is a firewall that decides who may connect to it.', ask: 'Who is allowed to connect to it directly, and on which ports?' },
  { id: 'fn', x: 500, y: 78, title: 'Order processor', sub: 'Lambda', svc: 'lambda', findings: ['V6', 'V7'],
    what: 'A small piece of code (Lambda function) that runs for every new order: it charges the customer and saves an export file.', ask: 'Where does it keep its payment key? What is its role allowed to do?' },
  { id: 'pay', x: 660, y: 78, title: 'Payment gateway', sub: 'external service', external: true,
    what: 'An outside company that processes card payments. The order processor proves who it is with a secret payment key.' },
  { id: 'iam', x: 20, y: 200, title: 'Identities', sub: 'IAM users & roles', svc: 'iam', findings: ['V1'],
    what: 'IAM decides who can do what. Users (people or apps with access keys) and roles (identities that services borrow) get their permissions from policies.', ask: 'Does each identity have only the permissions it needs? Any keys or users you do not recognise?' },
  { id: 'assets', x: 180, y: 200, title: 'Product images', sub: 'S3 · product-assets', svc: 's3',
    what: 'An S3 bucket (a folder in the cloud) holding product photos. These are meant to be public so the store can show them.' },
  { id: 'docs', x: 340, y: 200, title: 'Internal docs', sub: 'S3 · internal-docs', svc: 's3', findings: ['V2', 'V5'],
    what: 'An S3 bucket with confidential company files such as invoices and payroll.', ask: 'Who can read it? Is it encrypted the way company policy requires?' },
  { id: 'kms', x: 500, y: 200, title: 'Encryption key', sub: 'KMS · novacart-data', svc: 'kms', findings: ['V9'],
    what: 'The key that encrypts confidential data. Anyone allowed to use this key can read that data.', ask: 'Who may use the key, and who may change its rules?' },
  { id: 'secrets', x: 660, y: 200, title: 'Stored secrets', sub: 'Secrets Manager', svc: 'secrets',
    what: 'A safe for passwords and API keys. Apps fetch a secret when they need it instead of keeping it in their settings.' },
  { id: 'trail', x: 180, y: 318, title: 'Audit log', sub: 'CloudTrail', svc: 'cloudtrail', findings: ['V4'],
    what: 'The account\'s security camera. It records every action: who did it, when, and from which IP address.', ask: 'Is it recording right now? Does it cover all regions and all actions?' },
  { id: 'cw', x: 420, y: 318, title: 'Monitoring', sub: 'CloudWatch alarms', svc: 'cloudwatch', findings: ['V8'],
    what: 'Collects logs and metrics, and raises an alarm when something looks wrong.', ask: 'If someone made unauthorized calls, would any alarm go off?' },
  { id: 'team', x: 660, y: 318, title: 'Security team', sub: 'SNS · nc-security-alerts', external: true,
    what: 'The people who receive alarms (through the SNS topic nc-security-alerts) and respond to incidents. In this lab, that is you.' },
];
const SVC_LABEL: Record<string, string> = { org: 'Governance', ec2: 'EC2', lambda: 'Lambda', iam: 'IAM', s3: 'S3', kms: 'KMS', secrets: 'Secrets Manager', cloudtrail: 'CloudTrail', cloudwatch: 'CloudWatch' };
const N = Object.fromEntries(NODES.map(n => [n.id, n]));
const TOUR = ['users', 'alb', 'app', 'assets', 'docs', 'kms', 'fn', 'secrets', 'pay', 'iam', 'org', 'trail', 'cw', 'team'];
// [from, to, label, plain explanation, health probe that breaks this flow]
const EDGES: [string, string, string, string, string?][] = [
  ['users', 'alb', 'HTTPS', 'Customers send requests to the load balancer over HTTPS.', 'storefront'],
  ['alb', 'app', 'port 8080', 'The load balancer forwards each request to the app server on port 8080.', 'storefront'],
  ['app', 'fn', 'new order', 'When someone checks out, the app hands the order to the order processor.', 'orders'],
  ['fn', 'pay', 'charge', 'The order processor charges the card through the payment gateway.', 'orders'],
  ['app', 'assets', 'upload', 'The app uploads product photos using the svc-storefront-app access key.', 'asset-upload'],
  ['app', 'docs', 'invoices', 'The app writes invoices using its server role (nc-app-server-role).', 'invoices'],
  ['docs', 'kms', 'encrypts with', 'Confidential files are encrypted with the KMS key.'],
  ['fn', 'secrets', 'payment key', 'The order processor needs the payment key to charge cards.'],
  ['trail', 'cw', 'events', 'CloudTrail sends its events to CloudWatch for checking.'],
  ['cw', 'team', 'alert', 'When an alarm fires, CloudWatch notifies the security team.'],
];

function anchor(a: Node, b: Node): [number, number, number, number] {
  const ac = [a.x + W / 2, a.y + H / 2], bc = [b.x + W / 2, b.y + H / 2];
  if (a.y === b.y) return a.x < b.x ? [a.x + W, ac[1], b.x, bc[1]] : [a.x, ac[1], b.x + W, bc[1]];
  return [ac[0], a.y + H, bc[0], b.y];
}

type Geo = { x: number; y: number; w: number; h: number };
const MIN_W = 360, MIN_H = 260, GEO_KEY = 'tr_arch_geo';
// Keep the whole window inside the viewport so no control is ever out of reach.
const clamp = (g: Geo): Geo => {
  const vw = window.innerWidth, vh = window.innerHeight;
  const w = Math.max(Math.min(MIN_W, vw - 16), Math.min(g.w, vw - 16)), h = Math.max(Math.min(MIN_H, vh - 16), Math.min(g.h, vh - 16));
  return { w, h, x: Math.max(8, Math.min(g.x, vw - w - 8)), y: Math.max(8, Math.min(g.y, vh - h - 8)) };
};
const loadGeo = (): Geo | null => { try { const g = JSON.parse(store.get(GEO_KEY) || 'null'); return g && ['x', 'y', 'w', 'h'].every(k => typeof g[k] === 'number') ? clamp(g) : null; } catch { return null; } };

export function ArchitectureCorner() {
  const { status, nav } = useLab();
  const [open, setOpen] = useState(false);
  const [geo, setGeo] = useState<Geo | null>(null); const [maxFrom, setMaxFrom] = useState<Geo | null>(null);
  const [sel, setSel] = useState<string | null>(null); const [tour, setTour] = useState(false);
  const [moving, setMoving] = useState(false);
  const fabRef = useRef<HTMLButtonElement>(null);

  useEffect(() => { if (geo) store.set(GEO_KEY, JSON.stringify(geo)); }, [geo]);
  useEffect(() => { const f = () => setGeo(g => g && clamp(g)); window.addEventListener('resize', f); return () => window.removeEventListener('resize', f); }, []);

  const cornerGeo = (): Geo => {
    const r = fabRef.current?.parentElement?.getBoundingClientRect();
    const w = Math.min(760, (r?.width ?? 800) - 32), h = Math.min(600, (r?.height ?? 600) - 28);
    return clamp({ x: (r?.left ?? 0) + 16, y: (r?.bottom ?? h) - h - 14, w, h });
  };
  const show = () => { setGeo(loadGeo() || cornerGeo()); setOpen(true); };
  const resetPos = () => { setMaxFrom(null); setGeo(cornerGeo()); };
  const toggleMax = () => {
    if (!geo) return;
    if (maxFrom) { setGeo(maxFrom); setMaxFrom(null); return; }
    setMaxFrom(geo); setGeo(clamp({ x: 8, y: 52, w: window.innerWidth - 16, h: window.innerHeight - 60 }));
  };
  // One pointer handler for moving ('move') and resizing from an edge or corner ('e', 's', 'w', 'se', 'sw').
  const startDrag = (mode: string) => (e: React.PointerEvent) => {
    if (!geo || e.button !== 0 || (mode === 'move' && (e.target as HTMLElement).closest('button'))) return;
    e.preventDefault(); const g0 = geo, x0 = e.clientX, y0 = e.clientY; const el = e.currentTarget as HTMLElement; el.setPointerCapture(e.pointerId); setMoving(true);
    const mv = (m: PointerEvent) => {
      const dx = m.clientX - x0, dy = m.clientY - y0; const g = { ...g0 };
      if (mode === 'move') { g.x += dx; g.y += dy; }
      if (mode.includes('e')) g.w = Math.min(g0.w + dx, window.innerWidth - g0.x - 8);
      if (mode.includes('s')) g.h = Math.min(g0.h + dy, window.innerHeight - g0.y - 8);
      if (mode.includes('w')) { g.w = Math.max(MIN_W, Math.min(g0.w - dx, g0.x + g0.w - 8)); g.x = g0.x + g0.w - g.w; }
      setMaxFrom(null); setGeo(clamp(g));
    };
    const up = () => { el.removeEventListener('pointermove', mv); el.removeEventListener('pointerup', up); el.removeEventListener('pointercancel', up); setMoving(false); };
    el.addEventListener('pointermove', mv); el.addEventListener('pointerup', up); el.addEventListener('pointercancel', up);
  };

  const fstat = Object.fromEntries(status.findings.map((f: any) => [f.id, f]));
  const known = (n: Node) => (n.findings || []).map(id => fstat[id]).filter(f => f && f.status !== 'Not found');
  const mark = (n: Node) => { const k = known(n); return !k.length ? null : k.every((f: any) => f.status === 'Verified') ? 'ok' : 'warn'; };
  const broken = new Set(status.health.filter((h: any) => !h.ok).map((h: any) => h.id));
  const linked = new Set(sel ? EDGES.filter(e => e[0] === sel || e[1] === sel).flatMap(e => [e[0], e[1]]) : []);
  const pick = (id: string | null) => { setSel(id); if (!id) setTour(false); };
  const step = tour && sel ? TOUR.indexOf(sel) : -1;
  const node = sel ? N[sel] : null;

  const fab = <button ref={fabRef} className="archfab" onClick={show} aria-label="Show architecture diagram" style={open ? { visibility: 'hidden' } : undefined} tabIndex={open ? -1 : 0}><span aria-hidden>⧉</span> Architecture</button>;
  if (!open || !geo) return fab;
  return <>{fab}
    <section className={`archwin ${moving ? 'moving' : ''}`} style={{ left: geo.x, top: geo.y, width: geo.w, height: geo.h }} aria-label="NovaCart architecture" onKeyDown={e => e.key === 'Escape' && pick(null)}>
      <div className="archwin-h" onPointerDown={startDrag('move')} onDoubleClick={e => !(e.target as HTMLElement).closest('button') && toggleMax()} title="Drag to move · double-click to maximise">
        <span className="grip" aria-hidden>⠿</span><b>How NovaCart works</b><span className="grow" />
        <button className="btn sm" onClick={() => { setTour(true); setSel(TOUR[0]); }}>▶ Guided tour</button>
        <button className="btn sm" onClick={toggleMax}>{maxFrom ? 'Restore' : 'Maximise'}</button>
        <button className="btn sm" onClick={resetPos} title="Put the window back in the corner">Reset</button>
        <button className="x" onClick={() => setOpen(false)} aria-label="Close architecture diagram">×</button></div>
      <div className="archwin-b">
        {!node && <p className="archintro"><b>New to cloud?</b> Each box is one part of NovaCart; arrows show how data moves. <b>Click any box</b> to learn what it does, or press <b>Guided tour</b> to walk through it in order. Drag the title bar to move this window and its edges to resize it.</p>}
        <div className="archcanvas">
          <svg className="archmap" viewBox="0 0 810 386" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Architecture flow: customers to load balancer to app server, then to storage, order processing and monitoring" onClick={e => e.target === e.currentTarget && pick(null)}>
            <defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#545b64" /></marker>
              <marker id="arr-hl" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#0972d3" /></marker>
              <marker id="arr-bad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#d13212" /></marker></defs>
            <rect className="arch-vpc" x="168" y="52" width="314" height="98" rx="6" /><text className="arch-lbl" x="176" y="146">Private network (VPC)</text>
            <line className="arch-sep" x1="10" y1="290" x2="800" y2="290" /><text className="arch-lbl" x="20" y="282">Watching everything: every action above is recorded and checked</text>
            {EDGES.map(([a, b, label, why, probe]) => {
              const [x1, y1, x2, y2] = anchor(N[a], N[b]); const bad = !!probe && broken.has(probe); const hl = !!sel && (a === sel || b === sel);
              return <g key={a + b} className={`arch-edge ${bad ? 'bad' : ''} ${hl ? 'hl' : ''} ${sel && !hl ? 'dim' : ''}`}><title>{bad ? `Broken right now — ${why}` : why}</title>
                <line x1={x1} y1={y1} x2={x2} y2={y2} markerEnd={`url(#${bad ? 'arr-bad' : hl ? 'arr-hl' : 'arr'})`} />
                <text x={(x1 + x2) / 2 + (x1 === x2 ? 6 : 0)} y={y1 === y2 ? N[a].y - 5 : (y1 + y2) / 2} textAnchor={x1 === x2 ? 'start' : 'middle'}>{bad ? `${label} — broken` : label}</text></g>;
            })}
            {NODES.map(n => {
              const m = mark(n); const w = n.w ?? W, h = n.h ?? H; const band = n.id === 'org';
              return <g key={n.id} className={`arch-node ${band ? 'band' : ''} ${n.external ? 'ext' : ''} ${sel === n.id ? 'sel' : ''} ${sel && sel !== n.id && !linked.has(n.id) ? 'dim' : ''}`}
                onClick={() => { setTour(false); setSel(sel === n.id ? null : n.id); }} onDoubleClick={() => n.svc && nav(n.svc)}
                role="button" tabIndex={0} aria-label={`${n.title}: ${n.sub}`} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setTour(false); setSel(n.id); } }}>
                <rect x={n.x} y={n.y} width={w} height={h} rx={band ? 4 : 5} />
                {band ? <text x={n.x + w / 2} y={n.y + 19} textAnchor="middle" className="t">Account guardrails (Governance) — rules that apply to everyone, even admins</text>
                  : <><text x={n.x + w / 2} y={n.y + 24} textAnchor="middle" className="t">{n.title}</text><text x={n.x + w / 2} y={n.y + 41} textAnchor="middle" className="s">{n.sub}</text></>}
                {m && <><circle cx={n.x + w - 4} cy={n.y + 4} r="9" className={`arch-dot ${m}`} /><text x={n.x + w - 4} y={n.y + 8} textAnchor="middle" className="arch-dot-t">{m === 'ok' ? '✓' : '!'}</text></>}
              </g>;
            })}
          </svg>
        </div>
        {node && <div className="archinfo" aria-live="polite">
          <div className="archinfo-h">{step >= 0 && <span className="archstep">Step {step + 1} of {TOUR.length}</span>}<b>{node.title}</b><span className="muted">· {node.sub}</span><span className="grow" /><button className="x" onClick={() => pick(null)} aria-label="Close details">×</button></div>
          <p>{node.what}</p>
          {node.ask && <p className="archask"><b>Good question to ask:</b> {node.ask}</p>}
          {known(node).map((f: any) => <p key={f.id} className="archfind"><Badge tone={statusTone(f.status)}>{f.status}</Badge> {f.title}</p>)}
          {EDGES.filter(e => e[0] === node.id || e[1] === node.id).map(([a, b, , why, probe]) => <p key={a + b} className={`archflow ${probe && broken.has(probe) ? 'bad' : ''}`}>{a === node.id ? '→' : '←'} {why}{probe && broken.has(probe) ? ' (broken right now)' : ''}</p>)}
          <div className="archinfo-f">
            {node.svc && <button className="btn sm primary" onClick={() => nav(node.svc!)}>Open {SVC_LABEL[node.svc!]} in console</button>}
            <span className="grow" />
            {tour && <><button className="btn sm" disabled={step <= 0} onClick={() => setSel(TOUR[step - 1])}>‹ Back</button>
              {step < TOUR.length - 1 ? <button className="btn sm" onClick={() => setSel(TOUR[step + 1])}>Next ›</button> : <button className="btn sm" onClick={() => pick(null)}>Finish tour</button>}</>}
          </div>
        </div>}
        <div className="archlegend"><span><i className="lg-dot warn" /> Finding you reported, not yet fixed</span><span><i className="lg-dot ok" /> Fixed and verified</span><span><i className="lg-line" /> Broken flow (app outage)</span><span><i className="lg-ext" /> Outside AWS</span></div>
      </div>
      {['e', 's', 'w', 'se', 'sw'].map(d => <div key={d} className={`archrs rs-${d}`} onPointerDown={startDrag(d)} aria-hidden />)}
    </section>
  </>;
}
