import { useState } from 'react';
import { useLab } from './ui';

// Simplified NovaCart architecture. Finding markers appear only for findings the learner has already discovered.
type Node = { id: string; x: number; y: number; title: string; sub: string; svc?: string; findings?: string[]; external?: boolean };
const W = 130, H = 56;
const NODES: Node[] = [
  { id: 'users', x: 20, y: 78, title: 'Customers', sub: 'Internet', external: true },
  { id: 'alb', x: 180, y: 78, title: 'Load balancer', sub: 'nc-storefront-alb', svc: 'ec2' },
  { id: 'app', x: 340, y: 78, title: 'App server', sub: 'nc-app-server', svc: 'ec2', findings: ['V3'] },
  { id: 'fn', x: 500, y: 78, title: 'Order processor', sub: 'Lambda', svc: 'lambda', findings: ['V6', 'V7'] },
  { id: 'pay', x: 660, y: 78, title: 'Payment gateway', sub: 'external service', external: true },
  { id: 'iam', x: 20, y: 200, title: 'Identities', sub: 'IAM users & roles', svc: 'iam', findings: ['V1'] },
  { id: 'assets', x: 180, y: 200, title: 'Product images', sub: 'S3 · product-assets', svc: 's3' },
  { id: 'docs', x: 340, y: 200, title: 'Internal docs', sub: 'S3 · internal-docs', svc: 's3', findings: ['V2', 'V5'] },
  { id: 'kms', x: 500, y: 200, title: 'Encryption key', sub: 'KMS · novacart-data', svc: 'kms', findings: ['V9'] },
  { id: 'secrets', x: 660, y: 200, title: 'Stored secrets', sub: 'Secrets Manager', svc: 'secrets' },
  { id: 'trail', x: 180, y: 318, title: 'Audit log', sub: 'CloudTrail', svc: 'cloudtrail', findings: ['V4'] },
  { id: 'cw', x: 420, y: 318, title: 'Monitoring', sub: 'CloudWatch alarms', svc: 'cloudwatch', findings: ['V8'] },
  { id: 'team', x: 660, y: 318, title: 'Security team', sub: 'SNS · nc-security-alerts', external: true },
];
const N = Object.fromEntries(NODES.map(n => [n.id, n]));
// [from, to, label, health probe that breaks this flow]
const EDGES: [string, string, string, string?][] = [
  ['users', 'alb', 'HTTPS', 'storefront'], ['alb', 'app', 'port 8080', 'storefront'], ['app', 'fn', 'new order', 'orders'], ['fn', 'pay', 'charge', 'orders'],
  ['app', 'assets', 'upload', 'asset-upload'], ['app', 'docs', 'invoices', 'invoices'], ['docs', 'kms', 'encrypts with'], ['fn', 'secrets', 'payment key'],
  ['trail', 'cw', 'events'], ['cw', 'team', 'alert'],
];

function anchor(a: Node, b: Node): [number, number, number, number] {
  const ac = [a.x + W / 2, a.y + H / 2], bc = [b.x + W / 2, b.y + H / 2];
  if (a.y === b.y) return a.x < b.x ? [a.x + W, ac[1], b.x, bc[1]] : [a.x, ac[1], b.x + W, bc[1]];
  return [ac[0], a.y + H, bc[0], b.y];
}

export function ArchitectureCorner() {
  const { status, nav } = useLab();
  const [open, setOpen] = useState(false); const [big, setBig] = useState(false);
  const fstat = Object.fromEntries(status.findings.map((f: any) => [f.id, f.status]));
  const broken = new Set(status.health.filter((h: any) => !h.ok).map((h: any) => h.id));
  const mark = (n: Node) => {
    const known = (n.findings || []).filter(f => fstat[f] && fstat[f] !== 'Not found');
    if (!known.length) return null;
    return known.every(f => fstat[f] === 'Verified') ? 'ok' : 'warn';
  };
  const orgMark = mark({ id: 'org', x: 0, y: 0, title: '', sub: '', findings: ['V10'] });
  if (!open) return <button className="archfab" onClick={() => setOpen(true)} aria-label="Show architecture diagram"><span aria-hidden>⧉</span> Architecture</button>;
  return <section className={`archcard ${big ? 'big' : ''}`} aria-label="NovaCart architecture">
    <div className="archcard-h"><b>How NovaCart works</b><span className="grow" />
      <button className="btn sm" onClick={() => setBig(!big)}>{big ? 'Smaller' : 'Expand'}</button>
      <button className="x" onClick={() => setOpen(false)} aria-label="Close architecture diagram">×</button></div>
    <div className="archcard-b">
      <ol className="archsteps">
        <li>Customers reach the store through the <b>load balancer</b>, which forwards to the <b>app server</b>.</li>
        <li>The app saves files in <b>S3</b> and sends orders to the <b>order processor</b>, which charges the payment gateway.</li>
        <li><b>CloudTrail</b> records every action in the account; <b>CloudWatch</b> alerts the security team.</li>
      </ol>
      <svg className="archmap" viewBox="0 0 810 386" role="img" aria-label="Architecture flow: customers to load balancer to app server, then to storage, order processing and monitoring">
        <defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#545b64" /></marker>
          <marker id="arr-bad" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="#d13212" /></marker></defs>
        <g className="arch-band" onClick={() => nav('org')} role="button" tabIndex={0} onKeyDown={e => e.key === 'Enter' && nav('org')}>
          <rect x="10" y="8" width="790" height="28" rx="4" /><text x="405" y="27" textAnchor="middle">Account guardrails (Governance) — rules that apply to everyone, even admins</text>
          {orgMark && <circle cx="790" cy="12" r="7" className={`arch-dot ${orgMark}`} />}</g>
        <rect className="arch-vpc" x="168" y="52" width="314" height="98" rx="6" /><text className="arch-lbl" x="176" y="146">Private network (VPC)</text>
        <line className="arch-sep" x1="10" y1="290" x2="800" y2="290" /><text className="arch-lbl" x="20" y="282">Watching everything: every action above is recorded and checked</text>
        {EDGES.map(([a, b, label, probe]) => {
          const [x1, y1, x2, y2] = anchor(N[a], N[b]); const bad = !!probe && broken.has(probe);
          return <g key={a + b} className={`arch-edge ${bad ? 'bad' : ''}`}><line x1={x1} y1={y1} x2={x2} y2={y2} markerEnd={`url(#${bad ? 'arr-bad' : 'arr'})`} />
            <text x={(x1 + x2) / 2 + (x1 === x2 ? 6 : 0)} y={y1 === y2 ? N[a].y - 5 : (y1 + y2) / 2} textAnchor={x1 === x2 ? 'start' : 'middle'}>{bad ? `${label} — broken` : label}</text></g>;
        })}
        {NODES.map(n => {
          const m = mark(n); const go = () => n.svc && nav(n.svc);
          return <g key={n.id} className={`arch-node ${n.external ? 'ext' : ''} ${n.svc ? 'click' : ''}`} onClick={go} role={n.svc ? 'button' : undefined} tabIndex={n.svc ? 0 : undefined} onKeyDown={e => e.key === 'Enter' && go()}>
            {n.svc && <title>{`Open ${n.sub}`}</title>}
            <rect x={n.x} y={n.y} width={W} height={H} rx="5" />
            <text x={n.x + W / 2} y={n.y + 24} textAnchor="middle" className="t">{n.title}</text>
            <text x={n.x + W / 2} y={n.y + 41} textAnchor="middle" className="s">{n.sub}</text>
            {m && <><circle cx={n.x + W - 4} cy={n.y + 4} r="9" className={`arch-dot ${m}`} /><text x={n.x + W - 4} y={n.y + 8} textAnchor="middle" className="arch-dot-t">{m === 'ok' ? '✓' : '!'}</text></>}
          </g>;
        })}
      </svg>
      <div className="archlegend"><span><i className="lg-dot warn" /> Finding you reported, not yet fixed</span><span><i className="lg-dot ok" /> Fixed and verified</span><span><i className="lg-line" /> Broken flow (app outage)</span><span className="muted">Click a box to open that service.</span></div>
    </div>
  </section>;
}
