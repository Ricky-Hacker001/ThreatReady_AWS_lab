import { createContext, useContext, useEffect, useMemo, useRef, useState, ReactNode } from 'react';

export const Ctx = createContext<any>(null);
export const useLab = () => useContext(Ctx);

export const Badge = ({ tone = 'grey', children }: { tone?: string; children: ReactNode }) => <span className={`badge b-${tone}`}>{children}</span>;
export const StatusDot = ({ ok, label }: { ok: boolean; label: string }) => <span className="statusdot"><i className={ok ? 'ok' : 'bad'} aria-hidden />{label}</span>;

export function Tabs({ tabs, value, onChange }: { tabs: { id: string; label: ReactNode }[]; value: string; onChange: (id: string) => void }) {
  return <div className="tabs" role="tablist">{tabs.map(t => <button key={t.id} role="tab" aria-selected={t.id === value} className={t.id === value ? 'on' : ''} onClick={() => onChange(t.id)}>{t.label}</button>)}</div>;
}

export function PageHeader({ crumbs, title, desc, actions }: { crumbs: { label: string; to?: any }[]; title: ReactNode; desc?: ReactNode; actions?: ReactNode }) {
  const { nav } = useLab();
  return <header className="pagehead">
    <nav className="crumbs" aria-label="Breadcrumb">{crumbs.map((c, i) => <span key={i}>{c.to ? <a href="#" onClick={e => { e.preventDefault(); nav(c.to); }}>{c.label}</a> : <span aria-current="page">{c.label}</span>}{i < crumbs.length - 1 && <em>›</em>}</span>)}</nav>
    <div className="pagehead-row"><div><h1>{title}</h1>{desc && <p className="desc">{desc}</p>}</div><div className="actions">{actions}</div></div>
  </header>;
}

export function Panel({ title, actions, children, pad = true }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; pad?: boolean }) {
  return <section className="panel">{(title || actions) && <div className="panel-h"><h2>{title}</h2><div className="actions">{actions}</div></div>}<div className={pad ? 'panel-b' : ''}>{children}</div></section>;
}

export function DataTable({ cols, rows, rowKey, onRow, selected, search = true, pageSize = 10, empty = 'No resources', placeholder = 'Find resources' }: { cols: { key: string; label: string; render?: (r: any) => ReactNode; text?: (r: any) => string }[]; rows: any[]; rowKey: (r: any) => string; onRow?: (r: any) => void; selected?: string | null; search?: boolean; pageSize?: number; empty?: string; placeholder?: string }) {
  const [q, setQ] = useState(''); const [page, setPage] = useState(1);
  const filtered = useMemo(() => { const s = q.trim().toLowerCase(); return !s ? rows : rows.filter(r => cols.some(c => String(c.text ? c.text(r) : r[c.key] ?? '').toLowerCase().includes(s))); }, [rows, q, cols]);
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize)); const pg = Math.min(page, pages);
  const shown = filtered.slice((pg - 1) * pageSize, pg * pageSize);
  return <div className="dt">
    {search && <div className="dt-bar"><input type="search" aria-label={placeholder} placeholder={placeholder} value={q} onChange={e => { setQ(e.target.value); setPage(1); }} /><span className="muted">{filtered.length} {filtered.length === 1 ? 'match' : 'matches'}</span>
      {pages > 1 && <span className="pager"><button className="btn sm" disabled={pg <= 1} onClick={() => setPage(pg - 1)} aria-label="Previous page">‹</button>{pg} / {pages}<button className="btn sm" disabled={pg >= pages} onClick={() => setPage(pg + 1)} aria-label="Next page">›</button></span>}</div>}
    <div className="dt-scroll"><table><thead><tr>{cols.map(c => <th key={c.key}>{c.label}</th>)}</tr></thead>
      <tbody>{shown.map(r => { const k = rowKey(r); return <tr key={k} className={`${onRow ? 'click' : ''} ${selected === k ? 'sel' : ''}`} tabIndex={onRow ? 0 : undefined} onClick={onRow ? () => onRow(r) : undefined} onKeyDown={onRow ? e => { if (e.key === 'Enter') onRow(r); } : undefined}>{cols.map(c => <td key={c.key}>{c.render ? c.render(r) : String(r[c.key] ?? '—')}</td>)}</tr>; })}
        {!shown.length && <tr><td colSpan={cols.length} className="empty">{q ? 'No matches for this filter' : empty}</td></tr>}</tbody></table></div>
  </div>;
}

export function Modal({ title, children, onClose, footer, wide }: { title: string; children: ReactNode; onClose: () => void; footer?: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => { const prev = document.activeElement as HTMLElement | null; ref.current?.focus(); const k = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); }; window.addEventListener('keydown', k); return () => { window.removeEventListener('keydown', k); prev?.focus?.(); }; }, []);
  return <div className="overlay" onMouseDown={e => { if (e.target === e.currentTarget) onClose(); }}>
    <div className={`modal ${wide ? 'wide' : ''}`} role="dialog" aria-modal="true" aria-label={title} tabIndex={-1} ref={ref}>
      <div className="modal-h"><h2>{title}</h2><button className="x" onClick={onClose} aria-label="Close">×</button></div>
      <div className="modal-b">{children}</div>{footer && <div className="modal-f">{footer}</div>}
    </div></div>;
}

export const Field = ({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) => <label className="field"><span className="field-l">{label}</span>{children}{hint && <span className="field-h">{hint}</span>}</label>;
export const KV = ({ items }: { items: [string, ReactNode][] }) => <dl className="kv">{items.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}</dl>;
export const Empty = ({ title, children }: { title: string; children?: ReactNode }) => <div className="emptystate"><b>{title}</b>{children && <p>{children}</p>}</div>;
export const Note = ({ tone = 'info', children }: { tone?: 'info' | 'warn' | 'ok' | 'bad'; children: ReactNode }) => <div className={`note n-${tone}`} role={tone === 'bad' ? 'alert' : 'note'}>{children}</div>;
export const Link = ({ to, children }: { to: any; children: ReactNode }) => { const { nav } = useLab(); return <a href="#" onClick={e => { e.preventDefault(); e.stopPropagation(); nav(to); }}>{children}</a>; };

/** JSON document viewer/editor with unsaved-change tracking. The server validates and decides; this only catches syntax early. */
export function JsonEditor({ doc, onSave, readOnly, emptyLabel = 'No policy attached', id }: { doc: any; onSave?: (text: string) => Promise<boolean>; readOnly?: boolean; emptyLabel?: string; id: string }) {
  const { setDirty, busy } = useLab();
  const pretty = doc ? JSON.stringify(doc, null, 2) : '';
  const [editing, setEditing] = useState(false); const [text, setText] = useState(pretty); const [err, setErr] = useState('');
  useEffect(() => { if (!editing) setText(pretty); }, [pretty, editing]);
  useEffect(() => () => setDirty(id, false), []);
  const change = (v: string) => { setText(v); setDirty(id, v !== pretty); try { JSON.parse(v); setErr(''); } catch (e: any) { setErr(e.message); } };
  const cancel = () => { setEditing(false); setText(pretty); setErr(''); setDirty(id, false); };
  if (!editing) return <div className="json"><pre tabIndex={0} aria-label="Policy document">{pretty || emptyLabel}</pre>{!readOnly && onSave && <div className="json-actions"><button className="btn" onClick={() => { setEditing(true); if (!pretty) setText('{\n  "Version": "2012-10-17",\n  "Statement": []\n}'); }}>Edit</button></div>}</div>;
  return <div className="json editing">
    <textarea aria-label="Policy JSON editor" spellCheck={false} value={text} onChange={e => change(e.target.value)} rows={Math.min(26, Math.max(10, text.split('\n').length + 1))} />
    {err && <Note tone="warn">JSON syntax: {err}</Note>}
    <div className="json-actions"><span className="muted">{text !== pretty ? 'Unsaved changes' : 'No changes'}</span><button className="btn" onClick={cancel}>Cancel</button>
      <button className="btn primary" disabled={!!err || busy || text === pretty} onClick={async () => { if (await onSave!(text)) { setDirty(id, false); setEditing(false); } }}>Save changes</button></div>
  </div>;
}

export function Spark({ points, threshold }: { points: { t: number; v: number }[]; threshold?: number }) {
  if (!points.length) return <span className="muted">No data</span>;
  const max = Math.max(...points.map(p => p.v), threshold || 0, 1); const w = 160, h = 34, bw = Math.max(3, Math.min(14, w / points.length - 2));
  return <svg className="spark" viewBox={`0 0 ${w} ${h}`} width={w} height={h} role="img" aria-label={`Latest value ${points[points.length - 1].v}`}>
    {points.slice(-12).map((p, i) => <rect key={i} x={i * (bw + 2)} y={h - (p.v / max) * (h - 2)} width={bw} height={Math.max(1, (p.v / max) * (h - 2))} rx="1" />)}
    {threshold !== undefined && <line x1="0" x2={w} y1={h - (threshold / max) * (h - 2)} y2={h - (threshold / max) * (h - 2)} />}
  </svg>;
}
