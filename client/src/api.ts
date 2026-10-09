const LS = { get: (k: string) => { try { return localStorage.getItem(k); } catch { return null; } }, set: (k: string, v: string | null) => { try { v === null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch { /* ignore */ } } };
export const store = LS;
let token = LS.get('tr_token');
export const hasToken = () => !!token;
export const setToken = (t: string | null) => { token = t; LS.set('tr_token', t); };
let onConn: (ok: boolean) => void = () => {};
export const onConnection = (f: (ok: boolean) => void) => { onConn = f; };
export class ApiError extends Error { constructor(public status: number, message: string) { super(message); } }

export async function api(path: string, body?: any, method?: string): Promise<any> {
  let res: Response;
  try {
    res = await fetch(`/api${path}`, { method: method || (body !== undefined ? 'POST' : 'GET'), headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  } catch { onConn(false); throw new ApiError(0, 'Cannot reach the lab server. Check your connection and retry.'); }
  onConn(true);
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, json.error || `Request failed (${res.status})`);
  return json;
}
export const newRequestId = () => (crypto.randomUUID ? crypto.randomUUID() : `r-${Date.now()}-${Math.random().toString(36).slice(2, 12)}`);

const ACC = '123456789012', R = 'ap-south-1';
export const arn = {
  user: (n: string) => `arn:aws:iam::${ACC}:user/${n}`, role: (n: string) => `arn:aws:iam::${ACC}:role/${n}`,
  bucket: (b: string) => `arn:aws:s3:::${b}`, key: (id: string) => `arn:aws:kms:${R}:${ACC}:key/${id}`,
  secret: (n: string) => `arn:aws:secretsmanager:${R}:${ACC}:secret:${n}`, fn: (n: string) => `arn:aws:lambda:${R}:${ACC}:function:${n}`,
  logGroup: (n: string) => `arn:aws:logs:${R}:${ACC}:log-group:${n}:*`, trail: (n: string) => `arn:aws:cloudtrail:${R}:${ACC}:trail/${n}`,
};
export const fmt = (iso?: string | null) => { if (!iso) return '—'; const d = new Date(iso); if (isNaN(+d)) return iso; return d.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false }) + ' IST'; };
