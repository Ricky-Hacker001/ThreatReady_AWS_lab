// IAM-style policy evaluation for the simulated account. Pure functions, no I/O.
export const ACC = '123456789012';
export const REGION = 'ap-south-1';
export const arn = {
  user: (n: string) => `arn:aws:iam::${ACC}:user/${n}`,
  role: (n: string) => `arn:aws:iam::${ACC}:role/${n}`,
  root: `arn:aws:iam::${ACC}:root`,
  bucket: (b: string) => `arn:aws:s3:::${b}`,
  object: (b: string, k: string) => `arn:aws:s3:::${b}/${k}`,
  key: (id: string) => `arn:aws:kms:${REGION}:${ACC}:key/${id}`,
  secret: (n: string) => `arn:aws:secretsmanager:${REGION}:${ACC}:secret:${n}`,
  fn: (n: string) => `arn:aws:lambda:${REGION}:${ACC}:function:${n}`,
  logGroup: (n: string) => `arn:aws:logs:${REGION}:${ACC}:log-group:${n}:*`,
  trail: (n: string) => `arn:aws:cloudtrail:${REGION}:${ACC}:trail/${n}`,
  sg: (id: string) => `arn:aws:ec2:${REGION}:${ACC}:security-group/${id}`,
  instance: (id: string) => `arn:aws:ec2:${REGION}:${ACC}:instance/${id}`,
};
export const ANON = 'anonymous';

export function glob(pattern: string, value: string, ci = false): boolean {
  const re = '^' + pattern.split('*').map(s => s.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\?/g, '.')).join('.*') + '$';
  return new RegExp(re, ci ? 'i' : '').test(value);
}
const arr = (x: any): any[] => (x === undefined ? [] : Array.isArray(x) ? x : [x]);
export const statements = (doc: any): any[] => (doc ? arr(doc.Statement) : []);

export function validatePolicy(doc: any, kind: 'identity' | 'resource' | 'scp'): string | null {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return 'Policy must be a JSON object.';
  if (JSON.stringify(doc).length > 6000) return 'Policy exceeds the 6,000 character limit.';
  if (doc.Version !== '2012-10-17') return 'Policy must declare "Version": "2012-10-17".';
  if (!Array.isArray(doc.Statement) || doc.Statement.length === 0) return 'Policy must contain a non-empty "Statement" array.';
  if (doc.Statement.length > 20) return 'Too many statements (max 20).';
  for (const [i, s] of doc.Statement.entries()) {
    const at = `Statement[${i}]`;
    if (!s || typeof s !== 'object') return `${at} must be an object.`;
    for (const k of Object.keys(s)) if (!['Sid', 'Effect', 'Action', 'Resource', 'Principal'].includes(k)) return `${at}: unsupported element "${k}" (the simulator supports Sid, Effect, Action, Resource, Principal).`;
    if (s.Effect !== 'Allow' && s.Effect !== 'Deny') return `${at}: "Effect" must be "Allow" or "Deny".`;
    const acts = arr(s.Action);
    if (!acts.length || acts.some(a => typeof a !== 'string' || !/^(\*|[a-z0-9-]+:[A-Za-z0-9*?]+)$/.test(a))) return `${at}: "Action" must be "service:Action" strings (wildcards allowed).`;
    const res = arr(s.Resource);
    if (!res.length || res.some(r => typeof r !== 'string' || !(r === '*' || r.startsWith('arn:')))) return `${at}: "Resource" must be "*" or ARN strings.`;
    if (kind === 'identity' || kind === 'scp') {
      if (s.Principal !== undefined) return `${at}: identity-based policies cannot contain "Principal".`;
    } else {
      const p = s.Principal;
      const ok = p === '*' || (p && typeof p === 'object' && arr(p.AWS).length > 0 && arr(p.AWS).every((x: any) => typeof x === 'string' && (x === '*' || x.startsWith('arn:aws:iam::'))));
      if (!ok) return `${at}: resource policies need "Principal": "*" or {"AWS": "<arn>" | ["<arn>", ...]}.`;
    }
  }
  return null;
}

const matchAR = (s: any, action: string, resource: string) =>
  arr(s.Action).some(a => glob(a, action, true)) && arr(s.Resource).some(r => glob(r, resource));

function matchPrincipal(s: any, principal: string): 'direct' | 'root' | null {
  if (s.Principal === '*') return 'direct';
  const list = arr(s.Principal?.AWS);
  if (list.includes('*')) return principal === ANON ? null : 'direct';
  if (list.includes(principal)) return 'direct';
  if (principal !== ANON && list.includes(arn.root)) return 'root';
  return null;
}

export function identityPolicies(state: any, principal: string): any[] {
  const m = principal.match(/:(user|role)\/(.+)$/);
  if (!m) return [];
  const ent = m[1] === 'user' ? state.iam.users[m[2]] : state.iam.roles[m[2]];
  if (!ent) return [];
  return ent.policies.map((id: string) => state.iam.policies[id]).filter(Boolean);
}

function identityDecision(state: any, principal: string, action: string, resource: string) {
  let allow: string | null = null;
  for (const p of identityPolicies(state, principal))
    for (const s of statements(p.document))
      if (matchAR(s, action, resource)) {
        if (s.Effect === 'Deny') return { deny: p.name, allow: null };
        allow = allow || p.name;
      }
  return { deny: null, allow };
}

function resourceDecision(doc: any, principal: string, action: string, resource: string) {
  let direct = false, root = false, deny = false, pub = false;
  for (const s of statements(doc)) {
    const m = matchPrincipal(s, principal);
    if (!m || !matchAR(s, action, resource)) continue;
    if (s.Effect === 'Deny') deny = true;
    else if (m === 'direct') { direct = true; if (s.Principal === '*' || arr(s.Principal?.AWS).includes('*')) pub = true; }
    else root = true;
  }
  return { direct, root, deny, pub };
}

export function scpDeny(state: any, action: string, resource: string): string | null {
  const acct = state.org.accounts[ACC];
  const targets = [state.org.rootId, acct.parent, ACC];
  for (const scp of Object.values<any>(state.org.scps))
    if (scp.attachedTo.some((t: string) => targets.includes(t)))
      for (const s of statements(scp.document))
        if (s.Effect === 'Deny' && matchAR(s, action, resource)) return scp.name;
  return null;
}

export const isPublicPolicy = (doc: any) =>
  statements(doc).some(s => s.Effect === 'Allow' && (s.Principal === '*' || arr(s.Principal?.AWS).includes('*')));

export interface Decision { allowed: boolean; reason: string }
export interface AuthReq { principal: string; action: string; resource: string; accessKeyId?: string; skipResourcePolicy?: boolean }

export function authorize(state: any, r: AuthReq): Decision {
  const { principal, action, resource } = r;
  const no = (reason: string): Decision => ({ allowed: false, reason });
  const yes = (reason: string): Decision => ({ allowed: true, reason });
  if (r.accessKeyId) {
    const owner = Object.values<any>(state.iam.users).find(u => u.accessKeys.some((k: any) => k.id === r.accessKeyId));
    const key = owner?.accessKeys.find((k: any) => k.id === r.accessKeyId);
    if (!key || key.status !== 'Active') return no(`InvalidAccessKeyId: access key ${r.accessKeyId} is inactive or does not exist`);
    if (arn.user(owner.name) !== principal) return no('SignatureDoesNotMatch: access key does not belong to this principal');
  }
  if (principal !== ANON) {
    const m = principal.match(/:(user|role)\/(.+)$/);
    if (!m || !(m[1] === 'user' ? state.iam.users[m[2]] : state.iam.roles[m[2]])) return no('Principal does not exist');
    const scp = scpDeny(state, action, resource);
    if (scp) return no(`Explicit deny in service control policy "${scp}"`);
  }
  const id = principal === ANON ? { deny: null, allow: null } : identityDecision(state, principal, action, resource);
  if (id.deny) return no(`Explicit deny in identity policy "${id.deny}"`);
  if (r.skipResourcePolicy) return id.allow ? yes(`Allowed by identity policy "${id.allow}"`) : no('Implicit deny: no identity policy allows this action');

  if (resource.startsWith('arn:aws:s3:::')) {
    const [bucketName, ...rest] = resource.slice('arn:aws:s3:::'.length).split('/');
    const key = rest.join('/');
    const b = state.s3.buckets[bucketName];
    if (!b) return no('NoSuchBucket');
    const rd = resourceDecision(b.policy, principal, action, resource);
    if (rd.deny) return no('Explicit deny in bucket policy');
    if (principal === ANON) {
      if (rd.direct && !b.blockPublicAccess.restrictPublicBuckets) return yes('Bucket policy grants access to everyone (Principal "*")');
      const obj = b.objects.find((o: any) => o.key === key);
      if (action === 's3:GetObject' && obj?.acl === 'public-read' && !b.blockPublicAccess.ignorePublicAcls) return yes('Object ACL grants public-read');
      return no(rd.direct ? 'Blocked by S3 Block Public Access (RestrictPublicBuckets)' : 'AccessDenied: no policy or ACL grants anonymous access');
    }
    if (id.allow) return yes(`Allowed by identity policy "${id.allow}"`);
    if (rd.direct && !(rd.pub && b.blockPublicAccess.restrictPublicBuckets)) return yes('Allowed by bucket policy');
    return no('Implicit deny: no identity or bucket policy allows this action');
  }
  if (resource.startsWith(`arn:aws:kms:`)) {
    const k = state.kms.keys[resource.split('/').pop()!];
    if (!k) return no('NotFoundException: key does not exist');
    if (k.state !== 'Enabled') return no('KMSInvalidStateException: key is not enabled');
    const rd = resourceDecision(k.policy, principal, action, resource);
    if (rd.deny) return no('Explicit deny in key policy');
    if (rd.direct) return yes('Allowed directly by the key policy');
    if (rd.root && id.allow) return yes(`Allowed by identity policy "${id.allow}" (key policy delegates to IAM via the account root principal)`);
    if (rd.root) return no('Key policy delegates to IAM, but no identity policy allows this action');
    return no('Implicit deny: the key policy does not grant this principal access');
  }
  if (principal === ANON) return no('AccessDenied: anonymous requests are not permitted');
  return id.allow ? yes(`Allowed by identity policy "${id.allow}"`) : no('Implicit deny: no identity policy allows this action');
}

// IPv4 helpers for security-group reachability
const ipNum = (ip: string) => ip.split('.').reduce((a, o) => a * 256 + Number(o), 0);
export function validCidr(c: string) {
  const m = c.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
  return !!m && m.slice(1, 5).every(o => Number(o) <= 255) && Number(m[5]) <= 32;
}
export function cidrContains(cidr: string, ip: string) {
  const [base, bitsS] = cidr.split('/'); const bits = Number(bitsS);
  if (bits === 0) return true;
  const size = 2 ** (32 - bits);
  return Math.floor(ipNum(base) / size) === Math.floor(ipNum(ip) / size);
}
export function cidrWithin(inner: string, outer: string) {
  const [ib, ibits] = inner.split('/'); const [, obits] = outer.split('/');
  return Number(ibits) >= Number(obits) && cidrContains(outer, ib);
}
