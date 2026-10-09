// Deterministic simulation helpers shared by handlers, verification and health probes.
import { arn, authorize, ANON, cidrContains, Decision } from './policy';
import { SG_ALB, SG_APP, I_APP, KEY_APP, FN, ATTACKER_IP } from './fixture';

export const SOURCES: Record<string, { label: string; ip: string; sgs: string[]; external: boolean }> = {
  internet: { label: 'Internet (198.51.100.77)', ip: ATTACKER_IP, sgs: [], external: true },
  'office-vpn': { label: 'Office VPN (203.0.113.10)', ip: '203.0.113.10', sgs: [], external: true },
  alb: { label: 'nc-storefront-alb', ip: '10.0.1.10', sgs: [SG_ALB], external: false },
  'app-server': { label: 'nc-app-server', ip: '10.0.1.25', sgs: [SG_APP], external: false },
};

export function reach(state: any, source: string, target: string, port: number): Decision {
  const src = SOURCES[source];
  if (!src) return { allowed: false, reason: 'Unknown source' };
  let sgs: string[]; let isPublic: boolean; let label: string;
  if (target === 'alb') { const lb = state.ec2.loadBalancers['nc-storefront-alb']; sgs = lb.securityGroups; isPublic = true; label = lb.name; }
  else {
    const i = state.ec2.instances[target];
    if (!i) return { allowed: false, reason: 'Unknown target' };
    if (i.state !== 'running') return { allowed: false, reason: `${i.name} is ${i.state}` };
    sgs = i.securityGroups; isPublic = !!i.publicIp; label = i.name;
  }
  if (src.external && !isPublic) return { allowed: false, reason: `${label} has no public IP and sits in a private subnet — no route from the internet` };
  for (const id of sgs) for (const r of state.ec2.securityGroups[id].inbound) {
    if (r.port !== port || r.protocol !== 'tcp') continue;
    if (r.source.startsWith('sg-') ? src.sgs.includes(r.source) : cidrContains(r.source, src.ip))
      return { allowed: true, reason: `Allowed by ${state.ec2.securityGroups[id].name} rule ${r.id} (tcp/${r.port} from ${r.source})` };
  }
  return { allowed: false, reason: `No inbound rule on ${sgs.map(s => state.ec2.securityGroups[s].name).join(', ')} permits tcp/${port} from ${src.label}` };
}

export function internetExposure(state: any) {
  const out: any[] = [];
  for (const i of Object.values<any>(state.ec2.instances)) {
    const ports = new Set<number>();
    for (const id of i.securityGroups) for (const r of state.ec2.securityGroups[id].inbound) if (reach(state, 'internet', i.id, r.port).allowed) ports.add(r.port);
    out.push({ target: i.id, name: i.name, ports: [...ports].sort((a, b) => a - b) });
  }
  return out;
}

export function s3Access(state: any, q: { principal: string; operation: 'GET' | 'PUT'; bucket: string; key: string; accessKeyId?: string }): Decision & { encryption?: string; preview?: string } {
  const b = state.s3.buckets[q.bucket];
  if (!b) return { allowed: false, reason: 'NoSuchBucket' };
  const action = q.operation === 'GET' ? 's3:GetObject' : 's3:PutObject';
  const d = authorize(state, { principal: q.principal, action, resource: arn.object(q.bucket, q.key), accessKeyId: q.accessKeyId });
  if (!d.allowed) return d;
  if (q.operation === 'GET') {
    const o = b.objects.find((x: any) => x.key === q.key);
    if (!o) return { allowed: false, reason: 'NoSuchKey: the object does not exist (the request was authorized)' };
    if (o.encryption === 'SSE-KMS') {
      if (q.principal === ANON) return { allowed: false, reason: 'Object is SSE-KMS encrypted; anonymous requests cannot use the KMS key' };
      const k = authorize(state, { principal: q.principal, action: 'kms:Decrypt', resource: arn.key(o.keyId) });
      if (!k.allowed) return { allowed: false, reason: `S3 authorized the read, but kms:Decrypt failed — ${k.reason}` };
    }
    return { ...d, encryption: o.encryption, preview: o.preview };
  }
  if (b.encryption.mode === 'SSE-KMS') {
    if (q.principal === ANON) return { allowed: false, reason: 'Bucket requires SSE-KMS; anonymous requests cannot use the KMS key' };
    const k = authorize(state, { principal: q.principal, action: 'kms:GenerateDataKey', resource: arn.key(b.encryption.keyId) });
    if (!k.allowed) return { allowed: false, reason: `S3 authorized the write, but kms:GenerateDataKey failed — ${k.reason}` };
  }
  return { ...d, encryption: b.encryption.mode };
}

export function findSecretByRef(state: any, ref: string) {
  if (!ref) return null;
  const name = ref.startsWith('arn:') ? ref.split(':secret:')[1] : ref;
  return state.secrets.secrets[name] || null;
}
export const currentValue = (s: any) => s.versions.find((v: any) => v.stage === 'AWSCURRENT')?.value;

export function lambdaRun(state: any, name: string) {
  const f = state.lambda.functions[name];
  const role = arn.role(f.role);
  const logs: string[] = ['START RequestId: sim-test-event'];
  const fail = (msg: string) => { logs.push(`ERROR ${msg}`, 'END RequestId: sim-test-event'); return { ok: false, error: msg, logs, usedSecret: null as string | null }; };
  for (const a of ['logs:CreateLogStream', 'logs:PutLogEvents']) {
    const d = authorize(state, { principal: role, action: a, resource: arn.logGroup(`/aws/lambda/${name}`) });
    if (!d.allowed) return fail(`AccessDenied: ${f.role} is not authorized to perform ${a} — ${d.reason}`);
  }
  let cred: string; let usedSecret: string | null = null;
  if (f.env.PAYMENT_GATEWAY_KEY) { cred = f.env.PAYMENT_GATEWAY_KEY; logs.push('INFO loading payment credential from process.env.PAYMENT_GATEWAY_KEY'); }
  else if (f.env.PAYMENT_SECRET_ARN) {
    const s = findSecretByRef(state, f.env.PAYMENT_SECRET_ARN);
    if (!s) return fail(`ResourceNotFoundException: secret ${f.env.PAYMENT_SECRET_ARN} not found`);
    const d = authorize(state, { principal: role, action: 'secretsmanager:GetSecretValue', resource: arn.secret(s.name) });
    if (!d.allowed) return fail(`AccessDenied: ${f.role} is not authorized to perform secretsmanager:GetSecretValue on ${s.name} — ${d.reason}`);
    cred = currentValue(s); usedSecret = s.name; logs.push(`INFO loaded payment credential from Secrets Manager (${s.name})`);
  } else return fail('ConfigError: no payment credential configured (expected PAYMENT_SECRET_ARN)');
  if (cred !== state.gateway.current) return fail('PaymentGatewayError: 401 Unauthorized — credential rejected');
  logs.push('INFO gateway auth ok');
  const put = authorize(state, { principal: role, action: 's3:PutObject', resource: arn.object(f.env.EXPORT_BUCKET || 'novacart-order-exports', 'exports/test-event.json') });
  if (!put.allowed) return fail(`AccessDenied: ${f.role} is not authorized to perform s3:PutObject on the export bucket — ${put.reason}`);
  logs.push('INFO s3:PutObject novacart-order-exports/exports/test-event.json', 'END RequestId: sim-test-event');
  return { ok: true, error: null as string | null, logs, usedSecret };
}

export function health(state: any) {
  const probes: any[] = [];
  const add = (id: string, label: string, ok: boolean, detail: string) => probes.push({ id, label, ok, detail });
  const a = reach(state, 'internet', 'alb', 443), b = reach(state, 'alb', I_APP, 8080);
  add('storefront', 'Storefront reachable (customers → ALB → app)', a.allowed && b.allowed, !a.allowed ? a.reason : b.reason);
  const img = s3Access(state, { principal: ANON, operation: 'GET', bucket: 'novacart-product-assets', key: 'public/logo.png' });
  add('catalog-images', 'Public catalog images load', img.allowed, img.reason);
  const up = s3Access(state, { principal: arn.user('svc-storefront-app'), operation: 'PUT', bucket: 'novacart-product-assets', key: 'uploads/health.jpg', accessKeyId: KEY_APP });
  add('asset-upload', 'Storefront app can upload product assets', up.allowed, up.reason);
  const inv = s3Access(state, { principal: arn.role('nc-app-server-role'), operation: 'PUT', bucket: 'novacart-internal-docs', key: 'invoices/health.json' });
  add('invoices', 'App server can write invoices', inv.allowed, inv.reason);
  const run = lambdaRun(state, FN);
  add('orders', 'Order processor charges and exports', run.ok, run.error || 'OK');
  return probes;
}
