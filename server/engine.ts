// Server-authoritative lab engine for TR-CLOUD-001. The browser never decides state, findings or objectives.
import { ACC, arn, authorize, ANON, validatePolicy, validCidr, isPublicPolicy, statements } from './policy';
import * as fx from './fixture';
import { reach, s3Access, lambdaRun, health, internetExposure, currentValue, SOURCES } from './sim';
import { FINDINGS, FINDING, OBJECTIVES, OBJECTIVE, ALERTS, TRIAGE_OPTIONS, REPORT_FORM, scoreReport, CHAPTERS, ATTACKER_STEPS, contained, goodAlarm } from './scenario';

export class LabError extends Error { constructor(public code: string, message: string) { super(message); } }
export interface LabAction { type: string; params?: any }
export interface ActionResult { ok: boolean; code?: string; message: string; result?: any }
export interface LabEngine {
  labId: string; title: string;
  definition(): any;
  createInitialState(): any;
  dispatch(state: any, action: LabAction): { state: any; result: ActionResult };
  view(state: any): any;
  status(state: any): any;
  report(state: any, meta: any): any;
}

const LEARNER = arn.role('ThreatReady-SecurityAnalyst');
const bad = (msg: string): never => { throw new LabError('ValidationError', msg); };
const str = (v: any, name: string, max = 200, re?: RegExp): string => { if (typeof v !== 'string' || !v.length || v.length > max || (re && !re.test(v))) bad(`Invalid value for "${name}".`); return v; };
const oneOf = <T>(v: any, opts: readonly T[], name: string): T => { if (!opts.includes(v)) bad(`"${name}" must be one of: ${opts.join(', ')}.`); return v; };
const int = (v: any, name: string, min: number, max: number): number => { if (!Number.isInteger(v) || v < min || v > max) bad(`"${name}" must be an integer between ${min} and ${max}.`); return v; };
const bool = (v: any, name: string): boolean => { if (typeof v !== 'boolean') bad(`"${name}" must be true or false.`); return v; };
const get = <T>(m: Record<string, T>, k: any, what: string): T => { if (typeof k !== 'string' || !Object.prototype.hasOwnProperty.call(m, k)) throw new LabError('NotFound', `${what} not found.`); return m[k]; };
const clone = <T>(x: T): T => structuredClone(x);

export const simTime = (s: any) => new Date(new Date(s.clock.start).getTime() + s.clock.minutes * 60000).toISOString();
const timeline = (s: any, kind: 'story' | 'good' | 'bad' | 'warn' | 'info', text: string) => s.sim.timeline.push({ at: simTime(s), kind, text });

function trailCovers(s: any, readOnly: boolean, region: string) {
  return Object.values<any>(s.cloudtrail.trails).some(t => t.logging && (region === t.homeRegion || t.multiRegion) && (t.managementEvents === 'All' || t.managementEvents === (readOnly ? 'ReadOnly' : 'WriteOnly')));
}
function recordTrail(s: any, e: { name: string; source: string; actor: string; resource?: string; ip?: string; region?: string; outcome?: string; accessKeyId?: string | null; readOnly?: boolean }) {
  const readOnly = e.readOnly ?? /^(Get|List|Describe|Lookup|Simulate)/.test(e.name);
  const region = e.region || 'ap-south-1';
  if (!trailCovers(s, readOnly, region)) return null;
  const id = `evt-${String(++s.cloudtrail.seq).padStart(4, '0')}`;
  s.cloudtrail.events.push({ id, time: simTime(s), name: e.name, source: e.source, actor: e.actor, sourceIp: e.ip || '203.0.113.50', resource: e.resource || '-', region, outcome: e.outcome || 'Success', readOnly, accessKeyId: e.accessKeyId || null, userAgent: e.actor.startsWith('ThreatReady') ? 'threatready-console' : 'python-requests/2.31' });
  return id;
}
function learnerAuth(s: any, action: string, resource: string, trail?: { name: string; source: string; resource?: string }) {
  const d = authorize(s, { principal: LEARNER, action, resource, skipResourcePolicy: true });
  if (!d.allowed) throw new LabError('AccessDenied', `User: ${LEARNER} is not authorized to perform: ${action} on resource: ${resource} — ${d.reason}`);
  if (trail) recordTrail(s, { ...trail, actor: 'ThreatReady-SecurityAnalyst' });
}
function pushMetric(s: any, metric: string, v: number): string[] {
  const def = s.cloudwatch.metricDefs.find((m: any) => m.name === metric);
  if (def.source === 'cloudtrail' && !Object.values<any>(s.cloudtrail.trails).some(t => t.logging)) return [];
  s.cloudwatch.metrics[metric].push({ t: s.clock.minutes, v });
  if (s.cloudwatch.metrics[metric].length > 60) s.cloudwatch.metrics[metric].shift();
  const fired: string[] = [];
  for (const a of Object.values<any>(s.cloudwatch.alarms)) {
    if (a.metric !== metric) continue;
    const hit = a.comparison === '>=' ? v >= a.threshold : a.comparison === '>' ? v > a.threshold : a.comparison === '<=' ? v <= a.threshold : v < a.threshold;
    const next = hit ? 'ALARM' : 'OK';
    if (next !== a.state) {
      a.history.push({ at: simTime(s), from: a.state, to: next, value: v }); a.state = next;
      if (next === 'ALARM') { fired.push(a.name); if (a.topic) s.cloudwatch.notifications.push({ at: simTime(s), topic: a.topic, alarm: a.name, message: `ALARM: "${a.name}" — ${metric} = ${v} ${a.comparison} ${a.threshold}` }); }
    }
  }
  return fired;
}
function recordTest(s: any, t: any) {
  s.sim.tests.push({ ...t, at: simTime(s) }); if (s.sim.tests.length > 100) s.sim.tests.shift();
  for (const f of FINDINGS) if (f.remediated(s)) for (const c of f.checks) if (c.match(t, s)) s.sim.checks[c.id] = true;
  if (t.kind === 's3.access' && t.accessKeyId === fx.KEY_OLD && !t.allowed && /InvalidAccessKeyId/.test(t.reason) && contained(s)) s.sim.checks['L2.replay'] = true;
}
const principalArg = (s: any, v: any, allowAnon = false) => {
  str(v, 'principal', 120);
  if (allowAnon && v === ANON) return v;
  const m = v.match(/^arn:aws:iam::123456789012:(user|role)\/([\w+=,.@-]+)$/);
  if (!m || !(m[1] === 'user' ? s.iam.users[m[2]] : s.iam.roles[m[2]])) bad('Unknown principal.');
  return v as string;
};
const parseDoc = (d: any) => { if (typeof d === 'string') { if (d.length > 8000) bad('Document too large.'); try { return JSON.parse(d); } catch (e: any) { throw new LabError('MalformedPolicyDocument', `Syntax error: ${e.message}`); } } return d; };

type Ctx = { s: any; p: any };
type Handler = { kind: 'change' | 'test' | 'inspect' | 'meta'; run: (c: Ctx) => { message: string; result?: any } };
const denied = (action: string, res: (p: any) => string): Handler => ({ kind: 'change', run: ({ s, p }) => { learnerAuth(s, action, res(p)); throw new LabError('NotSupported', 'This operation is not available in the simulation.'); } });

const H: Record<string, Handler> = {
  'incident.acknowledge': { kind: 'meta', run: ({ s }) => { if (s.incident.acknowledged) return { message: 'Ticket already acknowledged.' }; s.incident.acknowledged = true; s.incident.status = 'Investigating'; timeline(s, 'info', 'Ticket INC-2041 acknowledged by the analyst.'); return { message: 'INC-2041 acknowledged. You are the assigned analyst.' }; } },
  'inspect': { kind: 'inspect', run: ({ s, p }) => { const k = str(p.key, 'key', 160, /^[\w./$\[\]#:@ -]+$/); if (!s.sim.inspected[k] && Object.keys(s.sim.inspected).length < 400) s.sim.inspected[k] = simTime(s); return { message: 'ok' }; } },
  'finding.report': { kind: 'meta', run: ({ s, p }) => {
    const f = get(FINDING, p.findingId, 'Finding'); const resource = str(p.resource, 'resource', 160);
    const fs = s.sim.findings[f.id];
    if (fs.discovered) return { message: `${f.title} is already recorded.` };
    if (!f.resources.includes(resource)) { s.sim.wrongReports++; throw new LabError('NotSupportedByEvidence', 'The configuration of this resource does not support that finding. Review the evidence and try again.'); }
    if (!f.inspect.some(k => s.sim.inspected[k])) throw new LabError('EvidenceRequired', 'Inspect the relevant configuration of this resource before reporting a finding on it.');
    fs.discovered = true; fs.discoveredAt = simTime(s); fs.resource = resource;
    timeline(s, 'good', `Finding recorded: ${f.title} (${f.id}).`);
    return { message: `Finding ${f.id} recorded: ${f.title}.` };
  } },
  'evidence.add': { kind: 'meta', run: ({ s, p }) => { const id = str(p.eventId, 'eventId', 20); if (!s.cloudtrail.events.some((e: any) => e.id === id)) throw new LabError('NotFound', 'Event not found.'); if (s.sim.evidence.includes(id)) return { message: 'Event is already in the evidence locker.' }; if (s.sim.evidence.length >= 20) bad('The evidence locker holds at most 20 events. Remove one first.'); s.sim.evidence.push(id); return { message: `Event ${id} preserved in the evidence locker.` }; } },
  'evidence.remove': { kind: 'meta', run: ({ s, p }) => { s.sim.evidence = s.sim.evidence.filter((e: string) => e !== p.eventId); return { message: 'Event removed from the evidence locker.' }; } },
  'incident.declareCompromisedKey': { kind: 'meta', run: ({ s, p }) => {
    if (s.level < 2) throw new LabError('PreconditionFailed', 'No active incident alert yet — complete the Level 1 investigation first.');
    const id = str(p.accessKeyId, 'accessKeyId', 40);
    if (!Object.values<any>(s.iam.users).some(u => u.accessKeys.some((k: any) => k.id === id))) throw new LabError('NotFound', 'Access key not found.');
    if (id !== fx.KEY_OLD) throw new LabError('NotSupportedByEvidence', 'The audit evidence does not show hostile use of that key. Check source IPs and user agents.');
    s.incident.declaredKey = id; timeline(s, 'good', `Compromised credential identified: ${id}.`);
    return { message: `Recorded ${id} as the compromised credential.` };
  } },
  'hint.request': { kind: 'meta', run: ({ s, p }) => {
    const o = get(OBJECTIVE, p.objectiveId, 'Objective');
    if (o.level > s.level) throw new LabError('PreconditionFailed', 'This objective is not unlocked yet.');
    const n = s.sim.hints[o.id] || 0;
    if (n >= o.hints.length) return { message: 'No further hints for this objective.' };
    s.sim.hints[o.id] = n + 1; return { message: 'Hint revealed.', result: { hint: o.hints[n] } };
  } },

  // ---------- IAM ----------
  'iam.updatePolicy': { kind: 'change', run: ({ s, p }) => {
    const pol = get<any>(s.iam.policies, p.policyId, 'Policy');
    if (pol.protected) throw new LabError('AccessDenied', `${pol.name} is ${pol.type === 'AWS managed' ? 'an AWS managed policy' : 'protected in this simulation'} and cannot be edited.`);
    const doc = parseDoc(p.document); const err = validatePolicy(doc, 'identity'); if (err) throw new LabError('MalformedPolicyDocument', err);
    learnerAuth(s, 'iam:CreatePolicyVersion', `arn:aws:iam::${ACC}:policy/${pol.name}`, { name: 'CreatePolicyVersion', source: 'iam', resource: pol.name });
    pol.versions.forEach((v: any) => (v.isDefault = false));
    const id = `v${Number(pol.versions[pol.versions.length - 1].id.slice(1)) + 1}`;
    pol.versions.push({ id, document: doc, createdAt: simTime(s), by: 'ThreatReady-SecurityAnalyst', isDefault: true });
    if (pol.versions.length > 5) pol.versions.shift();
    pol.document = doc;
    return { message: `Policy ${pol.name} updated — version ${id} is now the default.` };
  } },
  'iam.restorePolicyVersion': { kind: 'change', run: ({ s, p }) => {
    const pol = get<any>(s.iam.policies, p.policyId, 'Policy'); if (pol.protected) throw new LabError('AccessDenied', `${pol.name} cannot be modified.`);
    const v = pol.versions.find((x: any) => x.id === p.versionId); if (!v) throw new LabError('NotFound', 'Policy version not found.');
    learnerAuth(s, 'iam:SetDefaultPolicyVersion', `arn:aws:iam::${ACC}:policy/${pol.name}`, { name: 'SetDefaultPolicyVersion', source: 'iam', resource: pol.name });
    pol.versions.forEach((x: any) => (x.isDefault = x.id === v.id)); pol.document = clone(v.document);
    return { message: `Version ${v.id} of ${pol.name} is now the default.` };
  } },
  'iam.setAccessKeyStatus': { kind: 'change', run: ({ s, p }) => {
    const u = get<any>(s.iam.users, p.userName, 'User'); const k = u.accessKeys.find((x: any) => x.id === p.accessKeyId); if (!k) throw new LabError('NotFound', 'Access key not found.');
    const status = oneOf(p.status, ['Active', 'Inactive'] as const, 'status');
    learnerAuth(s, 'iam:UpdateAccessKey', u.arn, { name: 'UpdateAccessKey', source: 'iam', resource: `${u.name}/${k.id}` });
    if (k.status === status) return { message: `Access key ${k.id} is already ${status}.` };
    k.status = status; return { message: `Access key ${k.id} is now ${status}.` };
  } },
  'iam.simulate': { kind: 'test', run: ({ s, p }) => {
    const principal = principalArg(s, p.principal); const action = str(p.action, 'action', 80, /^[a-z0-9-]+:[A-Za-z0-9]+$/); const resource = str(p.resource, 'resource', 200, /^(\*|arn:[\w:/*.$\[\]@+=,-]+)$/);
    const d = authorize(s, { principal, action, resource, skipResourcePolicy: true });
    recordTest(s, { kind: 'iam.simulate', principal, action, resource, ...d });
    return { message: `${d.allowed ? 'allowed' : 'denied'} — ${d.reason}`, result: { ...d, principal, action, resource } };
  } },
  'iam.deleteUser': denied('iam:DeleteUser', p => arn.user(String(p.userName))),
  'iam.deleteRole': denied('iam:DeleteRole', p => arn.role(String(p.roleName))),

  // ---------- S3 ----------
  's3.putPublicAccessBlock': { kind: 'change', run: ({ s, p }) => {
    const b = get<any>(s.s3.buckets, p.bucket, 'Bucket'); const c = p.config || {};
    const next = { blockPublicAcls: bool(c.blockPublicAcls, 'blockPublicAcls'), ignorePublicAcls: bool(c.ignorePublicAcls, 'ignorePublicAcls'), blockPublicPolicy: bool(c.blockPublicPolicy, 'blockPublicPolicy'), restrictPublicBuckets: bool(c.restrictPublicBuckets, 'restrictPublicBuckets') };
    learnerAuth(s, 's3:PutBucketPublicAccessBlock', arn.bucket(b.name), { name: 'PutBucketPublicAccessBlock', source: 's3', resource: b.name });
    b.blockPublicAccess = next; return { message: `Block Public Access settings updated for ${b.name}.` };
  } },
  's3.putBucketPolicy': { kind: 'change', run: ({ s, p }) => {
    const b = get<any>(s.s3.buckets, p.bucket, 'Bucket');
    if (p.document === null) { learnerAuth(s, 's3:DeleteBucketPolicy', arn.bucket(b.name), { name: 'DeleteBucketPolicy', source: 's3', resource: b.name }); b.policy = null; return { message: `Bucket policy deleted from ${b.name}.` }; }
    const doc = parseDoc(p.document); const err = validatePolicy(doc, 'resource'); if (err) throw new LabError('MalformedPolicy', err);
    for (const st of statements(doc)) for (const r of [st.Resource].flat()) if (!(r === arn.bucket(b.name) || r.startsWith(arn.bucket(b.name) + '/'))) throw new LabError('MalformedPolicy', `Policy has invalid resource: ${r} (must be this bucket or its objects).`);
    if (isPublicPolicy(doc) && b.blockPublicAccess.blockPublicPolicy) throw new LabError('AccessDenied', 'Public policies are blocked by the BlockPublicPolicy setting on this bucket.');
    learnerAuth(s, 's3:PutBucketPolicy', arn.bucket(b.name), { name: 'PutBucketPolicy', source: 's3', resource: b.name });
    b.policy = doc; return { message: `Bucket policy saved for ${b.name}.` };
  } },
  's3.putObjectAcl': { kind: 'change', run: ({ s, p }) => {
    const b = get<any>(s.s3.buckets, p.bucket, 'Bucket'); const o = b.objects.find((x: any) => x.key === p.key); if (!o) throw new LabError('NotFound', 'Object not found.');
    const acl = oneOf(p.acl, ['private', 'public-read'] as const, 'acl');
    if (acl === 'public-read' && b.blockPublicAccess.blockPublicAcls) throw new LabError('AccessDenied', 'Public ACLs are blocked by the BlockPublicAcls setting on this bucket.');
    learnerAuth(s, 's3:PutObjectAcl', arn.object(b.name, o.key), { name: 'PutObjectAcl', source: 's3', resource: `${b.name}/${o.key}` });
    o.acl = acl; return { message: `ACL of ${o.key} set to ${acl}.` };
  } },
  's3.putEncryption': { kind: 'change', run: ({ s, p }) => {
    const b = get<any>(s.s3.buckets, p.bucket, 'Bucket'); const mode = oneOf(p.mode, ['SSE-S3', 'SSE-KMS'] as const, 'mode');
    let keyId = null; if (mode === 'SSE-KMS') { keyId = get<any>(s.kms.keys, p.keyId, 'KMS key').id; }
    learnerAuth(s, 's3:PutEncryptionConfiguration', arn.bucket(b.name), { name: 'PutBucketEncryption', source: 's3', resource: b.name });
    b.encryption = { mode, keyId };
    return { message: `Default encryption for ${b.name} set to ${mode}. This applies to new objects only; existing objects are unchanged.` };
  } },
  's3.reencryptObjects': { kind: 'change', run: ({ s, p }) => {
    const b = get<any>(s.s3.buckets, p.bucket, 'Bucket');
    if (b.encryption.mode === 'None') throw new LabError('PreconditionFailed', 'Configure default encryption before re-encrypting existing objects.');
    if (b.encryption.mode === 'SSE-KMS' && s.kms.keys[b.encryption.keyId].state !== 'Enabled') throw new LabError('KMSInvalidStateException', 'The KMS key is not enabled.');
    learnerAuth(s, 's3:PutObject', arn.object(b.name, '*'), { name: 'CopyObject', source: 's3', resource: b.name });
    let n = 0; for (const o of b.objects) if (o.encryption !== b.encryption.mode || o.keyId !== b.encryption.keyId) { o.encryption = b.encryption.mode; o.keyId = b.encryption.keyId; o.lastModified = simTime(s); n++; }
    return { message: `Batch copy complete: ${n} object(s) re-written with ${b.encryption.mode}.` };
  } },
  's3.accessTest': { kind: 'test', run: ({ s, p }) => {
    const b = get<any>(s.s3.buckets, p.bucket, 'Bucket'); const principal = principalArg(s, p.principal, true); const operation = oneOf(p.operation, ['GET', 'PUT'] as const, 'operation');
    const key = str(p.key, 'key', 200, /^[\w./ -]+$/); const accessKeyId = p.accessKeyId ? str(p.accessKeyId, 'accessKeyId', 40) : undefined;
    if (accessKeyId && principal === ANON) bad('Anonymous requests are unsigned.');
    const d = s3Access(s, { principal, operation, bucket: b.name, key, accessKeyId });
    recordTest(s, { kind: 's3.access', bucket: b.name, key, principal, operation, accessKeyId, allowed: d.allowed, reason: d.reason, encryption: d.encryption });
    return { message: `${operation} ${b.name}/${key}: ${d.allowed ? '200 OK' : '403/4xx'} — ${d.reason}`, result: d };
  } },
  's3.deleteBucket': denied('s3:DeleteBucket', p => arn.bucket(String(p.bucket))),

  // ---------- EC2 ----------
  'ec2.addIngressRule': { kind: 'change', run: ({ s, p }) => {
    const g = get<any>(s.ec2.securityGroups, p.groupId, 'Security group'); const rule = sgRule(s, p);
    if (g.inbound.some((r: any) => r.port === rule.port && r.source === rule.source)) throw new LabError('InvalidPermission.Duplicate', 'The specified rule already exists.');
    if (g.inbound.length >= 12) bad('Rule limit reached for this simulated security group.');
    learnerAuth(s, 'ec2:AuthorizeSecurityGroupIngress', arn.sg(g.id), { name: 'AuthorizeSecurityGroupIngress', source: 'ec2', resource: g.id });
    g.inbound.push({ id: `sgr-n${s.rev + 1}`, ...rule }); return { message: `Inbound rule added to ${g.name}.` };
  } },
  'ec2.updateIngressRule': { kind: 'change', run: ({ s, p }) => {
    const g = get<any>(s.ec2.securityGroups, p.groupId, 'Security group'); const r = g.inbound.find((x: any) => x.id === p.ruleId); if (!r) throw new LabError('NotFound', 'Rule not found.');
    const rule = sgRule(s, p);
    if (g.inbound.some((x: any) => x !== r && x.port === rule.port && x.source === rule.source)) throw new LabError('InvalidPermission.Duplicate', 'The specified rule already exists.');
    learnerAuth(s, 'ec2:AuthorizeSecurityGroupIngress', arn.sg(g.id), { name: 'ModifySecurityGroupRules', source: 'ec2', resource: g.id });
    Object.assign(r, rule); return { message: `Rule ${r.id} updated on ${g.name}.` };
  } },
  'ec2.removeIngressRule': { kind: 'change', run: ({ s, p }) => {
    const g = get<any>(s.ec2.securityGroups, p.groupId, 'Security group'); const i = g.inbound.findIndex((x: any) => x.id === p.ruleId); if (i < 0) throw new LabError('NotFound', 'Rule not found — it may already have been removed.');
    learnerAuth(s, 'ec2:RevokeSecurityGroupIngress', arn.sg(g.id), { name: 'RevokeSecurityGroupIngress', source: 'ec2', resource: g.id });
    g.inbound.splice(i, 1); return { message: `Inbound rule removed from ${g.name}.` };
  } },
  'ec2.reachabilityTest': { kind: 'test', run: ({ s, p }) => {
    const source = oneOf(p.source, Object.keys(SOURCES), 'source'); const target = p.target === 'alb' ? 'alb' : get<any>(s.ec2.instances, p.target, 'Target').id; const port = int(p.port, 'port', 1, 65535);
    const d = reach(s, source, target, port); recordTest(s, { kind: 'ec2.reach', source, target, port, ...d });
    return { message: `${SOURCES[source].label} → ${target === 'alb' ? 'nc-storefront-alb' : s.ec2.instances[target].name} tcp/${port}: ${d.allowed ? 'REACHABLE' : 'BLOCKED'} — ${d.reason}`, result: d };
  } },
  'ec2.terminateInstance': denied('ec2:TerminateInstances', p => arn.instance(String(p.instanceId))),
  'ec2.stopInstance': denied('ec2:StopInstances', p => arn.instance(String(p.instanceId))),

  // ---------- CloudTrail ----------
  'cloudtrail.updateTrail': { kind: 'change', run: ({ s, p }) => {
    const t = get<any>(s.cloudtrail.trails, p.name, 'Trail');
    const next = { multiRegion: bool(p.multiRegion, 'multiRegion'), managementEvents: oneOf(p.managementEvents, ['All', 'ReadOnly', 'WriteOnly'] as const, 'managementEvents'), logFileValidation: bool(p.logFileValidation, 'logFileValidation') };
    learnerAuth(s, 'cloudtrail:UpdateTrail', arn.trail(t.name));
    Object.assign(t, next); recordTrail(s, { name: 'UpdateTrail', source: 'cloudtrail', actor: 'ThreatReady-SecurityAnalyst', resource: t.name });
    return { message: `Trail ${t.name} updated.` };
  } },
  'cloudtrail.startLogging': { kind: 'change', run: ({ s, p }) => {
    const t = get<any>(s.cloudtrail.trails, p.name, 'Trail'); learnerAuth(s, 'cloudtrail:StartLogging', arn.trail(t.name));
    if (t.logging) return { message: 'Trail is already logging.' };
    t.logging = true; t.startedAt = simTime(s); recordTrail(s, { name: 'StartLogging', source: 'cloudtrail', actor: 'ThreatReady-SecurityAnalyst', resource: t.name });
    timeline(s, 'good', `CloudTrail logging restarted. Events between ${t.stoppedAt} and now were never recorded.`);
    return { message: `Logging started on ${t.name}. Events from the gap period were never recorded and cannot be recovered.` };
  } },
  'cloudtrail.auditTest': { kind: 'test', run: ({ s }) => {
    const id = recordTrail(s, { name: 'CreateTags', source: 'ec2', actor: 'ThreatReady-AuditProbe', resource: 'synthetic-probe', region: 'us-east-1', readOnly: false, ip: '203.0.113.50' });
    recordTest(s, { kind: 'cloudtrail.audit', recorded: !!id });
    return { message: id ? `Synthetic write event (ec2:CreateTags, us-east-1) was captured as ${id}. Find it in Event history.` : 'Synthetic write event (ec2:CreateTags, us-east-1) was performed but no trail captured it.', result: { recorded: !!id, eventId: id } };
  } },
  'cloudtrail.stopLogging': denied('cloudtrail:StopLogging', p => arn.trail(String(p.name))),
  'cloudtrail.deleteTrail': denied('cloudtrail:DeleteTrail', p => arn.trail(String(p.name))),

  // ---------- CloudWatch ----------
  'cloudwatch.putAlarm': { kind: 'change', run: ({ s, p }) => {
    const name = str(p.name, 'name', 64, /^[\w-]+$/); const metric = oneOf(p.metric, s.cloudwatch.metricDefs.map((m: any) => m.name), 'metric');
    const comparison = oneOf(p.comparison, ['>=', '>', '<=', '<'] as const, 'comparison');
    if (typeof p.threshold !== 'number' || !isFinite(p.threshold) || p.threshold < 0 || p.threshold > 1e6) bad('"threshold" must be a number between 0 and 1,000,000.');
    const period = oneOf(p.period, [60, 300, 900] as const, 'period'); const topic = p.topic ? oneOf(p.topic, s.cloudwatch.topics, 'topic') : null;
    learnerAuth(s, 'cloudwatch:PutMetricAlarm', '*', { name: 'PutMetricAlarm', source: 'cloudwatch', resource: name });
    const prev = s.cloudwatch.alarms[name];
    if (!prev && Object.keys(s.cloudwatch.alarms).length >= 10) bad('Alarm limit reached in this simulation.');
    s.cloudwatch.alarms[name] = { name, metric, comparison, threshold: p.threshold, period, topic, state: 'INSUFFICIENT_DATA', createdBy: prev?.createdBy || 'ThreatReady-SecurityAnalyst', history: prev?.history || [] };
    return { message: `Alarm ${name} ${prev ? 'updated' : 'created'}. State: INSUFFICIENT_DATA until data arrives.` };
  } },
  'cloudwatch.deleteAlarm': { kind: 'change', run: ({ s, p }) => { const a = get<any>(s.cloudwatch.alarms, p.name, 'Alarm'); learnerAuth(s, 'cloudwatch:DeleteAlarms', '*', { name: 'DeleteAlarms', source: 'cloudwatch', resource: a.name }); delete s.cloudwatch.alarms[a.name]; return { message: `Alarm ${a.name} deleted.` }; } },
  'cloudwatch.sendTestEvents': { kind: 'test', run: ({ s, p }) => {
    const metric = oneOf<string>(p.metric, s.cloudwatch.metricDefs.map((m: any) => m.name), 'metric'); const count = int(p.count, 'count', 1, 100);
    const def = s.cloudwatch.metricDefs.find((m: any) => m.name === metric);
    const before = s.cloudwatch.metrics[metric].length; const fired = pushMetric(s, metric, count); const delivered = s.cloudwatch.metrics[metric].length > before || before === 60;
    recordTest(s, { kind: 'cw.test', metric, count, fired, delivered });
    if (!delivered) return { message: `${count} synthetic events were generated, but ${metric} received no data: this metric is derived from CloudTrail, and no trail is logging.`, result: { delivered, fired } };
    return { message: `${count} synthetic ${def.source === 'cloudtrail' ? 'events' : 'samples'} published to ${metric}. ${fired.length ? `Alarm(s) now in ALARM: ${fired.join(', ')}.` : 'No alarm changed to ALARM.'}`, result: { delivered, fired } };
  } },

  // ---------- Lambda ----------
  'lambda.updateConfig': { kind: 'change', run: ({ s, p }) => {
    const f = get<any>(s.lambda.functions, p.name, 'Function'); const env = p.env;
    if (!env || typeof env !== 'object' || Array.isArray(env) || Object.keys(env).length > 20) bad('"env" must be an object with at most 20 variables.');
    for (const [k, v] of Object.entries(env)) { if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(k)) bad(`Invalid environment variable name: ${k}`); if (typeof v !== 'string' || v.length > 512) bad(`Invalid value for ${k}.`); }
    learnerAuth(s, 'lambda:UpdateFunctionConfiguration', arn.fn(f.name), { name: 'UpdateFunctionConfiguration', source: 'lambda', resource: f.name });
    f.env = { ...env }; f.lastModified = simTime(s); return { message: `Configuration of ${f.name} updated.` };
  } },
  'lambda.invoke': { kind: 'test', run: ({ s, p }) => {
    const f = get<any>(s.lambda.functions, p.name, 'Function'); learnerAuth(s, 'lambda:InvokeFunction', arn.fn(f.name));
    const r = lambdaRun(s, f.name); const stream = s.cloudwatch.logGroups[`/aws/lambda/${f.name}`].streams;
    const lines = (stream['sim/test-events'] ||= []); lines.push(...r.logs.map(l => `${simTime(s)} ${l}`)); if (lines.length > 60) lines.splice(0, lines.length - 60);
    if (r.usedSecret) { s.secrets.secrets[r.usedSecret].accessLog.push({ at: simTime(s), by: f.role, action: 'GetSecretValue' }); recordTrail(s, { name: 'GetSecretValue', source: 'secretsmanager', actor: f.role, resource: r.usedSecret, ip: 'lambda.amazonaws.com' }); }
    f.lastInvocation = { at: simTime(s), ok: r.ok, error: r.error }; recordTest(s, { kind: 'lambda.invoke', name: f.name, ok: r.ok });
    return { message: r.ok ? `Test event succeeded for ${f.name}.` : `Test event failed: ${r.error}`, result: r };
  } },
  'lambda.deleteFunction': denied('lambda:DeleteFunction', p => arn.fn(String(p.name))),

  // ---------- KMS ----------
  'kms.putKeyPolicy': { kind: 'change', run: ({ s, p }) => {
    const k = get<any>(s.kms.keys, p.keyId, 'Key'); const doc = parseDoc(p.document); const err = validatePolicy(doc, 'resource'); if (err) throw new LabError('MalformedPolicyDocumentException', err);
    learnerAuth(s, 'kms:PutKeyPolicy', arn.key(k.id), { name: 'PutKeyPolicy', source: 'kms', resource: k.alias });
    k.policyHistory.push({ at: simTime(s), document: k.policy }); if (k.policyHistory.length > 5) k.policyHistory.shift();
    k.policy = doc;
    if (!authorize(s, { principal: arn.role('nc-kms-admin-role'), action: 'kms:PutKeyPolicy', resource: arn.key(k.id) }).allowed)
      throw new LabError('MalformedPolicyDocumentException', 'Policy lockout safety check failed: the new key policy would prevent the key administrators (nc-kms-admin-role or the account root) from calling kms:PutKeyPolicy, making the key unmanageable.');
    return { message: `Key policy updated for ${k.alias}.` };
  } },
  'kms.restoreKeyPolicy': { kind: 'change', run: ({ s, p }) => {
    const k = get<any>(s.kms.keys, p.keyId, 'Key'); const h = k.policyHistory[int(p.index, 'index', 0, 4)]; if (!h) throw new LabError('NotFound', 'Policy version not found.');
    learnerAuth(s, 'kms:PutKeyPolicy', arn.key(k.id), { name: 'PutKeyPolicy', source: 'kms', resource: k.alias });
    const prev = k.policy; k.policy = clone(h.document); k.policyHistory.push({ at: simTime(s), document: prev }); if (k.policyHistory.length > 5) k.policyHistory.shift();
    return { message: `Key policy restored to the version from ${h.at}.` };
  } },
  'kms.cryptoTest': { kind: 'test', run: ({ s, p }) => {
    const k = get<any>(s.kms.keys, p.keyId, 'Key'); const principal = principalArg(s, p.principal); const operation = oneOf(p.operation, ['Encrypt', 'Decrypt', 'GenerateDataKey'] as const, 'operation');
    const d = authorize(s, { principal, action: `kms:${operation}`, resource: arn.key(k.id) });
    recordTest(s, { kind: 'kms.crypto', keyId: k.id, principal, operation, ...d }); recordTrail(s, { name: operation, source: 'kms', actor: principal.split('/').pop()!, resource: k.alias, outcome: d.allowed ? 'Success' : 'AccessDenied', readOnly: true });
    return { message: `kms:${operation} as ${principal.split(':').pop()}: ${d.allowed ? 'SUCCESS' : 'AccessDeniedException'} — ${d.reason}`, result: d };
  } },
  'kms.scheduleKeyDeletion': denied('kms:ScheduleKeyDeletion', p => arn.key(String(p.keyId))),
  'kms.disableKey': denied('kms:DisableKey', p => arn.key(String(p.keyId))),

  // ---------- Secrets Manager ----------
  'secrets.create': { kind: 'change', run: ({ s, p }) => {
    const name = str(p.name, 'name', 64, /^[A-Za-z0-9/_+=.@-]+$/); const value = str(p.value, 'value', 256); const description = p.description ? str(p.description, 'description', 200) : '';
    if (s.secrets.secrets[name]) throw new LabError('ResourceExistsException', `A secret named ${name} already exists.`);
    if (Object.keys(s.secrets.secrets).length >= 8) bad('Secret limit reached in this simulation.');
    learnerAuth(s, 'secretsmanager:CreateSecret', arn.secret(name), { name: 'CreateSecret', source: 'secretsmanager', resource: name });
    s.secrets.secrets[name] = { name, description, createdAt: simTime(s), createdBy: 'ThreatReady-SecurityAnalyst', rotationCount: 0, versions: [{ id: `ver-${String(++s.secrets.seq).padStart(4, '0')}`, value, stage: 'AWSCURRENT', createdAt: simTime(s) }], accessLog: [] };
    return { message: `Secret ${name} stored.`, result: { arn: arn.secret(name) } };
  } },
  'secrets.putValue': { kind: 'change', run: ({ s, p }) => {
    const sec = get<any>(s.secrets.secrets, p.name, 'Secret'); const value = str(p.value, 'value', 256);
    learnerAuth(s, 'secretsmanager:PutSecretValue', arn.secret(sec.name), { name: 'PutSecretValue', source: 'secretsmanager', resource: sec.name });
    newVersion(s, sec, value); return { message: `New version stored for ${sec.name}.` };
  } },
  'secrets.getValue': { kind: 'inspect', run: ({ s, p }) => {
    const sec = get<any>(s.secrets.secrets, p.name, 'Secret'); learnerAuth(s, 'secretsmanager:GetSecretValue', arn.secret(sec.name), { name: 'GetSecretValue', source: 'secretsmanager', resource: sec.name });
    sec.accessLog.push({ at: simTime(s), by: 'ThreatReady-SecurityAnalyst', action: 'GetSecretValue' }); if (sec.accessLog.length > 30) sec.accessLog.shift();
    return { message: 'Secret value retrieved. This access was logged.', result: { value: currentValue(sec) } };
  } },
  'secrets.rotate': { kind: 'change', run: ({ s, p }) => {
    const sec = get<any>(s.secrets.secrets, p.name, 'Secret'); learnerAuth(s, 'secretsmanager:RotateSecret', arn.secret(sec.name), { name: 'RotateSecret', source: 'secretsmanager', resource: sec.name });
    const cur = currentValue(sec); const n = ++sec.rotationCount;
    if (sec.name === 'novacart/prod/db-master') { newVersion(s, sec, `pg_SYNTHETIC_db_master_r${n}${s.secrets.seq}`); return { message: `${sec.name} rotated. Database clients fetch the new version automatically.` }; }
    if (cur !== s.gateway.current) { sec.rotationCount--; throw new LabError('RotationFailed', 'Rotation failed: the rotation function could not authenticate to the payment gateway with the secret\'s current value. Check that the stored value is the credential currently in use.'); }
    const next = `ncpg_SYNTHETIC_rot${n}_${(s.secrets.seq * 7919 + 104729).toString(16)}`;
    newVersion(s, sec, next); s.gateway.current = next; s.gateway.history.push(next);
    s.cloudwatch.logGroups['payment-gateway/auth'].streams.gateway.push(`${simTime(s)} credential rotated by secretsmanager; previous credential revoked`);
    timeline(s, 'good', `Payment gateway credential rotated via ${sec.name}; previous value revoked.`);
    return { message: `${sec.name} rotated. The payment gateway now accepts only the new version; the previous credential is revoked.` };
  } },
  'secrets.testCredential': { kind: 'test', run: ({ s, p }) => {
    const source = oneOf(p.source, ['secret', 'leaked'] as const, 'source'); let value = fx.LEAKED_CRED; let label = 'previously exposed credential';
    if (source === 'secret') { const sec = get<any>(s.secrets.secrets, p.name, 'Secret'); value = currentValue(sec); label = `current value of ${sec.name}`; }
    const accepted = value === s.gateway.current;
    s.cloudwatch.logGroups['payment-gateway/auth'].streams.gateway.push(`${simTime(s)} auth ${accepted ? 'ok' : 'REJECTED (401)'} client=threatready-probe (${label})`);
    recordTest(s, { kind: 'secrets.testCredential', source, accepted });
    return { message: `Payment gateway ${accepted ? 'ACCEPTED' : 'REJECTED (401)'} the ${label}.`, result: { accepted } };
  } },
  'secrets.delete': denied('secretsmanager:DeleteSecret', p => arn.secret(String(p.name))),

  // ---------- Organizations (performed from the management account's audit role) ----------
  'org.attachScp': { kind: 'change', run: ({ s, p }) => {
    const scp = get<any>(s.org.scps, p.scpId, 'Policy'); const target = str(p.targetId, 'targetId', 40);
    if (!(target === s.org.rootId || s.org.ous[target] || s.org.accounts[target])) throw new LabError('TargetNotFoundException', 'Target not found.');
    if (scp.attachedTo.includes(target)) throw new LabError('DuplicatePolicyAttachmentException', 'The policy is already attached to this target.');
    scp.attachedTo.push(target); return { message: `${scp.name} attached to ${target}.` };
  } },
  'org.detachScp': { kind: 'change', run: ({ s, p }) => {
    const scp = get<any>(s.org.scps, p.scpId, 'Policy'); if (!scp.attachedTo.includes(p.targetId)) throw new LabError('PolicyNotAttachedException', 'The policy is not attached to this target.');
    if (scp.awsManaged) throw new LabError('ConstraintViolationException', 'FullAWSAccess cannot be detached: every target must keep at least one allowing policy.');
    scp.attachedTo = scp.attachedTo.filter((t: string) => t !== p.targetId); return { message: `${scp.name} detached from ${p.targetId}.` };
  } },

  // ---------- Level 3 / 4 ----------
  'l3.regression': { kind: 'test', run: ({ s }) => {
    if (s.level < 3) throw new LabError('PreconditionFailed', 'The regression suite unlocks at Level 3.');
    const results = [...health(s).map(h => ({ label: h.label, ok: h.ok, detail: h.ok ? 'OK' : h.detail })), ...FINDINGS.map(f => ({ label: `${f.id} ${s.sim.findings[f.id].discovered ? f.title : '(undiscovered finding)'}`, ok: !!s.sim.findings[f.id].verified, detail: s.sim.findings[f.id].verified ? 'Verified' : f.remediated(s) ? 'Configuration fixed — not yet verified by test' : 'Open' }))];
    const passed = results.every(r => r.ok); s.sim.regression = { passed, at: simTime(s), results };
    return { message: passed ? 'Regression suite passed: all services healthy, all findings verified.' : `Regression suite: ${results.filter(r => !r.ok).length} check(s) failing.`, result: { passed, results } };
  } },
  'l4.triage': { kind: 'meta', run: ({ s, p }) => {
    if (s.level < 4) throw new LabError('PreconditionFailed', 'Alert triage unlocks at Level 4.'); if (s.sim.report) throw new LabError('PreconditionFailed', 'The report has been submitted; triage is closed.');
    const a = ALERTS.find(x => x.id === p.alertId); if (!a) throw new LabError('NotFound', 'Alert not found.');
    s.sim.triage[a.id] = oneOf(p.classification, TRIAGE_OPTIONS, 'classification'); return { message: `${a.id} classified as ${p.classification}.` };
  } },
  'l4.submitReport': { kind: 'meta', run: ({ s, p }) => {
    if (s.level < 4) throw new LabError('PreconditionFailed', 'The incident report unlocks at Level 4.'); if (s.sim.report) throw new LabError('PreconditionFailed', 'The report has already been submitted.');
    if (!ALERTS.every(a => s.sim.triage[a.id])) throw new LabError('PreconditionFailed', 'Triage all open alerts before submitting the report.');
    const ids = (k: keyof typeof REPORT_FORM) => REPORT_FORM[k].map(x => x.id);
    const multi = (v: any, k: keyof typeof REPORT_FORM) => { if (!Array.isArray(v) || v.some(x => !ids(k).includes(x)) || new Set(v).size !== v.length) bad(`Invalid selection for "${k}".`); return v as string[]; };
    const tl = multi(p.timeline, 'timeline'); if (tl.length !== REPORT_FORM.timeline.length) bad('Place every timeline event in order.');
    const input = { rootCause: oneOf(p.rootCause, ids('rootCause'), 'rootCause'), credential: str(p.credential, 'credential', 40), timeline: tl, affected: multi(p.affected, 'affected'), residual: multi(p.residual, 'residual'), hardening: multi(p.hardening, 'hardening'), summary: str(p.summary, 'summary', 4000), containmentRationale: str(p.containmentRationale, 'containmentRationale', 2000) };
    if (input.summary.trim().length < 80) bad('The executive summary must be at least 80 characters.');
    s.sim.report = { input, score: scoreReport(s, input), at: simTime(s) }; s.sim.completedAt = simTime(s); s.incident.status = 'Closed';
    timeline(s, 'story', 'Incident report submitted.');
    return { message: 'Incident report submitted. The lab is complete.' };
  } },
};
function sgRule(s: any, p: any) {
  const protocol = oneOf(p.protocol ?? 'tcp', ['tcp'] as const, 'protocol'); const port = int(p.port, 'port', 1, 65535); const source = str(p.source, 'source', 40);
  if (!(source.startsWith('sg-') ? !!s.ec2.securityGroups[source] : validCidr(source))) throw new LabError('InvalidParameterValue', 'Source must be a valid IPv4 CIDR (e.g. 203.0.113.0/24) or an existing security group ID.');
  return { protocol, port, source, description: p.description ? str(p.description, 'description', 80) : '' };
}
function newVersion(s: any, sec: any, value: string) {
  sec.versions.forEach((v: any) => (v.stage = v.stage === 'AWSCURRENT' ? 'AWSPREVIOUS' : 'DEPRECATED'));
  sec.versions.push({ id: `ver-${String(++s.secrets.seq).padStart(4, '0')}`, value, stage: 'AWSCURRENT', createdAt: simTime(s) }); if (sec.versions.length > 5) sec.versions.shift();
}

// ---------- post-action simulation: attacker, health, findings, objectives, levels ----------
function runAttacker(s: any) {
  const A = s.sim.attacker; if (A.t0 === null) return;
  for (const step of ATTACKER_STEPS) {
    if (A.done[step.id] || s.clock.minutes < A.t0 + step.at) continue;
    A.done[step.id] = true;
    const creds = [{ principal: arn.user('svc-storefront-app'), key: fx.KEY_OLD, actor: 'svc-storefront-app' }, { principal: arn.user('support-temp-01'), key: fx.KEY_BACKDOOR, actor: 'support-temp-01' }]
      .filter(c => s.iam.users[c.actor]?.accessKeys.some((k: any) => k.id === c.key && k.status === 'Active'));
    if (step.id === 'A4') {
      if (A.secretStolen && s.gateway.current === A.stolenValue) { A.successes++; A.fraud = true; s.cloudwatch.logGroups['payment-gateway/auth'].streams.gateway.push(`${simTime(s)} auth ok client=unknown ip=${fx.ATTACKER_IP} — 14 charges attempted (SYNTHETIC)`); timeline(s, 'bad', 'Consequence: the payment gateway reports charges from an unknown client using NovaCart\'s credential. The exposed secret was never rotated.'); }
      else if (A.secretStolen) { s.cloudwatch.logGroups['payment-gateway/auth'].streams.gateway.push(`${simTime(s)} auth REJECTED (401) client=unknown ip=${fx.ATTACKER_IP} — retired credential`); timeline(s, 'good', 'The payment gateway rejected an unknown client presenting the retired credential. Rotation worked.'); }
      continue;
    }
    if (!creds.length) { timeline(s, 'good', `No activity: the intruder has no working credential (${step.event} never reached the API).`); continue; }
    let ok: (typeof creds)[0] | null = null;
    for (const c of creds) {
      const allowed = step.id === 'A1' ? s3Access(s, { principal: c.principal, operation: 'GET', bucket: 'novacart-internal-docs', key: 'finance/payroll-2026-09.csv', accessKeyId: c.key }).allowed
        : step.id === 'A2' ? ['iam:CreateUser', 'iam:AttachUserPolicy', 'iam:CreateAccessKey'].every(a => authorize(s, { principal: c.principal, action: a, resource: step.resource, accessKeyId: c.key }).allowed) && !s.iam.users['support-temp-01']
        : authorize(s, { principal: c.principal, action: step.action, resource: step.resource, accessKeyId: c.key }).allowed;
      if (allowed) { ok = c; break; }
    }
    const c = ok || creds[0];
    recordTrail(s, { name: step.event, source: step.source, actor: c.actor, resource: step.resource.split(/[:/]/).pop(), ip: fx.ATTACKER_IP, accessKeyId: c.key, outcome: ok ? 'Success' : 'AccessDenied' });
    if (!ok) { pushMetric(s, 'UnauthorizedAPICalls', 6); timeline(s, 'good', `Blocked: the intruder attempted ${step.action} and was denied.`); continue; }
    A.successes++;
    if (step.id === 'A1') { A.exfil++; s.cloudwatch.logGroups['s3-access/novacart-internal-docs'].streams['2026-10-09'].push(`${simTime(s)} ${fx.ATTACKER_IP} ${c.actor} REST.GET.OBJECT finance/payroll-2026-09.csv 200`); timeline(s, 'bad', 'Consequence: the S3 access log shows the payroll file downloaded from 198.51.100.77 while the compromised credential was still usable.'); }
    if (step.id === 'A2') { A.backdoor = true; s.iam.users['support-temp-01'] = { name: 'support-temp-01', arn: arn.user('support-temp-01'), createdAt: simTime(s), groups: [], mfa: false, console: false, policies: ['pol-admin'], tags: {}, accessKeys: [{ id: fx.KEY_BACKDOOR, status: 'Active', createdAt: simTime(s), lastUsed: simTime(s), lastUsedIp: fx.ATTACKER_IP, lastUsedService: 'iam' }] }; timeline(s, 'bad', 'Consequence: a new IAM user appeared in the account. Nobody at NovaCart created it.'); }
    if (step.id === 'A3') { const env = s.lambda.functions[fx.FN].env; const v = Object.values<string>(env).find(x => x === s.gateway.current); if (v) { A.secretStolen = true; A.stolenValue = v; timeline(s, 'bad', 'Consequence: the order processor\'s configuration was read from 198.51.100.77. Anything stored in it must be treated as disclosed.'); } else { A.successes--; timeline(s, 'good', 'The intruder read the function configuration, but it no longer contains a credential.'); } }
  }
}
function recompute(s: any, causedBy: string) {
  for (const f of FINDINGS) {
    const fs = (s.sim.findings[f.id] ||= { discovered: false, remediated: false, verified: false });
    const rem = f.remediated(s);
    if (!rem) for (const c of f.checks) delete s.sim.checks[c.id];
    const ver = rem && f.checks.every(c => s.sim.checks[c.id]);
    if (fs.verified && !ver) timeline(s, 'warn', `Regression: ${f.id} (${f.title}) is no longer verified after ${causedBy}.`);
    if (!fs.verified && ver) { fs.verifiedAt = simTime(s); if (!fs.discovered) { fs.discovered = true; fs.discoveredAt = simTime(s); } timeline(s, 'good', `Verified: ${f.id} ${f.title}.`); }
    if (!fs.remediated && rem) fs.remediatedAt = simTime(s);
    fs.remediated = rem; fs.verified = ver;
  }
  const probes = health(s);
  for (const p of probes) {
    const was = s.sim.health[p.id];
    if (was === true && !p.ok) { s.sim.outages.push({ probe: p.id, label: p.label, at: simTime(s), cause: causedBy, detail: p.detail }); timeline(s, 'bad', `Outage: "${p.label}" started failing after ${causedBy}. ${p.detail}`); if (p.id === 'storefront') pushMetric(s, 'ALB5xxCount', 240); }
    if (was === false && p.ok) timeline(s, 'good', `Restored: "${p.label}".`);
    s.sim.health[p.id] = p.ok;
  }
  for (const o of OBJECTIVES) {
    const st = (s.sim.objectives[o.id] ||= { done: false });
    const d = o.level <= s.level && o.done(s);
    if (d && !st.done) st.at = simTime(s);
    st.done = o.sticky ? st.done || d : d;
  }
  while (s.level < 4 && OBJECTIVES.filter(o => o.level === s.level).every(o => s.sim.objectives[o.id].done)) {
    s.level++; s.sim.levelStartedAt[s.level] = s.clock.minutes;
    timeline(s, 'story', `Level ${s.level - 1} complete. Level ${s.level} unlocked.`);
    if (s.level === 2) { s.sim.attacker.t0 = s.clock.minutes; s.sim.alerts.push({ id: 'AL-0', at: simTime(s), severity: 'High', title: 'Suspicious IAM activity: svc-storefront-app', detail: 'An access key for svc-storefront-app is being used from 198.51.100.77, outside NovaCart address space. Activity is ongoing.' }); timeline(s, 'bad', 'ALERT: an access key for svc-storefront-app is in use from an unknown external address. The intruder is active.'); }
    if (s.level === 4) for (const a of ALERTS) s.sim.alerts.push({ id: a.id, at: simTime(s), severity: 'Medium', title: a.title, detail: a.detail, source: a.source, triage: true });
    for (const o of OBJECTIVES) if (o.level === s.level) { const d = o.done(s); s.sim.objectives[o.id].done = d; if (d) s.sim.objectives[o.id].at = simTime(s); }
  }
  const ch = CHAPTERS.filter(c => c.when(s)).pop()!.n;
  if (ch > s.chapter) { s.chapter = ch; const c = CHAPTERS[ch - 1]; timeline(s, 'story', `Chapter ${c.n}: ${c.title} — ${c.text}`); }
  const A = s.sim.attacker; const isContained = contained(s);
  s.incident.containment = s.level < 2 ? 'Not assessed' : isContained ? 'Contained' : 'Not contained';
  s.incident.severity = s.sim.report ? 'Resolved' : (A.backdoor || A.fraud) && !isContained ? 'Critical' : s.level >= 2 && !isContained ? 'High' : FINDINGS.every(f => s.sim.findings[f.id].verified) ? 'Low' : 'Medium';
}

function score(s: any) {
  const cats: Record<string, { awarded: number; max: number }> = {};
  const add = (c: string, a: number, m: number) => { (cats[c] ||= { awarded: 0, max: 0 }); cats[c].awarded += a; cats[c].max += m; };
  const per: Record<string, number> = {};
  for (const o of OBJECTIVES) {
    const st = s.sim.objectives[o.id]; const factor = 1 - 0.25 * Math.min(2, s.sim.hints[o.id] || 0); let a = 0;
    if (o.id === 'L4.report') a = s.sim.report ? s.sim.report.score.total : 0;
    else if (o.id === 'L4.triage') a = s.sim.report ? ALERTS.filter(x => s.sim.triage[x.id] === x.truth).length * 5 : 0;
    else if (st.done) a = o.points;
    else if (o.kind === 'fix' && o.level <= s.level && s.sim.findings[o.finding!].remediated) a = o.points * 0.6;
    a = Math.round(a * factor * 10) / 10; per[o.id] = a;
    if (o.kind === 'fix') { add('remediation', Math.min(a, o.points * 0.6 * factor), o.points * 0.6); add('verification', Math.max(0, a - o.points * 0.6 * factor), o.points * 0.4); } else add(o.category, a, o.points);
  }
  const unhealthy = Object.values(s.sim.health).some(v => v === false);
  add('availability', unhealthy ? 0 : Math.max(0, 30 - 6 * s.sim.outages.length), 30);
  const penalties = [
    { label: 'Unsupported finding reports', points: Math.min(10, s.sim.wrongReports * 2) },
    { label: 'Intruder actions that succeeded during the active incident', points: Math.min(32, s.sim.attacker.successes * 8) }].filter(p => p.points);
  const raw = Object.values(cats).reduce((n, c) => n + c.awarded, 0); const max = Object.values(cats).reduce((n, c) => n + c.max, 0);
  const total = Math.max(0, Math.round((raw - penalties.reduce((n, p) => n + p.points, 0)) * 10) / 10);
  for (const c of Object.values(cats)) { c.awarded = Math.round(c.awarded * 10) / 10; c.max = Math.round(c.max * 10) / 10; }
  return { total, max, percent: Math.round((total / max) * 100), categories: cats, penalties, perObjective: per };
}

const BRIEFING = {
  company: 'NovaCart', role: 'Cloud Security Analyst', ticket: 'INC-2041',
  intro: 'NovaCart is an Indian e-commerce startup preparing for its biggest product launch. Its AWS-style environment was built quickly. An internal security review has identified suspicious access patterns, and some customers report unusual account activity. You have just joined as the Cloud Security Analyst and the ticket is yours.',
  rules: [
    'Everything here is simulated. No real AWS account, credentials or customer data are involved.',
    'Nothing is fixed for you. Opening a page never changes a resource — you inspect, decide, act, confirm and then verify.',
    'A finding is only resolved when the server has verified the resulting configuration and you have tested it.',
    'NovaCart is live. Changes that break the storefront, uploads, invoicing or order processing count against you — and can be undone.',
    'Hints are available per objective and reduce that objective\'s points by 25% each.',
    'You can investigate in any order. Levels unlock when the previous level\'s objectives are complete.'],
  levels: [
    { n: 1, name: 'Cloud Security Analyst — Investigate' }, { n: 2, name: 'Incident Responder — Contain' },
    { n: 3, name: 'Cloud Security Engineer — Remediate' }, { n: 4, name: 'Incident Commander — Command and report' }],
  policies: [
    { title: 'Network access policy NC-NET-01', body: 'Production application servers accept application traffic (tcp/8080) only from the load balancer security group. SSH (tcp/22) is permitted only from the office VPN range 203.0.113.0/24. No other inbound access from the internet is permitted on application servers. The public load balancer serves customers on 443 (and 80 for redirect).' },
    { title: 'Data handling policy NC-DATA-02', body: 'Data classified "confidential" must not be publicly accessible and must be encrypted at rest with SSE-KMS using the customer managed key alias/novacart-data, including objects that already exist. Product catalog images under novacart-product-assets/public/ are intentionally public.' },
    { title: 'Secrets policy NC-SEC-03', body: 'Credentials must be stored in Secrets Manager and referenced by ARN (environment variable PAYMENT_SECRET_ARN for the order processor). Any credential that has been exposed must be rotated.' },
    { title: 'Detection policy NC-DET-04', body: 'A complete management-event audit trail (read and write, all regions) must be active. An alarm on unauthorized API calls (threshold between 1 and 10 per period) must notify the nc-security-alerts topic.' },
    { title: 'Key management policy NC-KMS-05', body: 'Use of alias/novacart-data is limited to nc-app-server-role. Key administration (including kms:PutKeyPolicy) belongs to nc-kms-admin-role.' }],
};

export const cloudLab001: LabEngine = {
  labId: 'TR-CLOUD-001', title: 'The Compromised Startup',
  definition: () => ({ id: 'TR-CLOUD-001', title: 'The Compromised Startup', subtitle: 'Investigate, contain, and secure a vulnerable AWS environment.', category: 'Cloud Security / AWS Security', briefing: BRIEFING, vulnerabilities: FINDINGS.map(f => ({ id: f.id, title: f.title })), triageOptions: TRIAGE_OPTIONS, reportForm: REPORT_FORM, sources: Object.entries(SOURCES).map(([id, v]) => ({ id, label: v.label })) }),
  createInitialState() { const s = fx.createInitialState(); recompute(s, 'lab start'); const c = CHAPTERS[0]; timeline(s, 'story', `Chapter 1: ${c.title} — ${c.text}`); return s; },
  dispatch(state, action) {
    const h = typeof action.type === 'string' && Object.prototype.hasOwnProperty.call(H, action.type) ? H[action.type] : undefined;
    const fail = (code: string, message: string) => {
      const s = clone(state); s.sim.failedActions++;
      s.labEvents.push({ seq: ++s.eventSeq, at: simTime(s), type: action.type, outcome: code, message, params: summarize(action.params) });
      if (code === 'AccessDenied') recordTrail(s, { name: action.type.split('.')[1] || action.type, source: action.type.split('.')[0], actor: 'ThreatReady-SecurityAnalyst', outcome: 'AccessDenied', readOnly: false });
      if (action.type === 'finding.report' && code === 'NotSupportedByEvidence') s.sim.wrongReports++;
      return { state: s, result: { ok: false, code, message } };
    };
    if (!h) return fail('UnknownAction', 'Unknown action.');
    if (state.sim.report && h.kind === 'change') return fail('LabComplete', 'The incident is closed. Reset the lab to start a new run.');
    const s = clone(state);
    let out;
    try { out = h.run({ s, p: action.params && typeof action.params === 'object' ? action.params : {} }); }
    catch (e) { if (e instanceof LabError) return fail(e.code, e.message); throw e; }
    s.rev++; s.clock.minutes += h.kind === 'change' ? 5 : h.kind === 'test' ? 2 : 1;
    if (action.type !== 'inspect') s.labEvents.push({ seq: ++s.eventSeq, at: simTime(s), type: action.type, outcome: 'Success', message: out.message, params: summarize(action.params) });
    runAttacker(s); recompute(s, action.type);
    return { state: s, result: { ok: true, message: out.message, result: out.result } };
  },
  view(state) {
    const v = clone(state); delete v.gateway; delete v.sim; delete v.labEvents; delete v.eventSeq;
    v.cloudtrail.eventCount = v.cloudtrail.events.length; delete v.cloudtrail.events;
    for (const sec of Object.values<any>(v.secrets.secrets)) for (const ver of sec.versions) ver.value = '••••••••';
    v.exposure = internetExposure(state); v.time = simTime(state); v.learner = LEARNER; v.account = { id: ACC, alias: 'novacart-training', region: 'ap-south-1', environment: 'production-simulation' };
    return v;
  },
  status(state) {
    const s = state; const sc = score(s);
    return {
      level: s.level, chapter: s.chapter, chapters: CHAPTERS.filter(c => c.n <= s.chapter).map(c => ({ n: c.n, title: c.title, text: c.text })),
      incident: s.incident, time: simTime(s), minutes: s.clock.minutes, complete: !!s.sim.report, rev: s.rev,
      objectives: OBJECTIVES.map(o => ({ id: o.id, level: o.level, title: o.level <= s.level ? o.title : 'Locked objective', locked: o.level > s.level, done: s.sim.objectives[o.id].done, points: o.points, awarded: sc.perObjective[o.id], category: o.category, hints: o.hints.slice(0, s.sim.hints[o.id] || 0), hintsRemaining: o.level <= s.level ? o.hints.length - (s.sim.hints[o.id] || 0) : 0, partial: o.kind === 'fix' && !s.sim.objectives[o.id].done && s.sim.findings[o.finding!].remediated })),
      findings: FINDINGS.map(f => { const fs = s.sim.findings[f.id]; const status = fs.verified ? 'Verified' : fs.remediated && fs.discovered ? 'Remediated — unverified' : fs.discovered ? 'Open' : 'Not found';
        return { id: f.id, title: f.title, status, ...(fs.discovered ? { service: f.service, resource: fs.resource, severity: f.severity, severityWhy: f.severityWhy, business: f.business, technical: f.technical, discoveredAt: fs.discoveredAt, checks: f.checks.map(c => ({ label: c.label, passed: !!s.sim.checks[c.id] })) } : {}), ...(fs.verified ? { explanation: f.explanation, verifiedAt: fs.verifiedAt } : {}) }; }),
      score: sc, health: health(s).map(h => ({ id: h.id, label: h.label, ok: h.ok, detail: h.ok ? '' : h.detail })), outages: s.sim.outages,
      alerts: s.sim.alerts.map((a: any) => ({ ...a, classification: s.sim.triage[a.id] || null, ...(s.sim.report && a.triage ? { correct: s.sim.triage[a.id] === ALERTS.find(x => x.id === a.id)!.truth } : {}) })),
      timeline: s.sim.timeline, evidence: s.sim.evidence.map((id: string) => s.cloudtrail.events.find((e: any) => e.id === id)).filter(Boolean),
      tests: s.sim.tests.slice(-15).reverse(), regression: s.sim.regression, hintsUsed: Object.values<number>(s.sim.hints).reduce((a, b) => a + b, 0), failedActions: s.sim.failedActions,
      posture: { resolved: FINDINGS.filter(f => s.sim.findings[f.id].verified).length, total: FINDINGS.length },
      progress: Math.round((OBJECTIVES.filter(o => s.sim.objectives[o.id].done).length / OBJECTIVES.length) * 100),
      reportSubmitted: !!s.sim.report,
    };
  },
  report(state, meta) {
    const s = state; const sc = score(s); const ev = s.labEvents; const of = (t: string[]) => ev.filter((e: any) => e.outcome === 'Success' && t.some(x => e.type.startsWith(x)));
    const fsOf = (f: any) => s.sim.findings[f.id];
    return {
      meta: { ...meta, lab: 'TR-CLOUD-001 — The Compromised Startup', generatedAt: new Date().toISOString(), simulatedTime: simTime(s), final: !!s.sim.report, simulatedMinutes: s.clock.minutes, level: s.level },
      summary: { learnerText: s.sim.report?.input.summary || null, containmentRationale: s.sim.report?.input.containmentRationale || null, severity: s.incident.severity, containment: s.incident.containment, findingsVerified: FINDINGS.filter(f => fsOf(f).verified).length, findingsTotal: FINDINGS.length },
      timeline: s.sim.timeline,
      findings: FINDINGS.map(f => { const fs = fsOf(f); return { id: f.id, title: fs.discovered ? f.title : 'Undiscovered finding', service: fs.discovered ? f.service : '—', severity: fs.discovered ? f.severity : '—', discovered: fs.discovered, discoveredAt: fs.discoveredAt || null, contained: f.id === 'V1' || f.id === 'V6' ? contained(s) && s.level >= 2 : null, remediated: fs.remediated, remediatedAt: fs.remediated ? fs.remediatedAt : null, verified: fs.verified, verifiedAt: fs.verified ? fs.verifiedAt : null, checks: fs.discovered ? f.checks.map(c => ({ label: c.label, passed: !!s.sim.checks[c.id] })) : [], statement: fs.verified ? 'Root cause remediated and verified by test.' : fs.remediated ? 'Configuration changed, but NOT verified by test — do not treat as secure.' : fs.discovered ? 'Discovered; still open.' : 'Not discovered during this session.' }; }),
      evidence: s.sim.evidence.map((id: string) => s.cloudtrail.events.find((e: any) => e.id === id)).filter(Boolean),
      containmentActions: of(['iam.setAccessKeyStatus', 'secrets.rotate', 'incident.declare']),
      remediationActions: of(['iam.updatePolicy', 'iam.restore', 's3.put', 's3.reencrypt', 'ec2.add', 'ec2.update', 'ec2.remove', 'cloudtrail.update', 'cloudtrail.start', 'cloudwatch.put', 'cloudwatch.delete', 'lambda.update', 'kms.put', 'kms.restore', 'secrets.create', 'secrets.putValue', 'org.']),
      verificationTests: s.sim.tests, regression: s.sim.regression,
      intruder: { successfulActions: s.sim.attacker.successes, backdoorUserCreated: s.sim.attacker.backdoor, paymentCredentialDisclosed: s.sim.attacker.secretStolen, fraudulentCharges: !!s.sim.attacker.fraud, documentsAccessed: s.sim.attacker.exfil },
      availability: { outages: s.sim.outages, current: health(s).map(h => ({ label: h.label, ok: h.ok })) },
      remainingRisks: [...FINDINGS.filter(f => !fsOf(f).verified).map(f => fsOf(f).discovered ? `${f.id} ${f.title}: ${fsOf(f).remediated ? 'changed but unverified' : 'open'}` : 'One or more findings were never discovered'), ...(s.sim.attacker.exfil ? [`${s.sim.attacker.exfil} confidential document download(s) by the intruder are on record and cannot be recalled`] : []), 'CloudTrail events between the StopLogging call and the restart were never recorded'].filter((x, i, a) => a.indexOf(x) === i),
      reportAssessment: s.sim.report ? { ...s.sim.report.score, input: s.sim.report.input, triage: ALERTS.map(a => ({ id: a.id, title: a.title, chosen: s.sim.triage[a.id], correct: s.sim.triage[a.id] === a.truth })) } : null,
      performance: { score: sc, hintsUsed: Object.values<number>(s.sim.hints).reduce((a, b) => a + b, 0), failedActions: s.sim.failedActions, unsupportedReports: s.sim.wrongReports, actions: ev.length, objectives: OBJECTIVES.map(o => ({ id: o.id, level: o.level, title: o.title, done: s.sim.objectives[o.id].done, at: s.sim.objectives[o.id].at || null, awarded: sc.perObjective[o.id], points: o.points, hints: s.sim.hints[o.id] || 0 })) },
    };
  },
};
function summarize(p: any) {
  if (!p || typeof p !== 'object') return {};
  const o: any = {}; for (const [k, v] of Object.entries(p).slice(0, 12)) o[k] = k === 'value' ? '[redacted]' : typeof v === 'string' ? v.slice(0, 120) : typeof v === 'object' ? '[object]' : v; return o;
}
