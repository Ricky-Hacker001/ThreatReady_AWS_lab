import { describe, it, expect } from 'vitest';
import { Lab, steps, E, fx, arn, ANON, SVC, R_APP, R_ORDER, RAHUL, DOCS, APP_POLICY, KEY_POLICY, orderPolicy } from './helpers';
import { authorize, glob, validatePolicy, cidrContains } from '../server/policy';
import { reach } from '../server/sim';

describe('policy evaluation', () => {
  const s = E.createInitialState();
  it('matches wildcards', () => { expect(glob('s3:Get*', 's3:getobject', true)).toBe(true); expect(glob('arn:aws:s3:::a/*', 'arn:aws:s3:::b/x')).toBe(false); });
  it('wildcard identity policy allows everything', () => expect(authorize(s, { principal: SVC, action: 'iam:CreateUser', resource: '*' }).allowed).toBe(true));
  it('explicit deny beats allow', () => expect(authorize(s, { principal: arn.role('ThreatReady-SecurityAnalyst'), action: 'ec2:TerminateInstances', resource: '*' }).allowed).toBe(false));
  it('anonymous read follows bucket policy, ACL and Block Public Access', () => {
    const q = { principal: ANON, action: 's3:GetObject', resource: arn.object(DOCS, 'finance/payroll-2026-09.csv') };
    expect(authorize(s, q).allowed).toBe(true);
    const t = structuredClone(s); t.s3.buckets[DOCS].policy = null;
    expect(authorize(t, q).allowed).toBe(false);
    expect(authorize(t, { ...q, resource: arn.object(DOCS, 'hr/offer-letters/offer-NC-0113.pdf') }).allowed).toBe(true); // ACL path
    t.s3.buckets[DOCS].blockPublicAccess.ignorePublicAcls = true;
    expect(authorize(t, { ...q, resource: arn.object(DOCS, 'hr/offer-letters/offer-NC-0113.pdf') }).allowed).toBe(false);
  });
  it('inactive access keys are rejected', () => { const t = structuredClone(s); t.iam.users['svc-storefront-app'].accessKeys[1].status = 'Inactive'; expect(authorize(t, { principal: SVC, action: 's3:ListBucket', resource: '*', accessKeyId: fx.KEY_OLD }).reason).toMatch(/InvalidAccessKeyId/); });
  it('KMS needs the key policy; root delegation defers to IAM', () => {
    const t = structuredClone(s); t.kms.keys[fx.DATA_KEY].policy = KEY_POLICY; const k = arn.key(fx.DATA_KEY);
    expect(authorize(t, { principal: SVC, action: 'kms:Decrypt', resource: k }).allowed).toBe(false); // IAM "*" alone is not enough
    expect(authorize(t, { principal: R_APP, action: 'kms:Decrypt', resource: k }).allowed).toBe(true);
    t.kms.keys[fx.DATA_KEY].policy = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: arn.root }, Action: 'kms:*', Resource: '*' }] };
    expect(authorize(t, { principal: SVC, action: 'kms:Decrypt', resource: k }).allowed).toBe(true);
    expect(authorize(t, { principal: arn.user('ops-priya'), action: 'kms:Decrypt', resource: k }).allowed).toBe(false);
  });
  it('validates policy documents', () => { expect(validatePolicy({ Version: '2012-10-17', Statement: [] }, 'identity')).toBeTruthy(); expect(validatePolicy(APP_POLICY, 'identity')).toBeNull(); expect(validatePolicy(APP_POLICY, 'resource')).toMatch(/Principal/); });
  it('security group reachability', () => { expect(cidrContains('203.0.113.0/24', '203.0.113.10')).toBe(true); expect(reach(s, 'internet', fx.I_APP, 22).allowed).toBe(true); expect(reach(s, 'internet', fx.I_BATCH, 5432).allowed).toBe(false); expect(reach(s, 'alb', fx.I_APP, 8080).allowed).toBe(true); });
});

describe('user-driven state transitions', () => {
  it('starts healthy, unsolved, at level 1', () => { const l = new Lab(); const st = l.status; expect(st.level).toBe(1); expect(st.health.every((h: any) => h.ok)).toBe(true); expect(st.findings.every((f: any) => f.status === 'Not found')).toBe(true); expect(st.score.total).toBe(30); });
  it('inspecting changes no resource and solves nothing', () => { const l = new Lab(); const before = JSON.stringify(E.view(l.state).s3); l.ok('inspect', { key: `s3/bucket/${DOCS}#permissions` }); expect(JSON.stringify(E.view(l.state).s3)).toBe(before); expect(l.finding('V2').status).toBe('Not found'); });
  it('finding reports need evidence and the right resource', () => {
    const l = new Lab();
    expect(l.do('finding.report', { findingId: 'V2', resource: `s3/bucket/${DOCS}` }).code).toBe('EvidenceRequired');
    expect(l.do('finding.report', { findingId: 'V2', resource: 's3/bucket/novacart-product-assets' }).code).toBe('NotSupportedByEvidence');
    l.report('V2', `s3/bucket/${DOCS}#permissions`, `s3/bucket/${DOCS}`); expect(l.finding('V2').status).toBe('Open'); expect(l.finding('V2').severity).toBe('High');
  });
  it('a fix is not verified until the learner tests it', () => {
    const l = new Lab(); l.report('V2', `s3/bucket/${DOCS}#permissions`, `s3/bucket/${DOCS}`);
    l.ok('s3.putBucketPolicy', { bucket: DOCS, document: null }); expect(l.finding('V2').status).toBe('Open'); // ACL path still public
    l.ok('s3.putObjectAcl', { bucket: DOCS, key: 'hr/offer-letters/offer-NC-0113.pdf', acl: 'private' });
    expect(l.finding('V2').status).toBe('Remediated — unverified'); expect(l.obj('V2.fix').done).toBe(false); expect(l.obj('V2.fix').awarded).toBe(12);
    l.ok('s3.accessTest', { bucket: DOCS, key: 'finance/payroll-2026-09.csv', principal: ANON, operation: 'GET' }); l.ok('s3.accessTest', { bucket: DOCS, key: 'invoices/INV-2026-10-0001.json', principal: R_APP, operation: 'GET' });
    expect(l.finding('V2').status).toBe('Verified'); expect(l.finding('V2').explanation).toBeTruthy();
  });
  it('tests run before the fix do not count, and regressions reopen findings', () => {
    const l = new Lab(); l.ok('ec2.reachabilityTest', { source: 'alb', target: fx.I_APP, port: 8080 }); steps.v3(l); expect(l.finding('V3').status).toBe('Verified');
    l.ok('ec2.addIngressRule', { groupId: fx.SG_APP, port: 22, source: '0.0.0.0/0' }); expect(l.finding('V3').status).toBe('Open');
  });
  it('destructive operations are denied by the learner role', () => { const l = new Lab(); for (const [t, p] of [['ec2.terminateInstance', { instanceId: fx.I_APP }], ['s3.deleteBucket', { bucket: DOCS }], ['cloudtrail.deleteTrail', { name: fx.TRAIL }], ['kms.scheduleKeyDeletion', { keyId: fx.DATA_KEY }], ['iam.deleteUser', { userName: 'dev-rahul' }]] as const) expect(l.do(t, p).code).toBe('AccessDenied'); expect(l.status.failedActions).toBe(5); });
  it('invalid input and invalid transitions are rejected without changing state', () => {
    const l = new Lab(); const rev = l.state.rev;
    expect(l.do('iam.updatePolicy', { policyId: 'pol-app', document: '{bad json' }).code).toBe('MalformedPolicyDocument');
    expect(l.do('iam.updatePolicy', { policyId: 'pol-analyst', document: APP_POLICY }).code).toBe('AccessDenied');
    expect(l.do('ec2.addIngressRule', { groupId: fx.SG_APP, port: 99999, source: '0.0.0.0/0' }).code).toBe('ValidationError');
    expect(l.do('ec2.addIngressRule', { groupId: fx.SG_APP, port: 22, source: 'nonsense' }).code).toBe('InvalidParameterValue');
    expect(l.do('s3.reencryptObjects', { bucket: DOCS }).code).toBe('PreconditionFailed');
    expect(l.do('incident.declareCompromisedKey', { accessKeyId: fx.KEY_OLD }).code).toBe('PreconditionFailed');
    expect(l.do('l4.submitReport', {}).code).toBe('PreconditionFailed'); expect(l.do('nope.nope').code).toBe('UnknownAction');
    expect(l.do('__proto__').code).toBe('UnknownAction'); expect(l.state.rev).toBe(rev);
  });
  it('breaking production is recorded as an outage and can be undone', () => {
    const l = new Lab(); l.ok('ec2.removeIngressRule', { groupId: fx.SG_APP, ruleId: 'sgr-app1' }); l.ok('ec2.removeIngressRule', { groupId: fx.SG_APP, ruleId: 'sgr-app3' });
    expect(l.status.health.find((h: any) => h.id === 'storefront').ok).toBe(false); expect(l.status.outages).toHaveLength(1); expect(l.status.score.categories.availability.awarded).toBe(0);
    l.ok('ec2.addIngressRule', { groupId: fx.SG_APP, port: 8080, source: fx.SG_ALB }); expect(l.status.health.find((h: any) => h.id === 'storefront').ok).toBe(true); expect(l.status.score.categories.availability.awarded).toBe(24);
  });
  it('KMS lockout safety keeps the exercise recoverable', () => { const l = new Lab(); const bad = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: R_APP }, Action: 'kms:Decrypt', Resource: '*' }] }; expect(l.do('kms.putKeyPolicy', { keyId: fx.DATA_KEY, document: bad }).message).toMatch(/lockout/); l.ok('kms.putKeyPolicy', { keyId: fx.DATA_KEY, document: KEY_POLICY }); l.ok('kms.restoreKeyPolicy', { keyId: fx.DATA_KEY, index: 0 }); expect(l.state.kms.keys[fx.DATA_KEY].policy.Statement[0].Sid).toBe('AllowEveryoneTemp'); });
  it('hints are revealed on request and cost points', () => { const l = new Lab(); expect(l.obj('V2.find').hints).toHaveLength(0); const r = l.ok('hint.request', { objectiveId: 'V2.find' }); expect(r.result.hint).toBeTruthy(); l.report('V2', `s3/bucket/${DOCS}#permissions`, `s3/bucket/${DOCS}`); expect(l.obj('V2.find').awarded).toBe(7.5); expect(l.do('hint.request', { objectiveId: 'V4.find' }).code).toBe('PreconditionFailed'); });
});

describe('cross-service dependencies', () => {
  it('CloudTrail: gap events are never recovered; coverage decides what is recorded', () => {
    const l = new Lab(); const n = l.state.cloudtrail.events.length;
    l.ok('s3.putPublicAccessBlock', { bucket: DOCS, config: { blockPublicAcls: true, ignorePublicAcls: true, blockPublicPolicy: true, restrictPublicBuckets: true } });
    expect(l.state.cloudtrail.events.length).toBe(n); // trail is stopped: the learner's own change is invisible
    expect(l.ok('cloudtrail.auditTest').result.recorded).toBe(false);
    l.ok('cloudtrail.startLogging', { name: fx.TRAIL }); expect(l.ok('cloudtrail.auditTest').result.recorded).toBe(false); // single region, read-only
    l.ok('cloudtrail.updateTrail', { name: fx.TRAIL, multiRegion: true, managementEvents: 'All', logFileValidation: false });
    expect(l.ok('cloudtrail.auditTest').result.recorded).toBe(true);
    expect(l.state.cloudtrail.events.some((e: any) => e.name === 'PutBucketPublicAccessBlock')).toBe(false);
  });
  it('CloudWatch alarm only fires when CloudTrail is delivering', () => {
    const l = new Lab(); l.ok('cloudwatch.putAlarm', { name: 'a1', metric: 'UnauthorizedAPICalls', comparison: '>=', threshold: 5, period: 300, topic: 'nc-security-alerts' });
    expect(l.ok('cloudwatch.sendTestEvents', { metric: 'UnauthorizedAPICalls', count: 9 }).result.delivered).toBe(false); expect(l.state.cloudwatch.alarms.a1.state).toBe('INSUFFICIENT_DATA');
    l.ok('cloudtrail.startLogging', { name: fx.TRAIL }); expect(l.ok('cloudwatch.sendTestEvents', { metric: 'UnauthorizedAPICalls', count: 3 }).result.fired).toEqual([]);
    expect(l.ok('cloudwatch.sendTestEvents', { metric: 'UnauthorizedAPICalls', count: 9 }).result.fired).toEqual(['a1']); expect(l.state.cloudwatch.notifications).toHaveLength(1);
  });
  it('IAM role changes affect Lambda; secret rotation revokes the old credential', () => {
    const l = new Lab(); expect(l.ok('lambda.invoke', { name: fx.FN }).result.ok).toBe(true);
    l.ok('iam.updatePolicy', { policyId: 'pol-order', document: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'logs:*', Resource: '*' }] } });
    expect(l.ok('lambda.invoke', { name: fx.FN }).result.error).toMatch(/s3:PutObject/); expect(l.status.outages[0].probe).toBe('orders');
    l.ok('iam.restorePolicyVersion', { policyId: 'pol-order', versionId: 'v1' }); steps.v6(l);
    expect(l.finding('V6').status).toBe('Verified'); expect(l.ok('secrets.testCredential', { source: 'leaked' }).result.accepted).toBe(false);
    expect(JSON.stringify(E.view(l.state))).not.toContain('ncpg_SYNTHETIC_rot');
  });
  it('a mistyped secret cannot be rotated', () => { const l = new Lab(); l.ok('secrets.create', { name: 'x/pg', value: 'wrong' }); expect(l.do('secrets.rotate', { name: 'x/pg' }).code).toBe('RotationFailed'); });
  it('SSE-KMS makes S3 access depend on the key policy', () => {
    const l = new Lab(); steps.v5(l); expect(l.finding('V5').status).toBe('Verified');
    l.ok('kms.putKeyPolicy', { keyId: fx.DATA_KEY, document: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: arn.role('nc-kms-admin-role') }, Action: 'kms:*', Resource: '*' }] } });
    expect(l.ok('s3.accessTest', { bucket: DOCS, key: 'invoices/t.json', principal: R_APP, operation: 'PUT' }).result.reason).toMatch(/GenerateDataKey/); expect(l.status.health.find((h: any) => h.id === 'invoices').ok).toBe(false);
  });
  it('an SCP overrides administrator permissions; a harmful SCP breaks production', () => {
    const l = new Lab(); steps.v10(l); expect(l.finding('V10').status).toBe('Verified');
    l.ok('org.attachScp', { scpId: 'p-s3quarantine', targetId: '123456789012' }); expect(l.status.health.filter((h: any) => !h.ok).length).toBeGreaterThan(1); expect(l.finding('V10').status).toBe('Open');
    expect(l.do('s3.putPublicAccessBlock', { bucket: DOCS, config: { blockPublicAcls: true, ignorePublicAcls: true, blockPublicPolicy: true, restrictPublicBuckets: true } }).code).toBe('AccessDenied');
    l.ok('org.detachScp', { scpId: 'p-s3quarantine', targetId: '123456789012' }); expect(l.status.health.every((h: any) => h.ok)).toBe(true);
  });
});

describe('story, attacker and scoring', () => {
  it('level 1 unlocks level 2 and starts the incident', () => { const l = new Lab(); steps.level1(l); const st = l.status; expect(st.level).toBe(2); expect(st.alerts[0].id).toBe('AL-0'); expect(st.incident.severity).toBe('High'); expect(st.chapter).toBeGreaterThanOrEqual(3); });
  it('an uncontained intruder escalates deterministically', () => {
    const run = () => { const l = new Lab(); steps.level1(l); for (let i = 0; i < 70; i++) l.ok('iam.simulate', { principal: RAHUL, action: 's3:ListBucket', resource: '*' }); return l; };
    const a = run(), b = run();
    expect(a.state.iam.users['support-temp-01']).toBeTruthy(); expect(a.state.sim.attacker.secretStolen).toBe(true); expect(a.state.sim.attacker.fraud).toBe(true); expect(a.status.incident.severity).toBe('Critical');
    expect(a.status.score.penalties.find((p: any) => /Intruder/.test(p.label)).points).toBe(32);
    expect(JSON.stringify(a.state.sim.timeline)).toBe(JSON.stringify(b.state.sim.timeline)); // reproducible
    a.ok('iam.setAccessKeyStatus', { userName: 'svc-storefront-app', accessKeyId: fx.KEY_OLD, status: 'Inactive' }); expect(a.obj('L2.contain').done).toBe(false); // backdoor key still active
    a.ok('iam.setAccessKeyStatus', { userName: 'support-temp-01', accessKeyId: fx.KEY_BACKDOOR, status: 'Inactive' }); expect(a.obj('L2.contain').done).toBe(true);
  });
  it('deactivating the application key instead breaks the storefront', () => { const l = new Lab(); steps.level1(l); l.ok('iam.setAccessKeyStatus', { userName: 'svc-storefront-app', accessKeyId: fx.KEY_APP, status: 'Inactive' }); expect(l.status.health.find((h: any) => h.id === 'asset-upload').ok).toBe(false); expect(l.obj('L2.contain').done).toBe(false); });
  it('full walkthrough L1 → L4 produces an evidence-based report', () => {
    const l = new Lab(); steps.level1(l); steps.level2(l); expect(l.status.level).toBe(3); expect(l.state.sim.attacker.successes).toBe(0);
    steps.level3(l); const s3 = l.status; expect(s3.findings.every((f: any) => f.status === 'Verified')).toBe(true); expect(s3.level).toBe(4); expect(s3.health.every((h: any) => h.ok)).toBe(true);
    steps.level4(l); const st = l.status; expect(st.complete).toBe(true); expect(st.score.total).toBe(st.score.max); expect(st.incident.severity).toBe('Resolved');
    const r = E.report(l.state, { learner: 't' }); expect(r.findings.every((f: any) => f.verified)).toBe(true); expect(r.reportAssessment.total).toBe(40); expect(r.remediationActions.length).toBeGreaterThan(10); expect(r.containmentActions.length).toBeGreaterThan(1);
    expect(l.state.labEvents.filter((e: any) => e.outcome === 'Success').length).toBe(l.state.eventSeq); expect(l.state.labEvents.map((e: any) => e.seq)).toEqual(l.state.labEvents.map((_: any, i: number) => i + 1));
    expect(l.do('s3.putBucketPolicy', { bucket: DOCS, document: null }).code).toBe('LabComplete');
  });
  it('the report never claims unverified work is secure', () => { const l = new Lab(); l.report('V2', `s3/bucket/${DOCS}#permissions`, `s3/bucket/${DOCS}`); l.ok('s3.putPublicAccessBlock', { bucket: DOCS, config: { blockPublicAcls: true, ignorePublicAcls: true, blockPublicPolicy: true, restrictPublicBuckets: true } }); const f = E.report(l.state, {}).findings.find((x: any) => x.id === 'V2'); expect(f.remediated).toBe(true); expect(f.verified).toBe(false); expect(f.statement).toMatch(/NOT verified/); });
  it('public projections expose no answers', () => {
    const l = new Lab(); const out = JSON.stringify([E.view(l.state), E.status(l.state), E.definition()]);
    for (const leak of ['"truth"', 'remediated', 'ATTACKER', 'gateway":{', 'stolenValue', 'DenyAuditLogTampering to the', 'Access Advisor tab shows', 'Block Public Access is the guardrail']) expect(out).not.toContain(leak);
    expect(E.status(l.state).findings[3]).toEqual({ id: 'V4', title: 'Missing CloudTrail audit coverage', status: 'Not found' });
  });
});
