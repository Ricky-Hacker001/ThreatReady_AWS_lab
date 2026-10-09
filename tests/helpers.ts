import { cloudLab001 as E } from '../server/engine';
import * as fx from '../server/fixture';
import { arn, ANON } from '../server/policy';
export { E, fx, arn, ANON };
export const SVC = arn.user('svc-storefront-app'), R_APP = arn.role('nc-app-server-role'), R_ORDER = arn.role('nc-order-processor-role'), RAHUL = arn.user('dev-rahul');
export const DOCS = 'novacart-internal-docs';
const V = '2012-10-17';
export class Lab {
  state = E.createInitialState(); last: any;
  do(type: string, params: any = {}) { const r = E.dispatch(this.state, { type, params }); this.state = r.state; this.last = r.result; return r.result; }
  ok(type: string, params: any = {}) { const r = this.do(type, params); if (!r.ok) throw new Error(`${type} failed: ${r.code} ${r.message}`); return r; }
  get status() { return E.status(this.state); }
  finding(id: string) { return this.status.findings.find((f: any) => f.id === id); }
  obj(id: string) { return this.status.objectives.find((o: any) => o.id === id); }
  report(v: string, key: string, resource: string) { this.ok('inspect', { key }); this.ok('finding.report', { findingId: v, resource }); }
}
export const APP_POLICY = { Version: V, Statement: [{ Effect: 'Allow', Action: ['s3:GetObject', 's3:PutObject'], Resource: 'arn:aws:s3:::novacart-product-assets/*' }, { Effect: 'Allow', Action: 's3:ListBucket', Resource: 'arn:aws:s3:::novacart-product-assets' }] };
export const orderPolicy = (secret: string) => ({ Version: V, Statement: [
  { Effect: 'Allow', Action: ['logs:CreateLogStream', 'logs:PutLogEvents'], Resource: arn.logGroup('/aws/lambda/nc-order-processor') },
  { Effect: 'Allow', Action: 's3:PutObject', Resource: 'arn:aws:s3:::novacart-order-exports/exports/*' },
  { Effect: 'Allow', Action: 'secretsmanager:GetSecretValue', Resource: arn.secret(secret) }] });
export const KEY_POLICY = { Version: V, Statement: [
  { Sid: 'Admins', Effect: 'Allow', Principal: { AWS: arn.role('nc-kms-admin-role') }, Action: ['kms:Describe*', 'kms:Get*', 'kms:List*', 'kms:PutKeyPolicy'], Resource: '*' },
  { Sid: 'Use', Effect: 'Allow', Principal: { AWS: R_APP }, Action: ['kms:Encrypt', 'kms:Decrypt', 'kms:GenerateDataKey'], Resource: '*' }] };

export const steps = {
  v1find: (l: Lab) => l.report('V1', 'iam/policy/pol-app#permissions', 'iam/policy/pol-app'),
  v1fix: (l: Lab) => { l.ok('iam.updatePolicy', { policyId: 'pol-app', document: APP_POLICY }); l.ok('iam.simulate', { principal: SVC, action: 's3:PutObject', resource: 'arn:aws:s3:::novacart-product-assets/uploads/a.jpg' }); l.ok('iam.simulate', { principal: SVC, action: 'iam:CreateUser', resource: '*' }); },
  v2: (l: Lab) => { l.report('V2', `s3/bucket/${DOCS}#permissions`, `s3/bucket/${DOCS}`);
    l.ok('s3.putPublicAccessBlock', { bucket: DOCS, config: { blockPublicAcls: true, ignorePublicAcls: true, blockPublicPolicy: true, restrictPublicBuckets: true } });
    l.ok('s3.accessTest', { bucket: DOCS, key: 'finance/payroll-2026-09.csv', principal: ANON, operation: 'GET' }); l.ok('s3.accessTest', { bucket: DOCS, key: 'invoices/INV-2026-10-0001.json', principal: R_APP, operation: 'GET' }); },
  v3: (l: Lab) => { l.report('V3', `ec2/sg/${fx.SG_APP}#inbound`, `ec2/sg/${fx.SG_APP}`);
    l.ok('ec2.removeIngressRule', { groupId: fx.SG_APP, ruleId: 'sgr-app3' }); l.ok('ec2.removeIngressRule', { groupId: fx.SG_APP, ruleId: 'sgr-app4' });
    l.ok('ec2.updateIngressRule', { groupId: fx.SG_APP, ruleId: 'sgr-app2', port: 22, source: '203.0.113.0/24', description: 'office vpn' });
    l.ok('ec2.reachabilityTest', { source: 'internet', target: fx.I_APP, port: 22 }); l.ok('ec2.reachabilityTest', { source: 'alb', target: fx.I_APP, port: 8080 }); },
  level1: (l: Lab) => { l.ok('incident.acknowledge'); steps.v1find(l); steps.v2(l); steps.v3(l); l.ok('evidence.add', { eventId: 'evt-0017' }); },
  v6: (l: Lab) => { l.report('V6', `lambda/function/${fx.FN}#configuration`, `lambda/function/${fx.FN}`);
    l.ok('secrets.create', { name: 'novacart/prod/payment-gateway', value: fx.LEAKED_CRED });
    const env = { ...l.state.lambda.functions[fx.FN].env }; delete env.PAYMENT_GATEWAY_KEY; env.PAYMENT_SECRET_ARN = arn.secret('novacart/prod/payment-gateway');
    l.ok('lambda.updateConfig', { name: fx.FN, env }); l.ok('secrets.rotate', { name: 'novacart/prod/payment-gateway' });
    l.ok('lambda.invoke', { name: fx.FN }); l.ok('secrets.testCredential', { source: 'leaked' }); },
  level2: (l: Lab) => { l.ok('incident.declareCompromisedKey', { accessKeyId: fx.KEY_OLD }); for (const e of ['evt-0010', 'evt-0011']) l.ok('evidence.add', { eventId: e });
    l.ok('iam.setAccessKeyStatus', { userName: 'svc-storefront-app', accessKeyId: fx.KEY_OLD, status: 'Inactive' }); steps.v6(l); steps.v1fix(l);
    l.ok('s3.accessTest', { bucket: DOCS, key: 'finance/payroll-2026-09.csv', principal: SVC, operation: 'GET', accessKeyId: fx.KEY_OLD }); },
  v4: (l: Lab) => { l.report('V4', `cloudtrail/trail/${fx.TRAIL}#configuration`, `cloudtrail/trail/${fx.TRAIL}`); l.ok('cloudtrail.updateTrail', { name: fx.TRAIL, multiRegion: true, managementEvents: 'All', logFileValidation: true }); l.ok('cloudtrail.startLogging', { name: fx.TRAIL }); l.ok('cloudtrail.auditTest'); },
  v9: (l: Lab) => { l.report('V9', `kms/key/${fx.DATA_KEY}#policy`, `kms/key/${fx.DATA_KEY}`); l.ok('kms.putKeyPolicy', { keyId: fx.DATA_KEY, document: KEY_POLICY }); l.ok('kms.cryptoTest', { keyId: fx.DATA_KEY, principal: SVC, operation: 'Decrypt' }); l.ok('kms.cryptoTest', { keyId: fx.DATA_KEY, principal: R_APP, operation: 'Decrypt' }); },
  v5: (l: Lab) => { l.report('V5', `s3/bucket/${DOCS}#properties`, `s3/bucket/${DOCS}`); l.ok('s3.putEncryption', { bucket: DOCS, mode: 'SSE-KMS', keyId: fx.DATA_KEY }); l.ok('s3.reencryptObjects', { bucket: DOCS }); l.ok('s3.accessTest', { bucket: DOCS, key: 'invoices/t.json', principal: R_APP, operation: 'PUT' }); },
  v7: (l: Lab) => { l.report('V7', 'iam/policy/pol-order#permissions', 'iam/policy/pol-order'); l.ok('iam.updatePolicy', { policyId: 'pol-order', document: orderPolicy('novacart/prod/payment-gateway') }); l.ok('lambda.invoke', { name: fx.FN }); l.ok('iam.simulate', { principal: R_ORDER, action: 'iam:PassRole', resource: '*' }); },
  v8: (l: Lab) => { l.report('V8', 'cloudwatch/alarms/all#list', 'cloudwatch/alarms/all'); l.ok('cloudwatch.putAlarm', { name: 'nc-unauthorized-api', metric: 'UnauthorizedAPICalls', comparison: '>=', threshold: 5, period: 300, topic: 'nc-security-alerts' }); l.ok('cloudwatch.sendTestEvents', { metric: 'UnauthorizedAPICalls', count: 8 }); },
  v10: (l: Lab) => { l.report('V10', 'org/policies/all#list', 'org/policies/all'); l.ok('org.attachScp', { scpId: 'p-audit', targetId: 'ou-nc01-prod' }); l.ok('iam.simulate', { principal: RAHUL, action: 'cloudtrail:StopLogging', resource: arn.trail(fx.TRAIL) }); l.ok('iam.simulate', { principal: RAHUL, action: 's3:ListBucket', resource: 'arn:aws:s3:::novacart-product-assets' }); },
  level3: (l: Lab) => { steps.v4(l); steps.v9(l); steps.v5(l); steps.v7(l); steps.v8(l); steps.v10(l); l.ok('l3.regression'); },
  level4: (l: Lab) => { l.ok('inspect', { key: 'cloudwatch/log/ci/novacart-storefront-build/build-482#events' }); l.ok('inspect', { key: 'cloudwatch/log//var/log/auth/nc-app-server/sshd#events' });
    l.ok('l4.triage', { alertId: 'AL-1', classification: 'blocked-attempt' }); l.ok('l4.triage', { alertId: 'AL-2', classification: 'expected-activity' }); l.ok('l4.triage', { alertId: 'AL-3', classification: 'confirmed-incident' });
    l.ok('l4.submitReport', { rootCause: 'ci-leak', credential: fx.KEY_OLD, timeline: ['t-leak', 't-first', 't-recon', 't-stop', 't-exfil'], affected: ['svc', 'docs', 'trail'], residual: ['r-recall', 'r-gap', 'r-subnet'], hardening: ['h-roles', 'h-scan', 'h-mfa', 'h-private', 'h-rotate'], summary: 'A long-lived access key leaked through a public CI build log was used to enumerate the account, stop CloudTrail and download confidential documents.', containmentRationale: 'Deactivated only the leaked key so the storefront kept running.' }); },
};
