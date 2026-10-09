// SERVER-ONLY scenario definition: findings, verification predicates, objectives, hints, attacker script, rubric.
// Nothing in this file is ever serialised to the client except through explicit, state-gated projections in engine.ts.
import { arn, authorize, ANON, cidrWithin, statements } from './policy';
import { reach, s3Access, lambdaRun, findSecretByRef, currentValue, health } from './sim';
import { SG_APP, I_APP, TRAIL, FN, DATA_KEY, KEY_OLD, KEY_BACKDOOR, LEAKED_CRED } from './fixture';

const SVC = arn.user('svc-storefront-app');
const R_ORDER = arn.role('nc-order-processor-role');
const R_APP = arn.role('nc-app-server-role');
const R_KMS = arn.role('nc-kms-admin-role');
const can = (s: any, principal: string, action: string, resource: string) => authorize(s, { principal, action, resource }).allowed;
// identity policies + SCPs only, like the IAM policy simulator
const canId = (s: any, principal: string, action: string, resource: string) => authorize(s, { principal, action, resource, skipResourcePolicy: true }).allowed;
const DOCS = 'novacart-internal-docs';

const V1_REQUIRED: [string, string][] = [['s3:GetObject', 'arn:aws:s3:::novacart-product-assets/public/logo.png'], ['s3:PutObject', 'arn:aws:s3:::novacart-product-assets/uploads/x.jpg'], ['s3:ListBucket', 'arn:aws:s3:::novacart-product-assets']];
const V1_FORBIDDEN: [string, string][] = [['iam:CreateUser', arn.user('x')], ['iam:CreateAccessKey', SVC], ['iam:AttachUserPolicy', SVC], ['cloudtrail:StopLogging', arn.trail(TRAIL)], ['s3:GetObject', `arn:aws:s3:::${DOCS}/finance/payroll-2026-09.csv`], ['s3:PutBucketPolicy', `arn:aws:s3:::${DOCS}`], ['s3:DeleteObject', 'arn:aws:s3:::novacart-product-assets/public/logo.png'], ['lambda:GetFunctionConfiguration', arn.fn(FN)], ['secretsmanager:GetSecretValue', arn.secret('novacart/prod/db-master')], ['ec2:AuthorizeSecurityGroupIngress', arn.sg(SG_APP)], ['kms:Decrypt', arn.key(DATA_KEY)]];
const V7_REQUIRED: [string, string][] = [['logs:CreateLogStream', arn.logGroup(`/aws/lambda/${FN}`)], ['logs:PutLogEvents', arn.logGroup(`/aws/lambda/${FN}`)], ['s3:PutObject', 'arn:aws:s3:::novacart-order-exports/exports/x.json']];
const V7_FORBIDDEN: [string, string][] = [['s3:GetObject', `arn:aws:s3:::${DOCS}/finance/payroll-2026-09.csv`], ['s3:DeleteObject', 'arn:aws:s3:::novacart-order-exports/exports/x.json'], ['s3:PutObject', 'arn:aws:s3:::novacart-product-assets/public/logo.png'], ['iam:PassRole', arn.role('nc-kms-admin-role')], ['secretsmanager:GetSecretValue', arn.secret('novacart/prod/db-master')], ['dynamodb:DeleteTable', 'arn:aws:dynamodb:ap-south-1:123456789012:table/orders'], ['logs:DeleteLogGroup', arn.logGroup(`/aws/lambda/${FN}`)]];

export const v6Config = (s: any) => {
  const f = s.lambda.functions[FN];
  if (Object.values<string>(f.env).some(v => s.gateway.history.includes(v))) return false;
  const sec = findSecretByRef(s, f.env.PAYMENT_SECRET_ARN);
  return !!sec && currentValue(sec) === s.gateway.current && s.gateway.current !== LEAKED_CRED && can(s, R_ORDER, 'secretsmanager:GetSecretValue', arn.secret(sec.name));
};
export const goodAlarm = (s: any, a: any) => a.metric === 'UnauthorizedAPICalls' && ['>=', '>'].includes(a.comparison) && a.threshold >= 1 && a.threshold <= 10 && a.topic === 'nc-security-alerts';
const RAHUL = arn.user('dev-rahul');
const scpCovers = (s: any) => !canId(s, RAHUL, 'cloudtrail:StopLogging', arn.trail(TRAIL)) && !canId(s, RAHUL, 'cloudtrail:DeleteTrail', arn.trail(TRAIL))
  && canId(s, RAHUL, 's3:GetObject', 'arn:aws:s3:::novacart-product-assets/public/logo.png') && canId(s, RAHUL, 'iam:CreatePolicyVersion', 'arn:aws:iam::123456789012:policy/x') && canId(s, RAHUL, 'cloudtrail:StartLogging', arn.trail(TRAIL));

export interface Check { id: string; label: string; match: (t: any, s: any) => boolean }
export interface FindingDef { id: string; title: string; service: string; severity: string; severityWhy: string; business: string; technical: string; resources: string[]; inspect: string[]; remediated: (s: any) => boolean; checks: Check[]; explanation: string; level: number }

export const FINDINGS: FindingDef[] = [
  { id: 'V1', level: 1, title: 'Overly permissive IAM policy', service: 'IAM', severity: 'Critical',
    severityWhy: 'A long-lived application credential carries full administrative rights over the account.',
    business: 'Anyone holding the storefront application credential can read customer data, change infrastructure and hide their tracks.',
    technical: 'NovaCartAppPolicy grants Action "*" on Resource "*". The application only needs three S3 actions on one bucket.',
    resources: ['iam/policy/pol-app', 'iam/user/svc-storefront-app'], inspect: ['iam/policy/pol-app#permissions'],
    remediated: s => V1_REQUIRED.every(([a, r]) => canId(s, SVC, a, r)) && V1_FORBIDDEN.every(([a, r]) => !canId(s, SVC, a, r)),
    checks: [
      { id: 'V1.allowed', label: 'A required storefront action is confirmed as allowed in the policy simulator', match: t => t.kind === 'iam.simulate' && t.principal === SVC && t.allowed && t.resource.startsWith('arn:aws:s3:::novacart-product-assets') },
      { id: 'V1.denied', label: 'An action outside the application\'s needs is confirmed as denied', match: t => t.kind === 'iam.simulate' && t.principal === SVC && !t.allowed }],
    explanation: 'Least privilege means the policy lists only the actions and resources the workload actually uses. Access Advisor data (observed usage) is the evidence base: here S3 GetObject/PutObject/ListBucket on novacart-product-assets. Scoping the policy turns a stolen key from "account takeover" into "can touch product images".' },
  { id: 'V2', level: 1, title: 'Publicly exposed S3 bucket', service: 'S3', severity: 'High',
    severityWhy: 'Confidential finance, HR and customer documents are readable by anyone on the internet without credentials.',
    business: 'Payroll, contracts and a customer export can be downloaded anonymously — a reportable data exposure.',
    technical: 'The bucket policy allows s3:GetObject to Principal "*", one object carries a public-read ACL, and all four Block Public Access settings are off.',
    resources: ['s3/bucket/novacart-internal-docs'], inspect: ['s3/bucket/novacart-internal-docs#permissions'],
    remediated: s => s.s3.buckets[DOCS].objects.every((o: any) => !authorize(s, { principal: ANON, action: 's3:GetObject', resource: arn.object(DOCS, o.key) }).allowed),
    checks: [
      { id: 'V2.anon', label: 'An anonymous read of an internal document is denied', match: t => t.kind === 's3.access' && t.bucket === DOCS && t.principal === ANON && t.operation === 'GET' && !t.allowed },
      { id: 'V2.app', label: 'The app server role can still read or write the bucket', match: t => t.kind === 's3.access' && t.bucket === DOCS && t.principal === R_APP && t.allowed }],
    explanation: 'Public exposure had two independent causes: a bucket policy with Principal "*" and an object ACL. Block Public Access is the guardrail that neutralises both (RestrictPublicBuckets for policies, IgnorePublicAcls for ACLs), while removing the public statement fixes the root cause. Authorised access via IAM roles is unaffected.' },
  { id: 'V3', level: 1, title: 'Unrestricted security group', service: 'EC2 / VPC', severity: 'High',
    severityWhy: 'Management and debug ports on a production server are reachable from any internet address.',
    business: 'The production API server is exposed to brute-force and remote-debug attacks that bypass the load balancer.',
    technical: 'nc-app-server-sg allows tcp/22, tcp/8080 and tcp/9229 from 0.0.0.0/0. Only the ALB should reach 8080; SSH should be limited to the office VPN range.',
    resources: [`ec2/sg/${SG_APP}`], inspect: [`ec2/sg/${SG_APP}#inbound`],
    remediated: s => { const g = s.ec2.securityGroups[SG_APP]; return reach(s, 'alb', I_APP, 8080).allowed && g.inbound.every((r: any) => r.source.startsWith('sg-') || (cidrWithin(r.source, '203.0.113.0/24') && r.port === 22)); },
    checks: [
      { id: 'V3.blocked', label: 'A connection from the internet to the app server is blocked', match: t => t.kind === 'ec2.reach' && t.source === 'internet' && t.target === I_APP && !t.allowed },
      { id: 'V3.alb', label: 'The load balancer can still reach the app on tcp/8080', match: t => t.kind === 'ec2.reach' && t.source === 'alb' && t.target === I_APP && t.port === 8080 && t.allowed }],
    explanation: 'Security groups are allow-lists. Referencing the ALB\'s security group as the source keeps application traffic flowing while removing direct internet paths; SSH is narrowed to a known CIDR. The public ALB rule on 443 is intentional — exposure is judged per resource, not by the presence of 0.0.0.0/0 alone.' },
  { id: 'V4', level: 3, title: 'Missing CloudTrail audit coverage', service: 'CloudTrail', severity: 'High',
    severityWhy: 'Without a complete management-event trail, attacker activity cannot be reconstructed.',
    business: 'NovaCart cannot prove what an intruder did after the trail was stopped — a problem for customers, auditors and insurers.',
    technical: 'The only trail is not logging, covers a single region and records read-only management events only.',
    resources: [`cloudtrail/trail/${TRAIL}`], inspect: [`cloudtrail/trail/${TRAIL}#configuration`],
    remediated: s => { const t = s.cloudtrail.trails[TRAIL]; return t.logging && t.multiRegion && t.managementEvents === 'All'; },
    checks: [{ id: 'V4.audit', label: 'A synthetic write event in another region appears in event history', match: t => t.kind === 'cloudtrail.audit' && t.recorded }],
    explanation: 'A trail must be logging, multi-region and capture both read and write management events to be useful. Restarting it restores visibility going forward only: events during the gap were never recorded and cannot be recovered — other sources (S3 access logs, application logs) have to fill in.' },
  { id: 'V5', level: 3, title: 'Unencrypted sensitive S3 data', service: 'S3 / KMS', severity: 'Medium',
    severityWhy: 'Confidential data lacks the customer-managed-key encryption the data policy requires; exposure depends on other controls failing.',
    business: 'Confidential documents do not meet NovaCart\'s data-handling policy, weakening its compliance position.',
    technical: 'novacart-internal-docs has no default encryption and its existing objects are stored unencrypted.',
    resources: ['s3/bucket/novacart-internal-docs'], inspect: ['s3/bucket/novacart-internal-docs#properties'],
    remediated: s => { const b = s.s3.buckets[DOCS]; return b.encryption.mode === 'SSE-KMS' && b.encryption.keyId === DATA_KEY && b.objects.every((o: any) => o.encryption === 'SSE-KMS' && o.keyId === DATA_KEY); },
    checks: [{ id: 'V5.write', label: 'A new write by the app server role is stored with SSE-KMS', match: t => t.kind === 's3.access' && t.bucket === DOCS && t.operation === 'PUT' && t.principal === R_APP && t.allowed && t.encryption === 'SSE-KMS' }],
    explanation: 'Default encryption applies to new objects only. Existing objects keep whatever encryption they were written with until they are re-written, which is why re-encryption is a separate operation. With SSE-KMS, access also requires permission on the key — an extra, auditable control layer.' },
  { id: 'V6', level: 2, title: 'Exposed application secret', service: 'Lambda / Secrets Manager', severity: 'High',
    severityWhy: 'A live payment-gateway credential is readable by anyone who can view the function configuration.',
    business: 'A stolen payment credential enables fraudulent transactions in NovaCart\'s name.',
    technical: 'nc-order-processor stores the gateway credential in a plaintext environment variable; lambda:GetFunctionConfiguration is enough to read it.',
    resources: [`lambda/function/${FN}`], inspect: [`lambda/function/${FN}#configuration`],
    remediated: v6Config,
    checks: [
      { id: 'V6.invoke', label: 'The function\'s test event succeeds using the secret from Secrets Manager', match: t => t.kind === 'lambda.invoke' && t.name === FN && t.ok },
      { id: 'V6.old', label: 'The previously exposed credential is rejected by the payment gateway', match: t => t.kind === 'secrets.testCredential' && t.source === 'leaked' && !t.accepted }],
    explanation: 'Moving a secret is not enough once it has been exposed — it must be rotated so the old value is worthless. Secrets Manager gives per-secret IAM scoping, versioning and an access audit trail; the function receives only a reference (ARN), never the value, in its configuration.' },
  { id: 'V7', level: 3, title: 'Over-privileged Lambda execution role', service: 'Lambda / IAM', severity: 'High',
    severityWhy: 'A code flaw or dependency compromise in one function would yield broad data and privilege-escalation access.',
    business: 'A bug in order processing could expose every bucket, every secret and allow privilege escalation.',
    technical: 'nc-order-processor-policy allows s3:*, secretsmanager:*, dynamodb:*, kms:*, logs:* and iam:PassRole on all resources.',
    resources: ['iam/policy/pol-order', 'iam/role/nc-order-processor-role', `lambda/function/${FN}`], inspect: ['iam/policy/pol-order#permissions'],
    remediated: s => V7_REQUIRED.every(([a, r]) => canId(s, R_ORDER, a, r)) && V7_FORBIDDEN.every(([a, r]) => !canId(s, R_ORDER, a, r)) && lambdaRun(s, FN).ok,
    checks: [
      { id: 'V7.invoke', label: 'The function\'s test event still succeeds', match: t => t.kind === 'lambda.invoke' && t.name === FN && t.ok },
      { id: 'V7.denied', label: 'An action the function does not need is confirmed as denied for its role', match: t => t.kind === 'iam.simulate' && t.principal === R_ORDER && !t.allowed }],
    explanation: 'An execution role should be derived from what the function does: its own log group, its export prefix and its one secret. Execution logs and Access Advisor show real usage; everything else (including iam:PassRole, a classic escalation path) is removed.' },
  { id: 'V8', level: 3, title: 'Missing security alarm', service: 'CloudWatch', severity: 'Medium',
    severityWhy: 'Detection gap: hostile API activity generates no alert, lengthening attacker dwell time.',
    business: 'The intrusion ran for days because nobody was notified of a burst of denied API calls.',
    technical: 'The UnauthorizedAPICalls metric exists but has no alarm; the only alarm watches CPU.',
    resources: ['cloudwatch/alarms/all'], inspect: ['cloudwatch/alarms/all#list'],
    remediated: s => Object.values<any>(s.cloudwatch.alarms).some(a => goodAlarm(s, a)),
    checks: [{ id: 'V8.fired', label: 'Test events drive the alarm into ALARM and a notification is delivered', match: (t, s) => t.kind === 'cw.test' && t.fired.some((n: string) => s.cloudwatch.alarms[n] && goodAlarm(s, s.cloudwatch.alarms[n])) }],
    explanation: 'A detection is a metric, a threshold and a destination. The alarm on UnauthorizedAPICalls only works while CloudTrail is delivering events — detections depend on log coverage, which is why the trail and the alarm are verified together.' },
  { id: 'V9', level: 3, title: 'Weak KMS key policy', service: 'KMS', severity: 'High',
    severityWhy: 'The key protecting confidential data can be used by every principal in the account.',
    business: 'Encryption adds no protection if any identity can decrypt.',
    technical: 'The key policy grants kms:* to Principal {"AWS": "*"}. Usage should be limited to nc-app-server-role and administration to nc-kms-admin-role.',
    resources: [`kms/key/${DATA_KEY}`], inspect: [`kms/key/${DATA_KEY}#policy`],
    remediated: s => { const k = arn.key(DATA_KEY); return can(s, R_APP, 'kms:Decrypt', k) && can(s, R_APP, 'kms:GenerateDataKey', k) && can(s, R_KMS, 'kms:PutKeyPolicy', k) && !can(s, SVC, 'kms:Decrypt', k) && !can(s, R_ORDER, 'kms:Decrypt', k) && !can(s, arn.user('ops-priya'), 'kms:Decrypt', k); },
    checks: [
      { id: 'V9.denied', label: 'A principal with no need for the key is denied a decrypt operation', match: t => t.kind === 'kms.crypto' && ![R_APP, R_KMS].includes(t.principal) && !t.allowed },
      { id: 'V9.allowed', label: 'The app server role can still use the key', match: t => t.kind === 'kms.crypto' && t.principal === R_APP && t.allowed }],
    explanation: 'A key policy is the root of trust for a KMS key: unlike other resources, IAM policies alone never grant access unless the key policy delegates to IAM through the account root principal. Separating administrators (manage the policy) from users (encrypt/decrypt) limits blast radius, and KMS refuses policies that would lock out every administrator.' },
  { id: 'V10', level: 3, title: 'Missing organization guardrail', service: 'Organizations', severity: 'Medium',
    severityWhy: 'No preventive control stops a compromised or careless administrator from disabling audit logging.',
    business: 'A single compromised identity was able to switch off NovaCart\'s audit trail.',
    technical: 'No service control policy protecting CloudTrail is attached to the production account, its OU or the root.',
    resources: ['org/policies/all', 'org/account/123456789012'], inspect: ['org/policies/all#list'],
    remediated: s => scpCovers(s),
    checks: [
      { id: 'V10.denied', label: 'An administrator\'s attempt to stop CloudTrail is denied by the guardrail', match: t => t.kind === 'iam.simulate' && /^cloudtrail:(StopLogging|DeleteTrail)$/i.test(t.action) && !t.allowed && /service control policy/.test(t.reason) },
      { id: 'V10.allowed', label: 'An unrelated, legitimate operation is still allowed', match: t => t.kind === 'iam.simulate' && t.allowed }],
    explanation: 'Three layers decide access: identity policies grant, resource policies grant or restrict per resource, and SCPs set the maximum any identity in the account can ever have — they never grant. An SCP deny holds even against AdministratorAccess, which is what makes it a guardrail rather than a permission.' },
];
export const FINDING = Object.fromEntries(FINDINGS.map(f => [f.id, f]));

export const ATTACKER_EVENT_IDS = ['evt-0010', 'evt-0011', 'evt-0012', 'evt-0013', 'evt-0014', 'evt-0016', 'evt-0017'];
export const contained = (s: any) => {
  const off = (u: string, k: string) => { const key = s.iam.users[u]?.accessKeys.find((x: any) => x.id === k); return !key || key.status !== 'Active'; };
  return off('svc-storefront-app', KEY_OLD) && off('support-temp-01', KEY_BACKDOOR);
};

export interface ObjectiveDef { id: string; level: number; title: string; points: number; category: string; finding?: string; kind?: 'find' | 'fix'; sticky?: boolean; done: (s: any) => boolean; hints: string[]; prereq?: string }
const find = (v: string, level: number, hints: string[]): ObjectiveDef => ({ id: `${v}.find`, level, title: `Identify: ${FINDING[v].title}`, points: 10, category: 'investigation', finding: v, kind: 'find', sticky: true, done: s => !!s.sim.findings[v]?.discovered, hints });
const fix = (v: string, level: number, points: number, hints: string[]): ObjectiveDef => ({ id: `${v}.fix`, level, title: `Remediate and verify: ${FINDING[v].title}`, points, category: 'remediation', finding: v, kind: 'fix', done: s => !!s.sim.findings[v]?.verified, hints, prereq: `${v}.find` });

export const OBJECTIVES: ObjectiveDef[] = [
  { id: 'L1.ack', level: 1, title: 'Acknowledge incident ticket INC-2041 in the Incident Center', points: 5, category: 'investigation', sticky: true, done: s => s.incident.acknowledged, hints: ['Open Incident Center (left menu) and read ticket INC-2041.', 'Open Incident Center\nFind ticket INC-2041\nClick "Acknowledge ticket"'] },
  find('V1', 1, ['The storefront app\'s IAM policy may allow far more than the app needs.', 'Go to IAM → Policies → NovaCartAppPolicy\nOpen the Permissions tab\nClick "Report finding"']),
  find('V2', 1, ['One bucket holds confidential files. Can the public read it?', 'Go to S3 → novacart-internal-docs → Permissions\nClick "Report finding"']),
  fix('V2', 1, 20, ['The bucket is public in two ways (bucket policy and ACL). One setting blocks both: Block Public Access.', 'Turn on Block Public Access for the bucket\nAccess test: anonymous GET → should be denied\nAccess test: nc-app-server-role → should still be allowed']),
  find('V3', 1, ['Compare the app server\'s firewall rules with the network policy in Incident Center.', 'Go to EC2 → Security groups → nc-app-server-sg\nOpen Inbound rules\nClick "Report finding"']),
  fix('V3', 1, 20, ['Only two rules are allowed: port 8080 from the load balancer, and port 22 from the office VPN (203.0.113.0/24).', 'On nc-app-server-sg, remove or narrow every 0.0.0.0/0 rule\nKeep the rule from nc-alb-sg\nReachability test from Internet → should be blocked\nReachability test from the ALB → should work']),
  { id: 'L1.trail', level: 1, title: 'Preserve the last recorded audit event as evidence', points: 10, category: 'evidence', sticky: true, done: s => s.sim.evidence.includes('evt-0017'), hints: ['In CloudTrail, look at the very last event. What happened, and who did it?', 'Go to CloudTrail → Event history\nOpen the StopLogging event\nClick "Add to evidence locker"'] },

  { id: 'L2.declare', level: 2, title: 'Identify the compromised credential', points: 10, category: 'investigation', sticky: true, done: s => s.incident.declaredKey === KEY_OLD, hints: ['The app uses its key from inside (10.0.1.25). Which key is used from somewhere else?', 'In CloudTrail, compare each event\'s access key ID and source IP\nThe key used from an external IP is the stolen one\nDeclare it in Incident Center'] },
  { id: 'L2.evidence', level: 2, title: 'Preserve at least three audit events showing the intruder\'s activity', points: 15, category: 'evidence', sticky: true, done: s => s.sim.evidence.filter((e: string) => ATTACKER_EVENT_IDS.includes(e)).length >= 3, hints: ['Filter CloudTrail events by the stolen key or the outside IP address.', 'Go to CloudTrail → Event history\nFilter by the stolen access key\nAdd three of its events to the evidence locker'] },
  { id: 'L2.contain', level: 2, title: 'Contain the unauthorized access path without breaking the storefront', points: 25, category: 'containment', done: s => s.level >= 2 && contained(s), hints: ['Stop the intruder, not the store. The app has its own, separate key.', 'Go to IAM → Users → svc-storefront-app → Security credentials\nDeactivate only the stolen key\nCheck the user list for users you don\'t recognise'] },
  find('V6', 2, ['Where does the order processor keep its payment key? Could the intruder read it?', 'Go to Lambda → nc-order-processor → Configuration\nClick "Report finding"']),
  fix('V6', 2, 25, ['Move the payment key into Secrets Manager, and make the leaked value stop working.', 'Secrets Manager: create a secret with the current payment key\nLambda: add PAYMENT_SECRET_ARN (the secret\'s ARN) and delete PAYMENT_GATEWAY_KEY\nRotate the secret\nRun the function test event\nTest the old credential in Secrets Manager → should be rejected']),
  fix('V1', 2, 25, ['Give the app only what it really uses. The policy\'s Access Advisor tab shows that.', 'Edit NovaCartAppPolicy and remove everything except:\ns3:GetObject + s3:PutObject on arn:aws:s3:::novacart-product-assets/*\ns3:ListBucket on arn:aws:s3:::novacart-product-assets\nPolicy simulator (svc-storefront-app): test one allowed and one denied action']),
  { id: 'L2.verify', level: 2, title: 'Verify that requests signed with the compromised key are rejected', points: 10, category: 'verification', done: s => contained(s) && !!s.sim.checks['L2.replay'], hints: ['Prove the stolen key no longer works.', 'Go to S3 → any bucket → Permissions → access test\nChoose svc-storefront-app and the stolen key\nExpected result: InvalidAccessKeyId'] },

  ...(['V4', 'V5', 'V7', 'V8', 'V9', 'V10'] as const).flatMap(v => {
    const h: Record<string, string[][]> = {
      V4: [['The intruder switched off the audit log. Is it back on? Does it cover every region and every action?', 'Go to CloudTrail → Trails → novacart-mgmt-trail → Configuration\nClick "Report finding"'], ['Three settings matter: logging on, all regions, all management events.', 'Start logging\nEnable multi-region\nSet management events to All\nRun the audit coverage test and find its event in Event history']],
      V5: [['Incident Center\'s data-handling policy says how confidential files must be encrypted.', 'Go to S3 → novacart-internal-docs → Properties\nClick "Report finding"'], ['Default encryption only covers new files. Old files must be re-encrypted too.', 'Set default encryption to SSE-KMS with alias/novacart-data\nClick "Re-encrypt existing objects"\nAccess test: PUT as nc-app-server-role → should be allowed']],
      V7: [['Compare what the order processor actually does (its logs) with what its role allows.', 'Go to IAM → Policies → nc-order-processor-policy → Permissions\nClick "Report finding"'], ['The function needs only three things: write logs, save exports to S3, read its one secret.', 'Allow logs:CreateLogStream + logs:PutLogEvents on its log group\nAllow s3:PutObject on novacart-order-exports/exports/*\nAllow secretsmanager:GetSecretValue on its secret ARN only\nRun the function test event\nPolicy simulator: test a denied action for the role']],
      V8: [['If an attacker tried something, would any alarm tell the security team?', 'Go to CloudWatch → Alarms\nClick "Report finding"'], ['Add an alarm for unauthorized API calls that notifies the security team. (CloudTrail must be logging.)', 'Create an alarm on UnauthorizedAPICalls\nSet the threshold between 1 and 10\nNotify nc-security-alerts\nSend test events above the threshold']],
      V9: [['Who is allowed to use the key that protects confidential files?', 'Go to KMS → alias/novacart-data → Key policy\nClick "Report finding"'], ['Split key admins from key users, and remove "*" (everyone). A root-account statement also lets IAM users in — check it.', 'Let nc-app-server-role use kms:Decrypt + kms:GenerateDataKey\nLet nc-kms-admin-role do admin actions, including kms:PutKeyPolicy\nRemove the "*" principal\nCrypto test as an unrelated principal → denied; as nc-app-server-role → allowed']],
      V10: [['An admin-level user switched off the audit log. What could block that, whatever their IAM permissions?', 'Go to Governance → Policies\nClick "Report finding"'], ['Read each policy first: one protects the audit log, the others would break production.', 'Attach DenyAuditLogTampering to the Production OU (or the novacart-training account)\nSimulate cloudtrail:StopLogging for dev-rahul → denied\nSimulate one normal action → allowed']],
    };
    return [find(v, 3, h[v][0]), fix(v, 3, 20, h[v][1])];
  }),
  { id: 'L3.regression', level: 3, title: 'Run the regression suite with every finding verified and every service healthy', points: 20, category: 'verification', done: s => !!s.sim.regression?.passed && FINDINGS.every(f => s.sim.findings[f.id]?.verified) && health(s).every(p => p.ok), hints: ['The regression suite (Incident Center) re-checks the app and every finding at once.', 'Run the regression suite in Incident Center\nFix anything marked failing and re-verify it\nRun the suite again'] },

  { id: 'L4.logs', level: 4, title: 'Examine the CI build log and the app server authentication log', points: 10, category: 'investigation', sticky: true, done: s => !!s.sim.inspected['cloudwatch/log/ci/novacart-storefront-build/build-482#events'] && !!s.sim.inspected['cloudwatch/log//var/log/auth/nc-app-server/sshd#events'], hints: ['How was the key stolen? CloudWatch logs hold clues for two possible answers.', 'Go to CloudWatch → Log groups\nOpen ci/novacart-storefront-build → build-482\nOpen /var/log/auth/nc-app-server → sshd'] },
  { id: 'L4.triage', level: 4, title: 'Triage the three open alerts', points: 15, category: 'investigation', done: s => ALERTS.every(a => s.sim.triage[a.id]), hints: ['Judge each alert by the evidence, not its title. Was anything actually compromised?', 'Failed logins with no success → blocked attempt\nYour own changes → expected activity\nKey exposed in a public build log → confirmed incident'] },
  { id: 'L4.report', level: 4, title: 'Submit the incident report and hardening plan', points: 40, category: 'reporting', sticky: true, done: s => !!s.sim.report, hints: ['Root cause = how the key was stolen, not what it was used for.', 'Order the timeline by the log timestamps\nList only resources with evidence of unauthorized access\nRoot cause: how the credential was obtained'] },
];
export const OBJECTIVE = Object.fromEntries(OBJECTIVES.map(o => [o.id, o]));

export const ALERTS = [
  { id: 'AL-1', title: 'SSH authentication failures on nc-app-server', source: 'CloudWatch Logs — /var/log/auth/nc-app-server', detail: '1,912 failed SSH logins in 14 days from multiple external addresses.', truth: 'blocked-attempt' },
  { id: 'AL-2', title: 'IAM policy and key changes by ThreatReady-SecurityAnalyst', source: 'CloudTrail', detail: 'Policy versions created and an access key deactivated during the last few hours.', truth: 'expected-activity' },
  { id: 'AL-3', title: 'AWS access key pattern found in public CI build log', source: 'Secret scanner — novacart/storefront build #482', detail: 'AKIASYNTHNOVAOLD0002 printed on 2026-09-28; .env.legacy committed to a public repository.', truth: 'confirmed-incident' },
];
export const TRIAGE_OPTIONS = ['confirmed-incident', 'blocked-attempt', 'expected-activity'];

export const REPORT_FORM = {
  rootCause: [
    { id: 'ssh', label: 'SSH brute force against nc-app-server succeeded' },
    { id: 'ci-leak', label: 'Long-lived access key exposed through a public repository / CI build log' },
    { id: 'public-bucket', label: 'Credentials were stored in the public S3 bucket' },
    { id: 'insider', label: 'Deliberate misuse by an internal developer' },
    { id: 'lambda-env', label: 'Key read from the Lambda environment variables' }],
  timeline: [
    { id: 't-recon', label: 'Intruder enumerates buckets, users and policies' },
    { id: 't-exfil', label: 'Confidential documents downloaded from novacart-internal-docs' },
    { id: 't-leak', label: 'Access key appears in public CI build log' },
    { id: 't-stop', label: 'CloudTrail logging stopped' },
    { id: 't-first', label: 'First API call from 198.51.100.77 (GetCallerIdentity)' }],
  affected: [
    { id: 'svc', label: 'IAM user svc-storefront-app' }, { id: 'docs', label: 'S3 bucket novacart-internal-docs' }, { id: 'trail', label: 'CloudTrail trail novacart-mgmt-trail' },
    { id: 'assets', label: 'S3 bucket novacart-product-assets' }, { id: 'alb', label: 'Load balancer nc-storefront-alb' }, { id: 'db', label: 'Secret novacart/prod/db-master' },
    { id: 'fn', label: 'Lambda function nc-order-processor (payment credential)' }, { id: 'backdoor', label: 'IAM user support-temp-01' }],
  residual: [
    { id: 'r-recall', label: 'Downloaded documents cannot be recalled; affected parties may need notification' },
    { id: 'r-gap', label: 'Activity during the logging gap cannot be fully reconstructed' },
    { id: 'r-subnet', label: 'The app server still sits in a public subnet with a public IP' },
    { id: 'r-recover', label: 'Missing CloudTrail events will be backfilled now that logging is on' },
    { id: 'r-assets', label: 'Public catalog images remain a data-exposure risk' }],
  hardening: [
    { id: 'h-roles', label: 'Replace long-lived IAM user keys with roles / short-lived credentials' },
    { id: 'h-scan', label: 'Add secret scanning to repositories and CI, and make build logs private' },
    { id: 'h-mfa', label: 'Require MFA for all console users' },
    { id: 'h-private', label: 'Move the app server to a private subnet behind the ALB' },
    { id: 'h-rotate', label: 'Enforce maximum key age and automatic secret rotation' },
    { id: 'h-notrail', label: 'Reduce CloudTrail to read-only events to cut noise' },
    { id: 'h-openssh', label: 'Keep SSH open to 0.0.0.0/0 for faster incident access' },
    { id: 'h-shareroot', label: 'Share root credentials with the on-call team' }],
};
const TIMELINE_ORDER = ['t-leak', 't-first', 't-recon', 't-stop', 't-exfil'];
const setScore = (chosen: string[], correct: string[], max: number) => {
  const c = new Set(chosen), k = new Set(correct);
  const inter = [...c].filter(x => k.has(x)).length, union = new Set([...c, ...k]).size;
  return union ? Math.round((inter / union) * max * 10) / 10 : max;
};
export function scoreReport(s: any, r: any) {
  const affected = ['svc', 'docs', 'trail', ...(s.sim.attacker.secretStolen ? ['fn'] : []), ...(s.sim.attacker.backdoor ? ['backdoor'] : [])];
  const parts = [
    { id: 'rootCause', label: 'Root cause', max: 10, awarded: r.rootCause === 'ci-leak' ? 10 : 0, evidence: 'Build #482 log shows the key in a public build; the SSH log shows no successful external login.' },
    { id: 'credential', label: 'Compromised credential', max: 5, awarded: r.credential === KEY_OLD ? 5 : 0, evidence: 'All intruder CloudTrail events are signed with the key ending OLD0002 from 198.51.100.77.' },
    { id: 'timeline', label: 'Timeline order', max: 10, awarded: TIMELINE_ORDER.reduce((n, id, i) => n + (r.timeline[i] === id ? 2 : 0), 0), evidence: 'Leak 28 Sep → first call 8 Oct 18:10Z → reconnaissance → StopLogging 20:44Z → downloads from 20:51Z (S3 access log).' },
    { id: 'affected', label: 'Affected resources', max: 5, awarded: setScore(r.affected, affected, 5), evidence: 'Scored against resources with recorded unauthorized access in this session.' },
    { id: 'residual', label: 'Residual risks', max: 5, awarded: setScore(r.residual, ['r-recall', 'r-gap', 'r-subnet'], 5), evidence: 'Unrecorded events are never backfilled; public catalog images are intentionally public.' },
    { id: 'hardening', label: 'Hardening plan', max: 5, awarded: setScore(r.hardening, ['h-roles', 'h-scan', 'h-mfa', 'h-private', 'h-rotate'], 5), evidence: 'Recommendations must reduce the likelihood or impact of this incident recurring.' },
  ];
  return { parts, total: parts.reduce((n, p) => n + p.awarded, 0), max: 40 };
}

export const CHAPTERS = [
  { n: 1, title: 'A routine review', text: 'NovaCart\'s launch is days away. An internal review has flagged the storage and identity configuration, and support is hearing about unusual account activity. You have been assigned ticket INC-2041.', when: (_: any) => true },
  { n: 2, title: 'The trail goes quiet', text: 'The audit history ends abruptly. The final recorded action was performed by the storefront application identity — from an address that is not NovaCart\'s.', when: (s: any) => s.sim.evidence.includes('evt-0017') || s.level >= 2 },
  { n: 3, title: 'Active incident', text: 'A suspicious-activity alert has fired. Someone is using NovaCart credentials right now. The clock is running: work out what that identity can reach.', when: (s: any) => s.level >= 2 },
  { n: 4, title: 'Blast radius', text: 'The compromised identity is far more powerful than the application needs, and confidential data sat in a publicly readable bucket. Together they turn a leaked key into a breach.', when: (s: any) => s.level >= 2 && s.incident.declaredKey === KEY_OLD },
  { n: 5, title: 'Containment', text: 'The intruder\'s access path is closed and the evidence is preserved. Leadership wants to know: is it over, and what else is exposed?', when: (s: any) => s.level >= 2 && contained(s) && s.sim.evidence.length >= 3 },
  { n: 6, title: 'Deeper problems', text: 'With the immediate threat contained, the review widens: secrets, encryption, monitoring and governance all show the marks of an environment built in a hurry.', when: (s: any) => s.level >= 3 },
  { n: 7, title: 'Hardening', text: 'Root causes are fixed and verified, and the storefront is healthy. New alerts are arriving — not all of them mean what they appear to.', when: (s: any) => s.level >= 4 },
  { n: 8, title: 'The report', text: 'Your incident report is filed. The assessment below is based on what you actually did and verified.', when: (s: any) => !!s.sim.report },
];

// Deterministic attacker script, active from the start of Level 2. Offsets are simulated minutes.
export const ATTACKER_STEPS = [
  { id: 'A1', at: 30, action: 's3:GetObject', resource: arn.object(DOCS, 'finance/payroll-2026-09.csv'), event: 'GetObject', source: 's3' },
  { id: 'A2', at: 60, action: 'iam:CreateUser', resource: arn.user('support-temp-01'), event: 'CreateUser', source: 'iam' },
  { id: 'A3', at: 90, action: 'lambda:GetFunctionConfiguration', resource: arn.fn(FN), event: 'GetFunctionConfiguration', source: 'lambda' },
  { id: 'A4', at: 120, action: 'payment:Charge', resource: '-', event: 'FraudulentCharge', source: 'gateway' },
];
