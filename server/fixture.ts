// Initial scenario fixture for TR-CLOUD-001. All identities, keys, logs and secrets are synthetic.
import { ACC, arn } from './policy';

export const KEY_APP = 'AKIASYNTHNOVAAPP0001';
export const KEY_OLD = 'AKIASYNTHNOVAOLD0002';
export const KEY_BACKDOOR = 'AKIASYNTHBKDR000003';
export const ATTACKER_IP = '198.51.100.77';
export const LEAKED_CRED = 'ncpg_SYNTHETIC_live_7f3a91c2d7e4';
export const DATA_KEY = 'a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d';
export const SG_APP = 'sg-0a4f1app7c2d9e113';
export const SG_ALB = 'sg-0b7e2alb5d1c8f224';
export const SG_INT = 'sg-0c9d3int6e2b7a335';
export const I_APP = 'i-0f3a91c2d7e4b6a81';
export const I_BATCH = 'i-0b8d27e6f1a3c5d92';
export const TRAIL = 'novacart-mgmt-trail';
export const FN = 'nc-order-processor';
export const START = '2026-10-12T03:30:00.000Z'; // 09:00 IST

const pol = (name: string, document: any, extra: any = {}) => ({
  name, document, type: 'Customer managed', protected: false,
  versions: [{ id: 'v1', document, createdAt: '2026-06-14T08:12:00.000Z', by: 'dev-rahul', isDefault: true }], ...extra,
});
const V = '2012-10-17';
const ev = (n: number, time: string, name: string, source: string, actor: string, ip: string, resource: string, opt: any = {}) => ({
  id: `evt-${String(n).padStart(4, '0')}`, time, name, source, actor, sourceIp: ip, resource, region: 'ap-south-1',
  outcome: 'Success', readOnly: /^(Get|List|Describe|Lookup)/.test(name), accessKeyId: null, userAgent: 'aws-cli/2.17', ...opt,
});

export function createInitialState(): any {
  const lg = (n: string) => arn.logGroup(n);
  const policies: any = {
    'pol-app': pol('NovaCartAppPolicy', { Version: V, Statement: [{ Sid: 'AppAccess', Effect: 'Allow', Action: '*', Resource: '*' }] }, {
      description: 'Storefront application access', observedUsage: [
        { action: 's3:GetObject', resource: 'arn:aws:s3:::novacart-product-assets/*', calls: 48211 },
        { action: 's3:PutObject', resource: 'arn:aws:s3:::novacart-product-assets/uploads/*', calls: 1903 },
        { action: 's3:ListBucket', resource: 'arn:aws:s3:::novacart-product-assets', calls: 612 }] }),
    'pol-order': pol('nc-order-processor-policy', { Version: V, Statement: [{ Sid: 'Everything', Effect: 'Allow', Action: ['s3:*', 'secretsmanager:*', 'dynamodb:*', 'kms:*', 'logs:*', 'iam:PassRole'], Resource: '*' }] }, {
      description: 'Execution permissions for nc-order-processor', observedUsage: [
        { action: 'logs:CreateLogStream', resource: lg('/aws/lambda/nc-order-processor'), calls: 311 },
        { action: 'logs:PutLogEvents', resource: lg('/aws/lambda/nc-order-processor'), calls: 9120 },
        { action: 's3:PutObject', resource: 'arn:aws:s3:::novacart-order-exports/exports/*', calls: 4410 }] }),
    'pol-appserver': pol('nc-app-server-policy', { Version: V, Statement: [
      { Sid: 'InternalDocs', Effect: 'Allow', Action: ['s3:GetObject', 's3:PutObject'], Resource: 'arn:aws:s3:::novacart-internal-docs/*' },
      { Sid: 'ListDocs', Effect: 'Allow', Action: 's3:ListBucket', Resource: 'arn:aws:s3:::novacart-internal-docs' },
      { Sid: 'DataKey', Effect: 'Allow', Action: ['kms:Decrypt', 'kms:GenerateDataKey'], Resource: arn.key(DATA_KEY) }] }, { description: 'App server instance profile', observedUsage: [] }),
    'pol-admin': pol('AdministratorAccess', { Version: V, Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }, { type: 'AWS managed', protected: true, description: 'Full access', observedUsage: [] }),
    'pol-readonly': pol('ReadOnlyAccess', { Version: V, Statement: [{ Effect: 'Allow', Action: ['*:Get*', '*:List*', '*:Describe*'].map(a => a.replace('*:', 's3:')).concat(['ec2:Describe*', 'iam:Get*', 'iam:List*', 'cloudtrail:Describe*', 'cloudtrail:LookupEvents', 'logs:Get*', 'logs:Describe*']), Resource: '*' }] }, { type: 'AWS managed', protected: true, description: 'Read-only access', observedUsage: [] }),
    'pol-kmsadmin': pol('nc-kms-admin-policy', { Version: V, Statement: [{ Effect: 'Allow', Action: ['kms:Describe*', 'kms:List*', 'kms:Get*', 'kms:PutKeyPolicy', 'kms:EnableKeyRotation', 'kms:TagResource'], Resource: '*' }] }, { description: 'KMS key administration', observedUsage: [] }),
    'pol-analyst': pol('TR-SecurityAnalystPolicy', { Version: V, Statement: [
      { Sid: 'Investigate', Effect: 'Allow', Action: ['iam:Get*', 'iam:List*', 'iam:SimulatePrincipalPolicy', 's3:Get*', 's3:List*', 'ec2:Describe*', 'cloudtrail:Describe*', 'cloudtrail:Get*', 'cloudtrail:LookupEvents', 'cloudwatch:*', 'logs:*', 'lambda:Get*', 'lambda:List*', 'kms:Describe*', 'kms:Get*', 'kms:List*', 'secretsmanager:*', 'sns:Publish'], Resource: '*' },
      { Sid: 'Respond', Effect: 'Allow', Action: ['iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion', 'iam:UpdateAccessKey', 's3:PutBucketPolicy', 's3:DeleteBucketPolicy', 's3:PutBucketPublicAccessBlock', 's3:PutEncryptionConfiguration', 's3:PutObject', 's3:PutObjectAcl', 'ec2:AuthorizeSecurityGroupIngress', 'ec2:RevokeSecurityGroupIngress', 'cloudtrail:StartLogging', 'cloudtrail:UpdateTrail', 'cloudtrail:PutEventSelectors', 'lambda:UpdateFunctionConfiguration', 'lambda:InvokeFunction', 'kms:PutKeyPolicy'], Resource: '*' },
      { Sid: 'NoDestructiveActions', Effect: 'Deny', Action: ['iam:DeleteUser', 'iam:DeleteRole', 'ec2:TerminateInstances', 'ec2:StopInstances', 's3:DeleteBucket', 's3:DeleteObject', 'kms:ScheduleKeyDeletion', 'kms:DisableKey', 'cloudtrail:DeleteTrail', 'cloudtrail:StopLogging', 'lambda:DeleteFunction', 'secretsmanager:DeleteSecret'], Resource: '*' }] }, { protected: true, description: 'Your permissions in this simulation', observedUsage: [] }),
  };
  const user = (name: string, o: any) => ({ name, arn: arn.user(name), createdAt: '2025-03-02T06:00:00.000Z', groups: [], mfa: false, console: false, accessKeys: [], policies: [], tags: {}, ...o });
  const role = (name: string, o: any) => ({ name, arn: arn.role(name), createdAt: '2025-03-02T06:00:00.000Z', policies: [], trusted: 'ec2.amazonaws.com', description: '', ...o });

  const doc = (key: string, size: number, preview: string, acl = 'private') => ({ key, size, acl, encryption: 'None', lastModified: '2026-09-18T10:22:00.000Z', preview });
  const cloudtrailEvents = [
    ev(1, '2026-09-20T07:41:10.000Z', 'ConsoleLogin', 'signin', 'dev-rahul', '203.0.113.24', '-', { readOnly: false, userAgent: 'Mozilla/5.0' }),
    ev(2, '2026-09-20T07:48:32.000Z', 'PutBucketPolicy', 's3', 'dev-rahul', '203.0.113.24', 'novacart-internal-docs', { userAgent: 'console.amazonaws.com' }),
    ev(3, '2026-09-25T11:05:19.000Z', 'UpdateFunctionConfiguration', 'lambda', 'dev-rahul', '203.0.113.24', FN, { userAgent: 'console.amazonaws.com' }),
    ev(4, '2026-10-01T15:30:02.000Z', 'AuthorizeSecurityGroupIngress', 'ec2', 'dev-rahul', '203.0.113.24', SG_APP, { userAgent: 'console.amazonaws.com' }),
    ev(5, '2026-10-03T04:12:44.000Z', 'DescribeInstances', 'ec2', 'ops-priya', '203.0.113.31', '-'),
    ev(6, '2026-10-05T09:02:11.000Z', 'ConsoleLogin', 'signin', 'ops-priya', '203.0.113.31', '-', { readOnly: false, userAgent: 'Mozilla/5.0' }),
    ev(7, '2026-10-06T05:55:40.000Z', 'ListBuckets', 's3', 'svc-storefront-app', '10.0.1.25', '-', { accessKeyId: KEY_APP, userAgent: 'aws-sdk-nodejs/3.6' }),
    ev(8, '2026-10-07T12:20:08.000Z', 'GetBucketLocation', 's3', 'svc-storefront-app', '10.0.1.25', 'novacart-product-assets', { accessKeyId: KEY_APP, userAgent: 'aws-sdk-nodejs/3.6' }),
    ev(9, '2026-10-08T10:14:51.000Z', 'DescribeAlarms', 'cloudwatch', 'ops-priya', '203.0.113.31', '-'),
    ev(10, '2026-10-08T18:10:03.000Z', 'GetCallerIdentity', 'sts', 'svc-storefront-app', ATTACKER_IP, '-', { accessKeyId: KEY_OLD, userAgent: 'python-requests/2.31' }),
    ev(11, '2026-10-08T18:12:27.000Z', 'ListBuckets', 's3', 'svc-storefront-app', ATTACKER_IP, '-', { accessKeyId: KEY_OLD, userAgent: 'python-requests/2.31' }),
    ev(12, '2026-10-08T18:15:09.000Z', 'ListUsers', 'iam', 'svc-storefront-app', ATTACKER_IP, '-', { accessKeyId: KEY_OLD, userAgent: 'python-requests/2.31' }),
    ev(13, '2026-10-08T18:17:45.000Z', 'ListAttachedUserPolicies', 'iam', 'svc-storefront-app', ATTACKER_IP, 'svc-storefront-app', { accessKeyId: KEY_OLD, userAgent: 'python-requests/2.31' }),
    ev(14, '2026-10-08T18:21:30.000Z', 'GetBucketPolicy', 's3', 'svc-storefront-app', ATTACKER_IP, 'novacart-internal-docs', { accessKeyId: KEY_OLD, userAgent: 'python-requests/2.31' }),
    ev(15, '2026-10-08T19:02:18.000Z', 'ListBuckets', 's3', 'svc-storefront-app', '10.0.1.25', '-', { accessKeyId: KEY_APP, userAgent: 'aws-sdk-nodejs/3.6' }),
    ev(16, '2026-10-08T20:40:12.000Z', 'DescribeTrails', 'cloudtrail', 'svc-storefront-app', ATTACKER_IP, '-', { accessKeyId: KEY_OLD, userAgent: 'python-requests/2.31' }),
    ev(17, '2026-10-08T20:44:06.000Z', 'StopLogging', 'cloudtrail', 'svc-storefront-app', ATTACKER_IP, TRAIL, { accessKeyId: KEY_OLD, userAgent: 'python-requests/2.31' }),
  ];

  return {
    rev: 0,
    clock: { minutes: 0, start: START },
    level: 1, chapter: 1,
    incident: { id: 'INC-2041', status: 'Open', severity: 'Medium', acknowledged: false, declaredKey: null, containment: 'Not contained' },
    iam: {
      users: {
        'svc-storefront-app': user('svc-storefront-app', { policies: ['pol-app'], tags: { purpose: 'storefront-api' }, accessKeys: [
          { id: KEY_APP, status: 'Active', createdAt: '2026-05-11T06:20:00.000Z', lastUsed: '2026-10-12T03:21:00.000Z', lastUsedIp: '10.0.1.25', lastUsedService: 's3' },
          { id: KEY_OLD, status: 'Active', createdAt: '2025-08-30T09:45:00.000Z', lastUsed: '2026-10-11T22:58:00.000Z', lastUsedIp: ATTACKER_IP, lastUsedService: 's3' }] }),
        'dev-rahul': user('dev-rahul', { policies: ['pol-admin'], console: true, groups: ['developers'], accessKeys: [] }),
        'ops-priya': user('ops-priya', { policies: ['pol-readonly'], console: true, mfa: true, groups: ['operations'] }),
      },
      roles: {
        'nc-app-server-role': role('nc-app-server-role', { policies: ['pol-appserver'], description: 'Instance profile for nc-app-server' }),
        'nc-order-processor-role': role('nc-order-processor-role', { policies: ['pol-order'], trusted: 'lambda.amazonaws.com', description: 'Execution role for nc-order-processor' }),
        'nc-kms-admin-role': role('nc-kms-admin-role', { policies: ['pol-kmsadmin'], trusted: arn.root, description: 'Key administrators' }),
        'ThreatReady-SecurityAnalyst': role('ThreatReady-SecurityAnalyst', { policies: ['pol-analyst'], trusted: 'threatready.simulation', description: 'The role you are operating as' }),
      },
      policies,
    },
    s3: { buckets: {
      'novacart-internal-docs': {
        name: 'novacart-internal-docs', createdAt: '2025-04-10T08:00:00.000Z', tags: { classification: 'confidential', owner: 'finance' }, versioning: false,
        blockPublicAccess: { blockPublicAcls: false, ignorePublicAcls: false, blockPublicPolicy: false, restrictPublicBuckets: false },
        policy: { Version: V, Statement: [{ Sid: 'VendorShareTemp', Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::novacart-internal-docs/*' }] },
        encryption: { mode: 'None', keyId: null },
        objects: [
          doc('finance/payroll-2026-09.csv', 48211, 'emp_id,name,ctc_inr\nNC-0001,SYNTHETIC PERSON A,1800000\nNC-0002,SYNTHETIC PERSON B,2400000\n… (synthetic training data)'),
          doc('finance/vendor-contracts-q3.pdf', 912044, '[SYNTHETIC] Vendor master agreement — logistics partner — confidential'),
          doc('hr/offer-letters/offer-NC-0113.pdf', 120331, '[SYNTHETIC] Offer letter — candidate name redacted', 'public-read'),
          doc('customers/export-2026-10-01.csv', 2204113, 'customer_id,email,phone\nC-10001,user1@example.invalid,+91-00000-00001\n… (synthetic training data)'),
          doc('invoices/INV-2026-10-0001.json', 2210, '{"invoice":"INV-2026-10-0001","amount_inr":4999,"synthetic":true}'),
        ],
      },
      'novacart-product-assets': {
        name: 'novacart-product-assets', createdAt: '2025-03-12T08:00:00.000Z', tags: { classification: 'public', owner: 'storefront' }, versioning: true,
        blockPublicAccess: { blockPublicAcls: true, ignorePublicAcls: true, blockPublicPolicy: false, restrictPublicBuckets: false },
        policy: { Version: V, Statement: [{ Sid: 'PublicCatalogImages', Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::novacart-product-assets/public/*' }] },
        encryption: { mode: 'SSE-S3', keyId: null },
        objects: [
          { key: 'public/logo.png', size: 18230, acl: 'private', encryption: 'SSE-S3', lastModified: '2026-08-01T10:00:00.000Z', preview: '[image] NovaCart logo' },
          { key: 'public/catalog/sku-1001.jpg', size: 204811, acl: 'private', encryption: 'SSE-S3', lastModified: '2026-09-30T10:00:00.000Z', preview: '[image] product photo' },
          { key: 'uploads/pending/sku-1188.jpg', size: 190022, acl: 'private', encryption: 'SSE-S3', lastModified: '2026-10-11T10:00:00.000Z', preview: '[image] pending review' },
        ],
      },
      'novacart-order-exports': {
        name: 'novacart-order-exports', createdAt: '2025-06-01T08:00:00.000Z', tags: { classification: 'internal', owner: 'orders' }, versioning: false,
        blockPublicAccess: { blockPublicAcls: true, ignorePublicAcls: true, blockPublicPolicy: true, restrictPublicBuckets: true },
        policy: null, encryption: { mode: 'SSE-S3', keyId: null },
        objects: [{ key: 'exports/orders-2026-10-11.json', size: 88120, acl: 'private', encryption: 'SSE-S3', lastModified: '2026-10-11T18:30:00.000Z', preview: '{"orders":412,"synthetic":true}' }],
      },
    } },
    ec2: {
      instances: {
        [I_APP]: { id: I_APP, name: 'nc-app-server', type: 't3.large', state: 'running', subnet: 'subnet-0pub1a', privateIp: '10.0.1.25', publicIp: '198.51.100.20', securityGroups: [SG_APP], role: 'nc-app-server-role', tags: { env: 'production', app: 'storefront-api' }, launched: '2026-07-02T05:00:00.000Z' },
        [I_BATCH]: { id: I_BATCH, name: 'nc-batch-worker', type: 't3.medium', state: 'running', subnet: 'subnet-0prv1a', privateIp: '10.0.11.40', publicIp: null, securityGroups: [SG_INT], role: null, tags: { env: 'production', app: 'batch' }, launched: '2026-07-02T05:00:00.000Z' },
      },
      loadBalancers: { 'nc-storefront-alb': { name: 'nc-storefront-alb', scheme: 'internet-facing', dns: 'nc-storefront-alb.sim.threatready.invalid', securityGroups: [SG_ALB], targets: [I_APP], targetPort: 8080, privateIp: '10.0.1.10' } },
      securityGroups: {
        [SG_ALB]: { id: SG_ALB, name: 'nc-alb-sg', description: 'Public load balancer', inbound: [
          { id: 'sgr-alb1', protocol: 'tcp', port: 443, source: '0.0.0.0/0', description: 'HTTPS from customers' },
          { id: 'sgr-alb2', protocol: 'tcp', port: 80, source: '0.0.0.0/0', description: 'HTTP redirect to HTTPS' }], outbound: [{ id: 'sgr-albo', protocol: 'all', port: 0, source: '0.0.0.0/0', description: 'All traffic' }] },
        [SG_APP]: { id: SG_APP, name: 'nc-app-server-sg', description: 'Storefront API servers', inbound: [
          { id: 'sgr-app1', protocol: 'tcp', port: 8080, source: SG_ALB, description: 'App traffic from ALB' },
          { id: 'sgr-app2', protocol: 'tcp', port: 22, source: '0.0.0.0/0', description: 'temp ssh - rahul' },
          { id: 'sgr-app3', protocol: 'tcp', port: 8080, source: '0.0.0.0/0', description: 'debug direct access' },
          { id: 'sgr-app4', protocol: 'tcp', port: 9229, source: '0.0.0.0/0', description: 'node inspector' }], outbound: [{ id: 'sgr-appo', protocol: 'all', port: 0, source: '0.0.0.0/0', description: 'All traffic' }] },
        [SG_INT]: { id: SG_INT, name: 'nc-internal-sg', description: 'Private workloads', inbound: [
          { id: 'sgr-int1', protocol: 'tcp', port: 5432, source: SG_APP, description: 'Postgres from app tier' }], outbound: [{ id: 'sgr-into', protocol: 'all', port: 0, source: '0.0.0.0/0', description: 'All traffic' }] },
      },
    },
    vpc: {
      id: 'vpc-0nc1a2b3c', cidr: '10.0.0.0/16', name: 'novacart-prod-vpc', igw: 'igw-0nc77aa',
      subnets: [
        { id: 'subnet-0pub1a', name: 'public-1a', cidr: '10.0.1.0/24', az: 'ap-south-1a', public: true, routeTable: 'rtb-0public' },
        { id: 'subnet-0prv1a', name: 'private-1a', cidr: '10.0.11.0/24', az: 'ap-south-1a', public: false, routeTable: 'rtb-0private' }],
      routeTables: [
        { id: 'rtb-0public', name: 'public-rt', routes: [{ destination: '10.0.0.0/16', target: 'local' }, { destination: '0.0.0.0/0', target: 'igw-0nc77aa' }] },
        { id: 'rtb-0private', name: 'private-rt', routes: [{ destination: '10.0.0.0/16', target: 'local' }, { destination: '0.0.0.0/0', target: 'nat-0nc55bb' }] }],
    },
    cloudtrail: {
      trails: { [TRAIL]: { name: TRAIL, homeRegion: 'ap-south-1', logging: false, multiRegion: false, managementEvents: 'ReadOnly', logFileValidation: false, bucket: 'novacart-audit-logs', stoppedAt: '2026-10-08T20:44:06.000Z', stoppedBy: 'svc-storefront-app' } },
      events: cloudtrailEvents, seq: cloudtrailEvents.length,
    },
    cloudwatch: {
      topics: ['nc-security-alerts', 'nc-ops-pager'],
      metricDefs: [
        { name: 'UnauthorizedAPICalls', namespace: 'NovaCart/Security', source: 'cloudtrail', description: 'AccessDenied / UnauthorizedOperation errors in CloudTrail' },
        { name: 'ConsoleSignInFailures', namespace: 'NovaCart/Security', source: 'cloudtrail', description: 'Failed console sign-in attempts' },
        { name: 'RootAccountUsage', namespace: 'NovaCart/Security', source: 'cloudtrail', description: 'API activity by the root user' },
        { name: 'CPUUtilization', namespace: 'AWS/EC2', source: 'agent', description: 'nc-app-server CPU %' },
        { name: 'ALB5xxCount', namespace: 'AWS/ApplicationELB', source: 'agent', description: 'Storefront 5xx responses' }],
      metrics: { UnauthorizedAPICalls: [], ConsoleSignInFailures: [], RootAccountUsage: [], CPUUtilization: [{ t: 0, v: 41 }], ALB5xxCount: [{ t: 0, v: 0 }] },
      alarms: { 'nc-app-cpu-high': { name: 'nc-app-cpu-high', metric: 'CPUUtilization', comparison: '>=', threshold: 85, period: 300, topic: 'nc-ops-pager', state: 'OK', createdBy: 'ops-priya', history: [] } },
      notifications: [],
      logGroups: {
        '/aws/lambda/nc-order-processor': { streams: { '2026/10/11/[$LATEST]a41f': [
          '2026-10-11T18:30:01Z START RequestId: 5c1e-synthetic', '2026-10-11T18:30:01Z INFO loading payment credential from process.env.PAYMENT_GATEWAY_KEY',
          '2026-10-11T18:30:02Z INFO gateway auth ok', '2026-10-11T18:30:03Z INFO s3:PutObject novacart-order-exports/exports/orders-2026-10-11.json', '2026-10-11T18:30:03Z END RequestId: 5c1e-synthetic'] } },
        's3-access/novacart-internal-docs': { streams: { '2026-10-09': [
          '2026-10-08T20:51:14Z 198.51.100.77 svc-storefront-app/AKIA…OLD0002 REST.GET.OBJECT customers/export-2026-10-01.csv 200',
          '2026-10-08T20:52:40Z 198.51.100.77 svc-storefront-app/AKIA…OLD0002 REST.GET.OBJECT finance/vendor-contracts-q3.pdf 200',
          '2026-10-09T03:11:02Z 192.0.2.146 - REST.GET.OBJECT hr/offer-letters/offer-NC-0113.pdf 200 (anonymous)',
          '2026-10-09T06:40:55Z 10.0.1.25 nc-app-server-role REST.PUT.OBJECT invoices/INV-2026-10-0001.json 200'] } },
        'ci/novacart-storefront-build': { streams: {
          'build-481': ['2026-09-27T09:10:00Z npm ci', '2026-09-27T09:12:31Z npm test — 212 passed', '2026-09-27T09:13:02Z deploy ok'],
          'build-482': ['2026-09-28T13:02:00Z + set -x', '2026-09-28T13:02:01Z + export AWS_ACCESS_KEY_ID=AKIASYNTHNOVAOLD0002', '2026-09-28T13:02:01Z + export AWS_SECRET_ACCESS_KEY=**** (masked by CI, visible in .env.legacy committed to public repo novacart/storefront@4be1f0a)', '2026-09-28T13:02:05Z WARN legacy deploy script: using static credentials', '2026-09-28T13:03:44Z deploy ok', '2026-09-28T13:03:45Z NOTE build logs for public repositories are world-readable'] } },
        '/var/log/auth/nc-app-server': { streams: { 'sshd': [
          '2026-10-02T01:14:07Z sshd[2211]: Failed password for invalid user admin from 192.0.2.201 port 51122',
          '2026-10-04T03:40:19Z sshd[2890]: Failed password for root from 192.0.2.201 port 40118',
          '2026-10-07T22:05:51Z sshd[3312]: Failed publickey for ec2-user from 192.0.2.9 port 60233',
          '2026-10-10T02:17:33Z sshd[4120]: Failed password for invalid user deploy from 192.0.2.201 port 43310',
          '2026-10-11T04:02:10Z sshd[4388]: Accepted publickey for ec2-user from 203.0.113.24 port 50110 (dev-rahul, office VPN)',
          'SUMMARY last 14d: 1,912 failed attempts, 3 accepted — all accepted logins from 203.0.113.0/24 (office VPN)'] } },
        'payment-gateway/auth': { streams: { 'gateway': ['2026-10-11T18:30:02Z auth ok client=nc-order-processor ip=10.0.11.7'] } },
      },
    },
    lambda: { functions: { [FN]: { name: FN, runtime: 'nodejs20.x', handler: 'index.handler', memory: 256, timeout: 30, role: 'nc-order-processor-role', description: 'Charges orders via the payment gateway and exports order batches',
      env: { NODE_ENV: 'production', EXPORT_BUCKET: 'novacart-order-exports', PAYMENT_GATEWAY_URL: 'https://gateway.sim.threatready.invalid', PAYMENT_GATEWAY_KEY: LEAKED_CRED },
      lastModified: '2026-09-25T11:05:19.000Z', lastInvocation: null } } },
    kms: { keys: { [DATA_KEY]: { id: DATA_KEY, alias: 'alias/novacart-data', description: 'Customer managed key for sensitive NovaCart data', state: 'Enabled', rotation: false, createdAt: '2025-04-10T08:00:00.000Z',
      policy: { Version: V, Statement: [{ Sid: 'AllowEveryoneTemp', Effect: 'Allow', Principal: { AWS: '*' }, Action: 'kms:*', Resource: '*' }] }, policyHistory: [] } } },
    secrets: { secrets: { 'novacart/prod/db-master': { name: 'novacart/prod/db-master', description: 'Primary database credentials', createdAt: '2025-05-01T08:00:00.000Z', createdBy: 'ops-priya', rotationCount: 2,
      versions: [{ id: 'ver-0003', value: 'pg_SYNTHETIC_db_master_c0ffee', stage: 'AWSCURRENT', createdAt: '2026-08-01T00:00:00.000Z' }], accessLog: [] } }, seq: 3 },
    org: {
      rootId: 'r-nc01', managementAccount: '111122223333',
      ous: { 'ou-nc01-prod': { id: 'ou-nc01-prod', name: 'Production', parent: 'r-nc01' }, 'ou-nc01-sbx': { id: 'ou-nc01-sbx', name: 'Sandbox', parent: 'r-nc01' } },
      accounts: {
        '111122223333': { id: '111122223333', name: 'novacart-management', parent: 'r-nc01' },
        [ACC]: { id: ACC, name: 'novacart-training', parent: 'ou-nc01-prod' },
        '210987654321': { id: '210987654321', name: 'novacart-sandbox', parent: 'ou-nc01-sbx' } },
      scps: {
        'p-fullaccess': { id: 'p-fullaccess', name: 'FullAWSAccess', awsManaged: true, description: 'Allows all actions (default)', attachedTo: ['r-nc01'], document: { Version: V, Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] } },
        'p-audit': { id: 'p-audit', name: 'DenyAuditLogTampering', description: 'Prevents stopping or deleting CloudTrail trails', attachedTo: [], document: { Version: V, Statement: [{ Sid: 'ProtectTrails', Effect: 'Deny', Action: ['cloudtrail:StopLogging', 'cloudtrail:DeleteTrail'], Resource: '*' }] } },
        'p-leave': { id: 'p-leave', name: 'DenyLeaveOrganization', description: 'Prevents member accounts from leaving the organization', attachedTo: ['r-nc01'], document: { Version: V, Statement: [{ Effect: 'Deny', Action: 'organizations:LeaveOrganization', Resource: '*' }] } },
        'p-s3quarantine': { id: 'p-s3quarantine', name: 'QuarantineDenyAllS3', description: 'Emergency quarantine: denies every S3 action', attachedTo: [], document: { Version: V, Statement: [{ Effect: 'Deny', Action: 's3:*', Resource: '*' }] } },
        'p-iamfreeze': { id: 'p-iamfreeze', name: 'FreezeIAMChanges', description: 'Denies all IAM write operations', attachedTo: [], document: { Version: V, Statement: [{ Effect: 'Deny', Action: ['iam:Create*', 'iam:Delete*', 'iam:Put*', 'iam:Attach*', 'iam:Detach*', 'iam:Update*', 'iam:Set*'], Resource: '*' }] } },
      },
    },
    gateway: { current: LEAKED_CRED, history: [LEAKED_CRED] }, // hidden from clients
    sim: {
      inspected: {}, checks: {}, findings: {}, objectives: {}, hints: {}, evidence: [], tests: [],
      failedActions: 0, wrongReports: 0, outages: [], health: {}, alerts: [], timeline: [], triage: {}, report: null, regression: null,
      attacker: { t0: null, done: {}, successes: 0, backdoor: false, secretStolen: false, exfil: 2 },
      levelStartedAt: { 1: 0 }, completedAt: null,
    },
    labEvents: [], eventSeq: 0,
  };
}
