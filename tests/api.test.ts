import { describe, it, expect, beforeEach } from 'vitest';
import request from 'supertest';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';
import { createApp } from '../server/app';
import { Store } from '../server/store';
import { fx, DOCS } from './helpers';

let app: any, tokA: string, tokB: string, sid: string, n = 0;
const rid = () => `req-${Date.now()}-${n++}`;
const auth = (t: string) => ({ Authorization: `Bearer ${t}` });
const act = (t: string, s: string, type: string, params: any = {}, requestId = rid()) => request(app).post(`/api/sessions/${s}/actions`).set(auth(t)).send({ type, params, requestId });
const BPA = { bucket: DOCS, config: { blockPublicAcls: true, ignorePublicAcls: true, blockPublicPolicy: true, restrictPublicBuckets: true } };

beforeEach(async () => {
  app = createApp(new Store(null));
  tokA = (await request(app).post('/api/auth/login').send({ name: 'Asha' })).body.token;
  tokB = (await request(app).post('/api/auth/login').send({ name: 'Bharat' })).body.token;
  sid = (await request(app).post('/api/labs/TR-CLOUD-001/sessions').set(auth(tokA))).body.session.id;
});

describe('API security', () => {
  it('requires authentication', async () => { expect((await request(app).get(`/api/sessions/${sid}`)).status).toBe(401); expect((await request(app).get(`/api/sessions/${sid}`).set({ Authorization: 'Bearer nope' })).status).toBe(401); });
  it("a learner cannot read or modify another learner's session", async () => {
    expect((await request(app).get(`/api/sessions/${sid}`).set(auth(tokB))).status).toBe(404);
    expect((await act(tokB, sid, 's3.putPublicAccessBlock', BPA)).status).toBe(404);
    expect((await request(app).get(`/api/sessions/${sid}/report`).set(auth(tokB))).status).toBe(404);
    expect((await request(app).post(`/api/sessions/${sid}/reset`).set(auth(tokB)).send({ confirm: 'RESET' })).status).toBe(404);
    const own = await request(app).get(`/api/sessions/${sid}`).set(auth(tokA)); expect(own.body.cloud.s3.buckets[DOCS].blockPublicAccess.restrictPublicBuckets).toBe(false);
  });
  it('forged objective completions and state writes are rejected', async () => {
    for (const type of ['objective.complete', 'finding.verify', 'state.set', 'level.set']) { const r = await act(tokA, sid, type, { id: 'V2.fix', findingId: 'V2', level: 4 }); expect(r.body.ok).toBe(false); expect(r.body.code).toBe('UnknownAction'); }
    const r = await request(app).post(`/api/sessions/${sid}/actions`).set(auth(tokA)).send({ type: 'finding.report', params: { findingId: 'V2', resource: `s3/bucket/${DOCS}`, verified: true, discovered: true }, requestId: rid(), state: { level: 4 }, status: { complete: true } });
    expect(r.body.code).toBe('EvidenceRequired'); expect(r.body.status.level).toBe(1); expect(r.body.status.objectives.filter((o: any) => o.done)).toHaveLength(0);
  });
  it('repeated requests are idempotent and do not corrupt state', async () => {
    const id = rid(); const a = await act(tokA, sid, 'ec2.addIngressRule', { groupId: fx.SG_INT, port: 6379, source: '10.0.0.0/16' }, id); const b = await act(tokA, sid, 'ec2.addIngressRule', { groupId: fx.SG_INT, port: 6379, source: '10.0.0.0/16' }, id);
    expect(a.body.ok).toBe(true); expect(b.body.replayed).toBe(true); expect(b.body.cloud.ec2.securityGroups[fx.SG_INT].inbound).toHaveLength(2); expect(b.body.cloud.rev).toBe(a.body.cloud.rev);
    const c = await act(tokA, sid, 'ec2.addIngressRule', { groupId: fx.SG_INT, port: 6379, source: '10.0.0.0/16' }); expect(c.body.code).toBe('InvalidPermission.Duplicate');
    expect((await request(app).get(`/api/sessions/${sid}/activity`).set(auth(tokA))).body.total).toBe(2);
  });
  it('API responses never contain hidden solutions or secret values', async () => {
    await act(tokA, sid, 'secrets.create', { name: 'a/b', value: 'topsecret-value-123' });
    const bodies = [await request(app).get(`/api/sessions/${sid}`).set(auth(tokA)), await request(app).get('/api/labs/TR-CLOUD-001').set(auth(tokA)), await request(app).get(`/api/sessions/${sid}/activity`).set(auth(tokA)), await request(app).get(`/api/sessions/${sid}/report`).set(auth(tokA))].map(r => JSON.stringify(r.body)).join('');
    for (const leak of ['topsecret-value-123', '"truth"', '"current":"ncpg', 'stolenValue', 'pg_SYNTHETIC_db_master', 'Block Public Access settings neutralise']) expect(bodies).not.toContain(leak);
    expect((await act(tokA, sid, 'secrets.getValue', { name: 'a/b' })).body.result.value).toBe('topsecret-value-123'); // explicit, audited retrieval only
  });
  it('rejects malformed requests', async () => {
    expect((await request(app).post(`/api/sessions/${sid}/actions`).set(auth(tokA)).send({ type: 'inspect' })).status).toBe(400);
    expect((await request(app).post(`/api/sessions/${sid}/actions`).set(auth(tokA)).set('Content-Type', 'application/json').send('{oops')).status).toBe(400);
    expect((await request(app).post('/api/auth/login').send({ name: '<script>' })).status).toBe(400);
  });
});

describe('session lifecycle', () => {
  it('reset restores the original scenario and archives the prior run', async () => {
    await act(tokA, sid, 's3.putPublicAccessBlock', BPA);
    expect((await request(app).post(`/api/sessions/${sid}/reset`).set(auth(tokA)).send({})).status).toBe(400);
    const r = await request(app).post(`/api/sessions/${sid}/reset`).set(auth(tokA)).send({ confirm: 'RESET' });
    expect(r.body.session.run).toBe(2); expect(r.body.cloud.s3.buckets[DOCS].blockPublicAccess.restrictPublicBuckets).toBe(false); expect(r.body.cloud.rev).toBe(0);
    const runs = (await request(app).get('/api/labs/TR-CLOUD-001/runs').set(auth(tokA))).body; expect(runs.map((x: any) => x.status)).toEqual(['archived', 'active']);
    expect((await act(tokA, sid, 'incident.acknowledge')).status).toBe(409); // archived runs are read-only
    expect((await request(app).get(`/api/sessions/${sid}/report`).set(auth(tokA))).status).toBe(200);
  });
  it('progress persists across server restarts', async () => {
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'trlab-')), 'store.json');
    let a = createApp(new Store(file)); const tok = (await request(a).post('/api/auth/login').send({ name: 'Persist' })).body.token;
    const s = (await request(a).post('/api/labs/TR-CLOUD-001/sessions').set(auth(tok))).body.session.id;
    await request(a).post(`/api/sessions/${s}/actions`).set(auth(tok)).send({ type: 'incident.acknowledge', params: {}, requestId: rid() });
    a = createApp(new Store(file));
    const again = await request(a).post('/api/labs/TR-CLOUD-001/sessions').set(auth(tok)); expect(again.body.session.id).toBe(s); expect(again.body.status.incident.acknowledged).toBe(true);
  });
  it('CloudTrail history is paginated and searchable', async () => {
    const p1 = (await request(app).get(`/api/sessions/${sid}/cloudtrail?size=5`).set(auth(tokA))).body; expect(p1.total).toBe(17); expect(p1.rows).toHaveLength(5); expect(p1.rows[0].name).toBe('StopLogging');
    expect((await request(app).get(`/api/sessions/${sid}/cloudtrail?q=198.51.100.77`).set(auth(tokA))).body.total).toBe(7);
  });
});
