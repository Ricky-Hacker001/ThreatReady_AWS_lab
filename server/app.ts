import express from 'express';
import path from 'node:path';
import fs from 'node:fs';
import { Store, Session } from './store';
import { cloudLab001, LabEngine } from './engine';

const ENGINES: Record<string, LabEngine> = { [cloudLab001.labId]: cloudLab001 };

export function createApp(store: Store, staticDir?: string) {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '64kb' }));
  const api = express.Router();

  api.post('/auth/login', (req, res) => {
    const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
    if (!/^[\w .@-]{2,40}$/.test(name)) return res.status(400).json({ error: 'Enter a display name (2–40 letters, numbers, spaces).' });
    res.json(store.login(name));
  });

  api.use((req, res, next) => {
    const m = /^Bearer ([a-f0-9]{48})$/.exec(req.headers.authorization || '');
    const user = m && store.userByToken(m[1]);
    if (!user) return res.status(401).json({ error: 'Authentication required.' });
    (req as any).user = user; next();
  });

  api.get('/labs/:labId', (req, res) => { const e = ENGINES[req.params.labId]; if (!e) return res.status(404).json({ error: 'Lab not found.' }); res.json(e.definition()); });

  const snapshot = (s: Session) => { const e = ENGINES[s.labId]; return { session: { id: s.id, run: s.run, status: s.status, createdAt: s.createdAt }, cloud: e.view(s.state), status: e.status(s.state) }; };

  api.post('/labs/:labId/sessions', (req, res) => {
    const e = ENGINES[req.params.labId]; if (!e) return res.status(404).json({ error: 'Lab not found.' });
    const user = (req as any).user;
    const active = store.sessionsOf(user.id, e.labId).find(s => s.status === 'active') || store.createSession(user.id, e.labId, e.createInitialState());
    res.json(snapshot(active));
  });
  api.get('/labs/:labId/runs', (req, res) => {
    const user = (req as any).user; const e = ENGINES[req.params.labId]; if (!e) return res.status(404).json({ error: 'Lab not found.' });
    res.json(store.sessionsOf(user.id, e.labId).map(s => { const st = e.status(s.state); return { id: s.id, run: s.run, status: s.status, createdAt: s.createdAt, level: st.level, score: st.score.total, max: st.score.max, complete: st.complete }; }));
  });

  // Ownership check for every session route. 404 (not 403) so session IDs are not confirmed to other users.
  api.param('sid', (req, res, next, sid) => {
    const s = store.session(sid);
    if (!s || s.userId !== (req as any).user.id) return res.status(404).json({ error: 'Session not found.' });
    (req as any).session = s; next();
  });
  api.get('/sessions/:sid', (req, res) => res.json(snapshot((req as any).session)));

  api.post('/sessions/:sid/actions', (req, res) => {
    const s: Session = (req as any).session; const e = ENGINES[s.labId];
    const { type, params, requestId } = req.body || {};
    if (typeof type !== 'string' || type.length > 60) return res.status(400).json({ error: 'Invalid action.' });
    if (typeof requestId !== 'string' || !/^[\w-]{8,64}$/.test(requestId)) return res.status(400).json({ error: 'requestId is required.' });
    if (s.status !== 'active') return res.status(409).json({ error: 'This run is archived and read-only.' });
    if (s.requests[requestId]) return res.json({ ...s.requests[requestId], replayed: true, ...snapshot(s) });
    const { state, result } = e.dispatch(s.state, { type, params });
    store.commit(s, state, requestId, result);
    res.json({ ...result, ...snapshot(s) });
  });

  api.get('/sessions/:sid/cloudtrail', (req, res) => {
    const s: Session = (req as any).session; const q = String(req.query.q || '').toLowerCase().slice(0, 80);
    const page = Math.max(1, parseInt(String(req.query.page || '1'), 10) || 1); const size = Math.min(50, Math.max(5, parseInt(String(req.query.size || '15'), 10) || 15));
    let rows = [...s.state.cloudtrail.events].reverse();
    if (q) rows = rows.filter((e: any) => [e.id, e.name, e.actor, e.sourceIp, e.resource, e.accessKeyId, e.source, e.outcome, e.region].some(v => String(v || '').toLowerCase().includes(q)));
    if (req.query.readOnly === 'true' || req.query.readOnly === 'false') rows = rows.filter((e: any) => String(e.readOnly) === req.query.readOnly);
    res.json({ total: rows.length, page, size, rows: rows.slice((page - 1) * size, page * size) });
  });
  api.get('/sessions/:sid/activity', (req, res) => {
    const s: Session = (req as any).session; const page = Math.max(1, parseInt(String(req.query.page || '1'), 10) || 1); const size = 20;
    const rows = [...s.state.labEvents].reverse();
    res.json({ total: rows.length, page, size, rows: rows.slice((page - 1) * size, page * size) });
  });
  api.get('/sessions/:sid/report', (req, res) => { const s: Session = (req as any).session; res.json(ENGINES[s.labId].report(s.state, { learner: (req as any).user.name, run: s.run, sessionId: s.id })); });
  api.post('/sessions/:sid/reset', (req, res) => {
    const s: Session = (req as any).session; const e = ENGINES[s.labId];
    if (req.body?.confirm !== 'RESET') return res.status(400).json({ error: 'Reset must be confirmed.' });
    res.json(snapshot(store.createSession(s.userId, s.labId, e.createInitialState()))); // previous run is archived, not deleted
  });

  app.use('/api', api);
  app.use('/api', (_req, res) => res.status(404).json({ error: 'Not found.' }));
  if (staticDir && fs.existsSync(staticDir)) { app.use(express.static(staticDir)); app.get(/^(?!\/api).*/, (_req, res) => res.sendFile(path.join(staticDir, 'index.html'))); }
  app.use((err: any, _req: any, res: any, _next: any) => { if (err?.type === 'entity.parse.failed' || err?.type === 'entity.too.large') return res.status(400).json({ error: 'Invalid request body.' }); console.error(err); res.status(500).json({ error: 'Internal error.' }); });
  return app;
}
