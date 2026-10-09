// Persistence boundary. The prototype uses an atomic JSON file; swap this class for a PostgreSQL repository in the platform.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

export interface Session { id: string; userId: string; labId: string; run: number; status: 'active' | 'archived'; state: any; requests: Record<string, any>; createdAt: string; updatedAt: string }
interface Data { users: Record<string, { id: string; name: string }>; tokens: Record<string, string>; sessions: Record<string, Session> }

export class Store {
  private data: Data = { users: {}, tokens: {}, sessions: {} };
  constructor(private file: string | null) {
    if (file && fs.existsSync(file)) { try { this.data = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { console.warn('store: could not parse data file, starting empty'); } }
  }
  private save() {
    if (!this.file) return;
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = `${this.file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.data)); fs.renameSync(tmp, this.file);
  }
  login(name: string) {
    let user = Object.values(this.data.users).find(u => u.name.toLowerCase() === name.toLowerCase());
    if (!user) { user = { id: crypto.randomUUID(), name }; this.data.users[user.id] = user; }
    const token = crypto.randomBytes(24).toString('hex'); this.data.tokens[token] = user.id; this.save();
    return { token, user };
  }
  userByToken(token: string) { const id = this.data.tokens[token]; return id ? this.data.users[id] : null; }
  session(id: string) { return this.data.sessions[id] || null; }
  sessionsOf(userId: string, labId: string) { return Object.values(this.data.sessions).filter(s => s.userId === userId && s.labId === labId).sort((a, b) => a.run - b.run); }
  createSession(userId: string, labId: string, state: any): Session {
    const prior = this.sessionsOf(userId, labId); const now = new Date().toISOString();
    for (const p of prior) if (p.status === 'active') p.status = 'archived';
    const s: Session = { id: crypto.randomUUID(), userId, labId, run: prior.length + 1, status: 'active', state, requests: {}, createdAt: now, updatedAt: now };
    this.data.sessions[s.id] = s; this.save(); return s;
  }
  /** Commits the new state and the idempotency record together. */
  commit(s: Session, state: any, requestId: string | null, response: any) {
    s.state = state; s.updatedAt = new Date().toISOString();
    if (requestId) { s.requests[requestId] = response; const keys = Object.keys(s.requests); if (keys.length > 200) delete s.requests[keys[0]]; }
    this.save();
  }
}
