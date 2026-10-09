import path from 'node:path';
import { Store } from './store';
import { createApp } from './app';
const port = Number(process.env.PORT || 4000);
const root = path.resolve(import.meta.dirname, '..');
createApp(new Store(process.env.DATA_FILE || path.join(root, 'data', 'store.json')), path.join(root, 'dist')).listen(port, () => console.log(`ThreatReady Lab 001 — http://localhost:${port}`));
