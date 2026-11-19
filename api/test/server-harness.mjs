/* Starts the real server.js in a child process against a throwaway DATA_DIR, so the route tests
 * exercise exactly what ships. Seeds db.json and the instance secret
 * before boot, mints session cookies the way server.js does, and keeps the child's output so a
 * test can check that no secret reached the log. Each instance is stopped by the test that made it.
 */
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const API_DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
export const SECRET = 'a'.repeat(64);
export const RP_ID = 'localhost';
export const ORIGIN = 'http://localhost:8080';

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); });
  });
}

/**
 * @param {object} [o]
 * @param {object} [o.db]   initial db.json contents
 * @param {object} [o.env]  extra environment for the server
 */
export async function startServer({ db = {}, env = {} } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gym-auth-test-'));
  fs.writeFileSync(path.join(dir, 'secret'), SECRET, { mode: 0o600 });
  fs.writeFileSync(path.join(dir, 'db.json'), JSON.stringify({ users: [], creds: [], subs: [], invites: [], ...db }));
  const port = await freePort();
  const child = spawn(process.execPath, ['server.js'], {
    cwd: API_DIR,
    env: {
      PATH: process.env.PATH, SystemRoot: process.env.SystemRoot,
      PORT: String(port), DATA_DIR: dir, RP_ID, ORIGIN, RP_NAME: 'openGym test',
      ...env
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  let log = '';
  child.stdout.on('data', d => { log += d; });
  child.stderr.on('data', d => { log += d; });
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('server did not start:\n' + log)), 15000);
    child.stdout.on('data', () => { if (log.includes('gym-api on')) { clearTimeout(t); resolve(); } });
    child.once('exit', code => { clearTimeout(t); reject(new Error('server exited ' + code + ':\n' + log)); });
  });
  const base = `http://127.0.0.1:${port}`;

  async function call(method, p, { body, cookie, headers = {} } = {}) {
    const r = await fetch(base + p, {
      method,
      headers: { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}), ...headers },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    const data = await r.json().catch(() => ({}));
    const set = r.headers.get('set-cookie');
    const m = set && /gymsid=([^;]*)/.exec(set);
    return { status: r.status, data, headers: r.headers, cookie: m && m[1] ? 'gymsid=' + m[1] : null };
  }

  return {
    dir, base, call,
    get log() { return log; },
    db: () => JSON.parse(fs.readFileSync(path.join(dir, 'db.json'), 'utf8')),
    stop: () => new Promise(resolve => { child.once('exit', () => resolve()); child.kill(); })
  };
}

/** A cookie exactly as server.js mints it: `<uid>:<expiry>:<session version>` + HMAC. */
export function cookieFor(uid, sv = 0) {
  const payload = uid + ':' + (Date.now() + 86400000) + ':' + sv;
  const mac = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  return 'gymsid=' + payload + '.' + mac;
}

/** A stored credential row for a soft authenticator that is already registered. */
export function credRow(auth, userId) {
  return { id: auth.id, userId, publicKey: auth.publicKeyB64u, counter: 0, transports: ['internal'] };
}
