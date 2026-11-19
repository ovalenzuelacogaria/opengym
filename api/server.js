/* opengym-api — passkey (WebAuthn) auth + per-user state storage for openGym
   No framework, JSON-file storage, signed session cookies.               */
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse
} from '@simplewebauthn/server';
import webpush from 'web-push';
import * as coachConfig from './coach/config.js';
import * as coachJobs from './coach/jobs.js';
import { coachRoutes } from './coach/routes.js';
import { startCadence } from './coach/cadence.js';
import { rateLimiter, clientIp, forwardedFor, newRecoveryCode, hashCode, findRecovery, activeRecovery } from './account.js';

const PORT = +(process.env.PORT || 3000);
const DATA = process.env.DATA_DIR || '/data';
const RP_ID = process.env.RP_ID || 'localhost';
// Every write is checked against ORIGIN exactly (and WebAuthn too), so a
// stray trailing slash or path would refuse every write in silence. Keep only the origin part and
// say at boot what was done, or why the value can't work.
const ORIGIN = (() => {
  const raw = process.env.ORIGIN || 'http://localhost:8080';
  let u;
  try { u = new URL(raw); } catch { u = null; }
  if (!u || !/^https?:$/.test(u.protocol) || u.origin === 'null') {
    console.error(`ORIGIN "${raw}" is not a valid origin (expected e.g. https://gym.example.com): sign-in and every write will be refused`);
    return raw;
  }
  if (u.origin !== raw) console.warn(`ORIGIN "${raw}" normalized to "${u.origin}" (browsers send no path or trailing slash)`);
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (u.protocol !== 'https:' && !local) console.warn(`ORIGIN "${u.origin}" is not https: browsers allow passkeys only over https (or on localhost), and the session cookie would travel in the clear`);
  return u.origin;
})();
const RP_NAME = process.env.RP_NAME || 'openGym';
// Admin dashboard (issue): admins are matched by uid; INVITE_ONLY gates new signups behind a
// code the admin generates. Both default off so a fresh self-hosted instance stays open.
const ADMIN_UIDS = (process.env.ADMIN_UIDS || '').split(',').map(s => s.trim()).filter(Boolean);
const INVITE_ONLY = /^(1|true|yes|on)$/i.test(process.env.INVITE_ONLY || '');
// 90 days keeps someone who trains a few times a week permanently signed in without a stolen
// cookie staying good for a year. Overridable because a family instance and one on the open
// internet don't want the same number. Only affects cookies minted from now on — the expiry is
// baked into each cookie when it's issued, so lowering this never cuts an existing session short.
const SESSION_DAYS = Math.max(1, +(process.env.SESSION_DAYS || 90) || 90);
// GUEST_MODE=0 tells the app there is no way in without a session: no
// "continue without account", no local-only guest profile. On by default, as in the original.
const GUEST_MODE = !/^(0|false|no|off)$/i.test(process.env.GUEST_MODE || '');
// How long an admin-issued recovery code stays good, unless the admin asks for another span (1-72 h).
const RECOVERY_HOURS = Math.min(72, Math.max(1, +(process.env.RECOVERY_HOURS || 24) || 24));
// Attempts allowed per window on the passkey-add and recovery routes, per client IP and per user.
// The IP is read through TRUST_PROXY_HOPS reverse proxies (nginx alone = 1, Traefik + nginx = 2).
const AUTH_LIMIT_IP = Math.max(1, +(process.env.AUTH_LIMIT_IP || 20) || 20);
const AUTH_LIMIT_USER = Math.max(1, +(process.env.AUTH_LIMIT_USER || 10) || 10);
const AUTH_LIMIT_WINDOW_MS = Math.max(1, +(process.env.AUTH_LIMIT_WINDOW_MIN || 15) || 15) * 60000;
const TRUST_PROXY_HOPS = Math.max(0, Math.floor(+(process.env.TRUST_PROXY_HOPS ?? 1) || 0));
// How fresh the passkey assertion that unlocks adding or removing a passkey must be.
const STEPUP_MAX_AGE_MS = Math.max(1, +(process.env.STEPUP_MAX_AGE_S || 300) || 300) * 1000;
const MAX_BODY = 5 * 1024 * 1024;
// Secure cookies require HTTPS; over plain http://localhost the flag would drop the cookie
const SECURE = /^https:/i.test(ORIGIN) ? ' Secure;' : '';

fs.mkdirSync(DATA, { recursive: true });
// 0700 is what stops the unprivileged user that Coach jobs run as from reading any of this —
// state files, db.json, the session secret, the provider credential. The Agent SDK process gets
// its job payload in a temp directory and nothing else. Best-effort: a bind-mounted host directory
// may refuse the chmod, and that is not a reason to refuse to boot.
try { fs.chmodSync(DATA, 0o700); } catch { /* host filesystem says no — carry on */ }

/* ---------- secret + db ---------- */
const secretFile = path.join(DATA, 'secret');
if (!fs.existsSync(secretFile)) fs.writeFileSync(secretFile, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
const SECRET = fs.readFileSync(secretFile, 'utf8').trim();

const dbFile = path.join(DATA, 'db.json');
let db = { users: [], creds: [], subs: [], invites: [] };
try { db = JSON.parse(fs.readFileSync(dbFile, 'utf8')); } catch {}
db.subs = db.subs || [];
db.invites = db.invites || [];
db.recovery = db.recovery || [];   // admin-issued recovery codes, stored as HMACs only
db.authLog = db.authLog || [];     // account-access events (never a code, key or cookie)
const isAdmin = user => !!user && (user.admin === true || ADMIN_UIDS.includes(user.id));
function saveDb() { atomicWrite(dbFile, JSON.stringify(db, null, 2)); }
function atomicWrite(file, content) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, content);
  fs.renameSync(tmp, file);
}
const stateFile = uid => path.join(DATA, 'state-' + uid.replace(/[^a-zA-Z0-9_-]/g, '') + '.json');
function readState(uid) {
  try { return JSON.parse(fs.readFileSync(stateFile(uid), 'utf8')); } catch { return null; }
}

/* ---------- push notifications (Web Push / VAPID) ---------- */
const vapidFile = path.join(DATA, 'vapid.json');
let vapid;
try { vapid = JSON.parse(fs.readFileSync(vapidFile, 'utf8')); }
catch { vapid = webpush.generateVAPIDKeys(); fs.writeFileSync(vapidFile, JSON.stringify(vapid), { mode: 0o600 }); }
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || (SECURE ? ORIGIN : 'mailto:admin@localhost');
webpush.setVapidDetails(VAPID_SUBJECT, vapid.publicKey, vapid.privateKey);

async function sendPush(userId, payload) {
  const subs = db.subs.filter(s => s.userId === userId);
  if (!subs.length) return;
  const body = JSON.stringify(payload);
  let dirty = false;
  await Promise.all(subs.map(async sub => {
    // urgency 'high' is the one lever we have over delivery speed — iOS/Android throttle
    // low-urgency background push more aggressively under battery-saving modes. TTL is left
    // at the library default (long) so a briefly-offline device still gets it once reconnected,
    // rather than risking it being dropped for the sake of shaving off latency that TTL doesn't
    // actually control anyway.
    try { await webpush.sendNotification({ endpoint: sub.endpoint, keys: sub.keys }, body, { urgency: 'high' }); }
    catch (e) {
      console.error('push send failed', userId, e.statusCode, e.body || e.message);
      if (e.statusCode === 404 || e.statusCode === 410) {
        db.subs = db.subs.filter(s => s.endpoint !== sub.endpoint); dirty = true;
      }
    }
  }));
  if (dirty) saveDb();
}

// Rest-timer alerts: client schedules on start/extend, cancels on skip or on-screen completion —
// this only fires when the tab was backgrounded/suspended and never got to cancel it itself.
const restTimers = new Map(); // userId -> Timeout
function scheduleRestTimer(userId, sec) {
  const t = restTimers.get(userId);
  if (t) clearTimeout(t);
  restTimers.set(userId, setTimeout(() => {
    restTimers.delete(userId);
    sendPush(userId, { title: 'Rest over 💪', body: 'Time for your next set.', tag: 'rest-timer' });
  }, sec * 1000));
}
function cancelRestTimer(userId) {
  const t = restTimers.get(userId);
  if (t) { clearTimeout(t); restTimers.delete(userId); }
}

// "Workout planned today" reminder — one per user per day, at their chosen time.
// Duplicated (not imported) from frontend/src/lib/history.js effectiveRoutineId — tiny pure helper, not worth sharing across the two runtimes.
function effectiveRoutineId(S, iso) {
  const ov = S.dayPlan?.[iso];
  if (ov === 'rest') return null;
  if (ov && S.routines?.some(r => r.id === ov)) return ov;
  const wd = new Date(iso + 'T12:00:00').getDay();
  return S.week?.[wd] || null;
}
// Computes "now" in an arbitrary IANA zone (e.g. "Europe/Lisbon") instead of the server's own —
// each user's reminder fires by their own clock, wherever they and their phone actually are.
function userNow(tz) {
  try {
    const parts = new Intl.DateTimeFormat('en-CA', {
      timeZone: tz, hour12: false,
      year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit'
    }).formatToParts(new Date());
    const g = t => parts.find(p => p.type === t)?.value;
    const date = `${g('year')}-${g('month')}-${g('day')}`;
    // Weekday is derived from the zone's own date, not the server's — a Sunday-evening review
    // has to be Sunday where the user is, which is what the reminder already assumes for time.
    return { date, hhmm: `${g('hour')}:${g('minute')}`, weekday: new Date(date + 'T12:00:00Z').getUTCDay() };
  } catch { return null; } // unknown/invalid tz string — skip this user rather than guess
}
setInterval(() => {
  for (const user of db.users) {
    if (!db.subs.some(s => s.userId === user.id)) continue;
    const S = readState(user.id);
    if (!S?.reminder?.on) continue;
    const now = userNow(S.reminder.tz || 'UTC');
    if (!now || S.reminder.time !== now.hhmm) continue;
    if (user.lastReminder === now.date) continue;
    if ((S.workouts || []).some(w => w.d === now.date)) continue;
    const rid = effectiveRoutineId(S, now.date);
    if (!rid) continue; // rest day — nothing planned
    const routine = (S.routines || []).find(r => r.id === rid);
    console.log('reminder firing', user.id, rid);
    user.lastReminder = now.date;
    saveDb();
    sendPush(user.id, {
      title: routine ? `${routine.emoji || '🏋️'} ${routine.name} today` : 'Workout planned today',
      body: "It's on your plan — let's go 💪",
      tag: 'day-reminder'
    });
  }
// Checked every 10s (not 60s) — ticks aren't aligned to the top of the minute, so a 60s
// interval could sit on your target minute for up to 59s before noticing. 10s caps that at ~9s.
}, 10000).unref();

/* ---------- sessions (signed cookie) ---------- */
function sign(payload) {
  const mac = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  return payload + '.' + mac;
}
function verifySig(token) {
  const i = token.lastIndexOf('.');
  if (i < 0) return null;
  const payload = token.slice(0, i), mac = token.slice(i + 1);
  const expect = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  try {
    if (!crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(expect))) return null;
  } catch { return null; }
  return payload;
}
// Session payload is `<uid>:<expiry>:<version>`, where the version is the user's `sv` counter.
// Bumping `sv` (POST /api/logout/all) makes every cookie ever handed out for that account stop
// verifying, which is the only revocation there was before short of deleting ./data/secret and
// signing out the whole instance. Cookies minted before `sv` existed have no third field and are
// read as version 0, matching a user who has never bumped — they stay valid until they expire.
const sessionVersion = user => user.sv || 0;
function makeSession(user) {
  const exp = Date.now() + SESSION_DAYS * 86400000;
  return sign(user.id + ':' + exp + ':' + sessionVersion(user));
}
function sessionToken(req) {
  const cookies = Object.fromEntries((req.headers.cookie || '').split(';').map(c => {
    const i = c.indexOf('='); return i < 0 ? ['', ''] : [c.slice(0, i).trim(), c.slice(i + 1).trim()];
  }));
  return cookies.gymsid || '';
}
// One session = one cookie value. Its hash names the session for step-up grants and security
// notices without keeping the cookie itself anywhere.
const sessionKeyOf = tok => tok ? crypto.createHash('sha256').update(tok).digest('base64url').slice(0, 22) : '';
const sessionKey = req => sessionKeyOf(sessionToken(req));
function readSession(req) {
  const tok = sessionToken(req);
  if (!tok) return null;
  const payload = verifySig(tok);
  if (!payload) return null;
  const [uid, exp, ver] = payload.split(':');
  // A non-numeric expiry would compare as never-expired (NaN < now is false): treat it as expired.
  if (!uid || !Number.isFinite(+exp) || +exp < Date.now()) return null;
  const user = db.users.find(u => u.id === uid) || null;
  if (!user) return null;
  if (user.disabled) return null;           // disabled accounts are locked out everywhere
  // Missing third field = pre-versioning cookie = version 0. Anything non-numeric is a malformed
  // payload (it still had to pass the HMAC, so this is belt-and-braces) and is refused outright.
  const claimed = ver === undefined ? 0 : Number(ver);
  if (!Number.isInteger(claimed) || claimed !== sessionVersion(user)) return null;
  return user;
}
// Guard for /api/admin/* — resolves the caller and 401/403s if they aren't an admin.
function requireAdmin(req, res) {
  const user = readSession(req);
  if (!user) { json(res, 401, { error: 'not signed in' }); return null; }
  if (!isAdmin(user)) { json(res, 403, { error: 'forbidden' }); return null; }
  return user;
}
function sessionCookie(user, tok = makeSession(user)) {
  return `gymsid=${tok}; Path=/; Max-Age=${SESSION_DAYS * 86400}; HttpOnly;${SECURE} SameSite=Lax`;
}
const clearCookie = `gymsid=; Path=/; Max-Age=0; HttpOnly;${SECURE} SameSite=Lax`;

/* ---------- challenge store (in-memory, 5 min TTL) ---------- */
const challenges = new Map(); // cid -> {challenge, name?, uid?, exp}
function putChallenge(data) {
  const cid = crypto.randomBytes(16).toString('base64url');
  challenges.set(cid, { ...data, exp: Date.now() + 5 * 60000 });
  return cid;
}
function takeChallenge(cid) {
  const c = challenges.get(cid);
  challenges.delete(cid);
  if (!c || c.exp < Date.now()) return null;
  return c;
}
setInterval(() => { for (const [k, v] of challenges) if (v.exp < Date.now()) challenges.delete(k); }, 60000).unref();

/* ---------- account access: rate limits + event log ---------- */
// One pair of limiters (per IP, per user) for each family of new routes. A family counts every
// attempt, good or bad: the point is to cap guessing and hammering, not only failures. Only the
// calls that open a ceremony (*/options) or act on their own (remove, admin) are counted: a
// */verify does nothing without a live, single-use challenge from its options call, so capping
// the options caps the verifies, and a normal "add a passkey" costs 2 attempts, not 4.
const limiterPair = () => ({
  ip: rateLimiter({ max: AUTH_LIMIT_IP, windowMs: AUTH_LIMIT_WINDOW_MS }),
  user: rateLimiter({ max: AUTH_LIMIT_USER, windowMs: AUTH_LIMIT_WINDOW_MS })
});
const limits = { passkey: limiterPair(), recovery: limiterPair(), adminRecovery: limiterPair() };
setInterval(() => { for (const p of Object.values(limits)) { p.ip.sweep(); p.user.sweep(); } }, 60000).unref();
// Counts one attempt against `kind` ('ip' or 'user') and answers 429 when it is over the limit.
// Returns true when the request was refused (the caller just returns).
function overLimit(req, res, family, kind, key) {
  const r = limits[family][kind].hit(kind + ':' + key);
  if (r.ok) return false;
  // Logged once per key and window, and written with the next save: a flood of refused requests
  // must not turn into a flood of log lines and disk writes.
  if (r.first) authEvent('rate-limited', { family, kind, ip: clientIp(req, TRUST_PROXY_HOPS), ...(kind === 'user' ? { userId: key } : {}) });
  json(res, 429, { error: 'too many attempts — try again later' }, { 'Retry-After': String(r.retryAfter) });
  return true;
}
// Persistent, capped record of who did what to whose access. Fields are ids, times and IPs; the
// caller never passes a code, key or cookie. Also printed as one JSON line for `docker logs`.
function authEvent(type, fields) {
  const e = { at: new Date().toISOString(), type, ...fields };
  db.authLog.push(e);
  if (db.authLog.length > 500) db.authLog.splice(0, db.authLog.length - 500);
  console.log('auth-event ' + JSON.stringify(e));
}
const credsOf = uid => db.creds.filter(c => c.userId === uid);
const BAD_CODE = 'invalid or expired recovery code';

/* ---------- step-up grants ---------- */
// A session cookie alone must not be enough to change who can sign in: a borrowed, unlocked
// phone or a copied cookie would otherwise plant a passkey that outlives every sign-out and
// recovery. Adding or removing a passkey first needs a fresh assertion with a passkey the user
// already has. Success gives a one-time grant bound to that exact session (cookie hash), its
// session version, the user and the purpose, valid STEPUP_MAX_AGE_S.
const STEPUP_PURPOSES = new Set(['add', 'remove', 'recovery-issue']);
const grants = new Map(); // token -> { uid, sv, sess, purpose, exp }
setInterval(() => { for (const [k, g] of grants) if (g.exp < Date.now()) grants.delete(k); }, 60000).unref();
function issueGrant(user, sess, purpose) {
  const token = crypto.randomBytes(24).toString('base64url');
  grants.set(token, { uid: user.id, sv: sessionVersion(user), sess, purpose, exp: Date.now() + STEPUP_MAX_AGE_MS });
  return token;
}
// Consumes the grant whatever the outcome; true only if it fits this request exactly.
function takeGrant(token, user, req, purpose) {
  const g = typeof token === 'string' ? grants.get(token) : null;
  if (!g) return false;
  grants.delete(token);
  return g.exp >= Date.now() && g.uid === user.id && g.sv === sessionVersion(user) && g.sess === sessionKey(req) && g.purpose === purpose;
}

/* ---------- security notices ---------- */
// Shown in the app at the next load of every OTHER session of the user (no e-mail in openGym):
// "a passkey was added / removed", "access was recovered". The session that acted is not told.
function notify(user, type, sess, extra = {}) {
  user.notices = (user.notices || []).filter(n => !n.seen).slice(-19);
  user.notices.push({ id: crypto.randomBytes(6).toString('base64url'), at: new Date().toISOString(), type, sess, ...extra });
}
const pendingNotices = (user, req) => (user.notices || [])
  .filter(n => !n.seen && n.sess !== sessionKey(req))
  .map(({ id, at, type, device }) => ({ id, at, type, ...(device ? { device } : {}) }));

// What a passkey row says about where it lives, read from the request that created it. For a
// passkey made on a phone through the desktop's QR dialog the browser reports 'cross-platform'.
function deviceOf(req, body) {
  const ua = String(req.headers['user-agent'] || '');
  const os = /iPhone/.test(ua) ? 'iPhone' : /iPad/.test(ua) ? 'iPad' : /Android/.test(ua) ? 'Android'
    : /Windows/.test(ua) ? 'Windows' : /Mac OS X|Macintosh/.test(ua) ? 'Mac' : /CrOS/.test(ua) ? 'ChromeOS' : /Linux/.test(ua) ? 'Linux' : '';
  const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : '';
  const att = body?.credential?.authenticatorAttachment;
  return { os, browser, attachment: att === 'cross-platform' || att === 'platform' ? att : '' };
}
const publicPasskey = c => ({ id: c.id, device: c.device || null, created: c.created || null, lastUsed: c.lastUsed || null, via: c.via || null });

// Registration options for a passkey on an EXISTING profile (add or recover). Same user handle
// as the original sign-up (Buffer.from(uid)), the user's current passkeys excluded, UV required.
// @simplewebauthn/server 13.3.2: generateRegistrationOptions({ userID: Uint8Array, excludeCredentials: [{ id, transports }] }).
function registrationOptionsFor(user, { exclude = true } = {}) {
  return generateRegistrationOptions({
    rpName: RP_NAME, rpID: RP_ID,
    userID: Buffer.from(user.id), userName: user.name, userDisplayName: user.name,
    attestationType: 'none',
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    excludeCredentials: exclude ? credsOf(user.id).map(c => ({ id: c.id, transports: c.transports })) : []
  });
}
// Verifies a registration response against a stored challenge; answers 400 itself and returns
// null when it doesn't hold. requireUserVerification: true (13.3.2 default) — the UV flag must be set.
async function verifyNewCredential(res, body, c) {
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: body.credential,
      expectedChallenge: c.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true
    });
  } catch (e) { json(res, 400, { error: 'verification failed: ' + e.message }); return null; }
  if (!verification.verified) { json(res, 400, { error: 'not verified' }); return null; }
  return verification.registrationInfo.credential;
}
function storeCredential(user, credential, body, via, req) {
  db.creds.push({
    device: deviceOf(req, body),
    id: credential.id, userId: user.id,
    publicKey: Buffer.from(credential.publicKey).toString('base64url'),
    counter: credential.counter || 0,
    // Client-supplied and later echoed back in options: keep only short strings.
    transports: (Array.isArray(body.credential?.response?.transports) ? body.credential.response.transports : [])
      .filter(t => typeof t === 'string' && t.length <= 20).slice(0, 8),
    created: new Date().toISOString(), via
  });
}

/* ---------- helpers ---------- */
function json(res, code, obj, extraHeaders) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...(extraHeaders || {}) });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', d => {
      size += d.length;
      if (size > MAX_BODY) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(d);
    });
    req.on('end', () => {
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
      catch { reject(new Error('bad json')); }
    });
    req.on('error', reject);
  });
}
const b64uToBuf = s => Buffer.from(s, 'base64url');

/* ---------- live presence (in-memory) ---------- */
// Clients heartbeat /api/activity while a workout is on screen; the admin dashboard reads who's
// live. Purely ephemeral — never persisted. Expires shortly after the last ping.
const presence = new Map();               // uid -> { name, exIdx, exTotal, setsDone, setsTotal, startedAt, updatedAt }
const PRESENCE_TTL = 70000;               // ~3.5× the 20s client heartbeat
function livePresence(uid) {
  const p = presence.get(uid);
  if (!p) return null;
  if (Date.now() - p.updatedAt > PRESENCE_TTL) { presence.delete(uid); return null; }
  return p;
}
setInterval(() => { for (const [k, v] of presence) if (Date.now() - v.updatedAt > PRESENCE_TTL) presence.delete(k); }, 30000).unref();

/* ---------- routes ---------- */
const routes = {
  // With GUEST_MODE=0 the count of profiles is nobody's business before signing in.
  'GET /api/health': async (req, res) => json(res, 200, GUEST_MODE ? { ok: true, users: db.users.length } : { ok: true }),

  // Public config the login screen needs before anyone is signed in. `coach` is absent unless
  // the instance has both switched the Coach on and successfully connected a provider — the
  // single flag every piece of Coach UI hangs off, so an unconfigured instance is byte-for-byte
  // the app it was before the feature existed.
  'GET /api/config': async (req, res) => {
    const coach = coachConfig.publicConfig();
    json(res, 200, { invite_only: INVITE_ONLY, guest_mode: GUEST_MODE, ...(coach ? { coach } : {}) });
  },

  'GET /api/me': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    // `notices`: security events this session has not seen (passkey added/removed, recovery).
    json(res, 200, { user: { id: user.id, name: user.name, admin: isAdmin(user) }, notices: pendingNotices(user, req) });
  },

  // The app shows the notices once; this marks every pending one as seen.
  'POST /api/notices/ack': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    for (const n of user.notices || []) n.seen = true;
    saveDb();
    json(res, 200, { ok: true });
  },

  'POST /api/register/options': async (req, res) => {
    const body = await readBody(req);
    const name = String(body.name || '').trim().slice(0, 40);
    if (!name) return json(res, 400, { error: 'name required' });
    const code = String(body.code || '').trim().toUpperCase();
    if (INVITE_ONLY && !db.invites.some(i => i.code === code && !i.usedBy && !i.revoked))
      return json(res, 403, { error: 'a valid invite code is required' });
    const uid = crypto.randomBytes(12).toString('base64url');
    const options = await generateRegistrationOptions({
      rpName: RP_NAME, rpID: RP_ID,
      userID: Buffer.from(uid), userName: name, userDisplayName: name,
      attestationType: 'none',
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
      excludeCredentials: []
    });
    const cid = putChallenge({ purpose: 'register', challenge: options.challenge, name, uid, code });
    json(res, 200, { cid, options });
  },

  'POST /api/register/verify': async (req, res) => {
    const body = await readBody(req);
    const c = takeChallenge(body.cid);
    // Challenges carry their purpose: an add-passkey or recovery challenge also holds an existing
    // uid, and finishing one here would push a second user row with that id.
    if (!c || !c.uid || c.purpose !== 'register') return json(res, 400, { error: 'challenge expired — try again' });
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: body.credential,
        expectedChallenge: c.challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        requireUserVerification: false
      });
    } catch (e) { return json(res, 400, { error: 'verification failed: ' + e.message }); }
    if (!verification.verified) return json(res, 400, { error: 'not verified' });
    const { credential } = verification.registrationInfo;
    if (db.creds.find(x => x.id === credential.id)) return json(res, 409, { error: 'credential already registered' });
    // Re-check the invite at the last moment (it may have been used/revoked since options), then burn it.
    let invite = null;
    if (INVITE_ONLY) {
      invite = db.invites.find(i => i.code === c.code && !i.usedBy && !i.revoked);
      if (!invite) return json(res, 403, { error: 'invite code is no longer valid — ask for a new one' });
    }
    const user = { id: c.uid, name: c.name, created: new Date().toISOString() };
    if (invite) { user.invitedBy = invite.code; invite.usedBy = user.id; invite.usedAt = user.created; }
    db.users.push(user);
    db.creds.push({
      id: credential.id, userId: user.id,
      publicKey: Buffer.from(credential.publicKey).toString('base64url'),
      counter: credential.counter || 0,
      transports: body.credential?.response?.transports || [],
      // What Settings → Passkeys shows for it.
      device: deviceOf(req, body), created: user.created, via: 'signup'
    });
    saveDb();
    json(res, 200, { user: { id: user.id, name: user.name, admin: isAdmin(user) } }, { 'Set-Cookie': sessionCookie(user) });
  },

  'POST /api/login/options': async (req, res) => {
    const options = await generateAuthenticationOptions({
      rpID: RP_ID, userVerification: 'preferred', allowCredentials: []
    });
    const cid = putChallenge({ purpose: 'login', challenge: options.challenge });
    json(res, 200, { cid, options });
  },

  'POST /api/login/verify': async (req, res) => {
    const body = await readBody(req);
    const c = takeChallenge(body.cid);
    if (!c || c.purpose !== 'login') return json(res, 400, { error: 'challenge expired — try again' });
    const cred = db.creds.find(x => x.id === body.credential?.id);
    if (!cred) return json(res, 404, { error: 'unknown passkey — create a profile first' });
    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: body.credential,
        expectedChallenge: c.challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        requireUserVerification: false,
        credential: {
          id: cred.id,
          publicKey: b64uToBuf(cred.publicKey),
          counter: cred.counter,
          transports: cred.transports
        }
      });
    } catch (e) { return json(res, 400, { error: 'verification failed: ' + e.message }); }
    if (!verification.verified) return json(res, 400, { error: 'not verified' });
    cred.counter = verification.authenticationInfo.newCounter;
    cred.lastUsed = new Date().toISOString();   // shown in Settings -> passkeys
    saveDb();
    const user = db.users.find(u => u.id === cred.userId);
    if (!user) return json(res, 500, { error: 'user missing' });
    if (user.disabled) return json(res, 403, { error: 'this account has been disabled' });
    json(res, 200, { user: { id: user.id, name: user.name, admin: isAdmin(user) } }, { 'Set-Cookie': sessionCookie(user) });
  },

  'POST /api/logout': async (req, res) => json(res, 200, { ok: true }, { 'Set-Cookie': clearCookie }),

  // "Sign out everywhere" — bumps this user's session version, which invalidates every cookie
  // ever issued for the account, on every device, including a copy someone else walked off with.
  // The caller's own cookie is cleared here too, so the browser doing it doesn't sit on a token
  // it no longer accepts. Passkeys are untouched: signing back in works immediately.
  'POST /api/logout/all': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    user.sv = sessionVersion(user) + 1;
    saveDb();
    json(res, 200, { ok: true }, { 'Set-Cookie': clearCookie });
  },

  /* ---------- more passkeys on the same profile ---------- */
  // Signed-in AND a fresh assertion with a passkey the user already has (step-up): a cookie alone can't change who can sign in. The new credential is created under
  // the SAME user handle as the profile; passkeys already on file are excluded; user verification
  // is required.
  'POST /api/passkeys/stepup/options': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    if (overLimit(req, res, 'passkey', 'ip', clientIp(req, TRUST_PROXY_HOPS))) return;
    if (overLimit(req, res, 'passkey', 'user', user.id)) return;
    const body = await readBody(req);
    const purpose = String(body.purpose || '');
    if (!STEPUP_PURPOSES.has(purpose)) return json(res, 400, { error: 'unknown purpose' });
    const options = await generateAuthenticationOptions({
      rpID: RP_ID, userVerification: 'required',
      allowCredentials: credsOf(user.id).map(c => ({ id: c.id, transports: c.transports }))
    });
    const cid = putChallenge({ purpose: 'stepup', challenge: options.challenge, uid: user.id, sv: sessionVersion(user), sess: sessionKey(req), for: purpose });
    json(res, 200, { cid, options });
  },

  'POST /api/passkeys/stepup/verify': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    const body = await readBody(req);
    const c = takeChallenge(body.cid);
    if (!c || c.purpose !== 'stepup') return json(res, 400, { error: 'challenge expired — try again' });
    if (c.uid !== user.id || c.sv !== sessionVersion(user) || c.sess !== sessionKey(req)) return json(res, 403, { error: 'forbidden' });
    // The assertion has to come from one of THIS user's passkeys.
    const cred = db.creds.find(x => x.id === body.credential?.id);
    if (!cred || cred.userId !== user.id) return json(res, 403, { error: 'that passkey is not one of yours' });
    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: body.credential, expectedChallenge: c.challenge, expectedOrigin: ORIGIN, expectedRPID: RP_ID,
        requireUserVerification: true,
        credential: { id: cred.id, publicKey: b64uToBuf(cred.publicKey), counter: cred.counter, transports: cred.transports }
      });
    } catch (e) { return json(res, 400, { error: 'verification failed: ' + e.message }); }
    if (!verification.verified) return json(res, 400, { error: 'not verified' });
    if (user.disabled || sessionVersion(user) !== c.sv || !credsOf(user.id).includes(cred)) return json(res, 403, { error: 'forbidden' });
    cred.counter = verification.authenticationInfo.newCounter;
    cred.lastUsed = new Date().toISOString();
    saveDb();
    json(res, 200, { grant: issueGrant(user, c.sess, c.for), expiresIn: Math.round(STEPUP_MAX_AGE_MS / 1000) });
  },

  'POST /api/passkeys/options': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    if (overLimit(req, res, 'passkey', 'ip', clientIp(req, TRUST_PROXY_HOPS))) return;
    if (overLimit(req, res, 'passkey', 'user', user.id)) return;
    const body = await readBody(req);
    if (!takeGrant(body.grant, user, req, 'add')) return json(res, 403, { error: 'confirm with one of your passkeys first' });
    const options = await registrationOptionsFor(user);
    const cid = putChallenge({ purpose: 'add', challenge: options.challenge, uid: user.id, sv: sessionVersion(user), sess: sessionKey(req) });
    json(res, 200, { cid, options });
  },

  'POST /api/passkeys/verify': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    const body = await readBody(req);
    const c = takeChallenge(body.cid);
    if (!c || c.purpose !== 'add') return json(res, 400, { error: 'challenge expired — try again' });
    // The ceremony belongs to the session that started it, and only while that session lives.
    if (c.uid !== user.id || c.sv !== sessionVersion(user) || c.sess !== sessionKey(req)) return json(res, 403, { error: 'forbidden' });
    const credential = await verifyNewCredential(res, body, c);
    if (!credential) return;
    // Re-check after the await: the account may have been disabled or signed out meanwhile.
    if (user.disabled || sessionVersion(user) !== c.sv || !db.users.includes(user)) return json(res, 403, { error: 'forbidden' });
    if (db.creds.find(x => x.id === credential.id)) return json(res, 409, { error: 'credential already registered' });
    storeCredential(user, credential, body, 'add', req);
    const device = deviceOf(req, body);
    notify(user, 'passkey.added', c.sess, { device });
    authEvent('passkey.added', { userId: user.id, credId: credential.id.slice(0, 12), device, ip: clientIp(req, TRUST_PROXY_HOPS) });
    saveDb();
    json(res, 200, { ok: true, passkeys: credsOf(user.id).length });
  },

  // The user's own passkeys, for Settings. Never key material.
  'GET /api/passkeys': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    json(res, 200, { passkeys: credsOf(user.id).map(publicPasskey) });
  },

  // Remove one of the user's passkeys: also behind a step-up (a cookie thief must not be able to
  // lock the owner out), and never the last one (that is what recovery is for).
  'POST /api/passkeys/remove': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    if (overLimit(req, res, 'passkey', 'ip', clientIp(req, TRUST_PROXY_HOPS))) return;
    if (overLimit(req, res, 'passkey', 'user', user.id)) return;
    const body = await readBody(req);
    if (!takeGrant(body.grant, user, req, 'remove')) return json(res, 403, { error: 'confirm with one of your passkeys first' });
    const cred = credsOf(user.id).find(c => c.id === body.id);
    if (!cred) return json(res, 404, { error: 'no such passkey' });
    if (credsOf(user.id).length <= 1) return json(res, 400, { error: 'this is your only passkey — it cannot be removed' });
    db.creds = db.creds.filter(c => c !== cred);
    notify(user, 'passkey.removed', sessionKey(req), { device: cred.device || null });
    authEvent('passkey.removed', { userId: user.id, credId: cred.id.slice(0, 12), ip: clientIp(req, TRUST_PROXY_HOPS) });
    saveDb();
    json(res, 200, { ok: true, passkeys: credsOf(user.id).length });
  },

  /* ---------- recovery with an admin-issued, one-time code ---------- */
  // No session: this is how someone who lost their device gets back in. The code names the
  // account (it is bound to one user when issued); nothing the client sends can point it at
  // another. It is burned only when a new passkey has actually been verified, and then every
  // OTHER passkey of the account is removed: the lost device, and anything planted with a stolen
  // session, stops signing in.
  'POST /api/recovery/options': async (req, res) => {
    if (overLimit(req, res, 'recovery', 'ip', clientIp(req, TRUST_PROXY_HOPS))) return;
    const body = await readBody(req);
    const found = findRecovery(db.recovery, SECRET, body.code);
    const user = found.ok ? db.users.find(u => u.id === found.record.userId) : null;
    if (!found.ok || !user || user.disabled) {
      const ip = clientIp(req, TRUST_PROXY_HOPS), xff = forwardedFor(req).length;
      if (found.record) {
        // A known code that can't be used: worth keeping in db.json.
        authEvent('recovery.refused', { userId: found.record.userId, reason: found.ok ? 'account' : found.reason, ip, xff });
        saveDb();
      } else {
        // A guess: to the log only (bounded by the per-IP limit). It also shows which address the
        // server settled on and how long the X-Forwarded-For chain was: the way to check
        // TRUST_PROXY_HOPS on a deployment (see LEEME).
        console.log('auth-event ' + JSON.stringify({ at: new Date().toISOString(), type: 'recovery.refused', reason: 'unknown', ip, xff }));
      }
      return json(res, 400, { error: BAD_CODE });
    }
    if (overLimit(req, res, 'recovery', 'user', user.id)) return;
    // No exclude list: the account's old passkeys are about to go, and a phone that still holds
    // one simply overwrites it under the same user handle.
    const options = await registrationOptionsFor(user, { exclude: false });
    const cid = putChallenge({ purpose: 'recover', challenge: options.challenge, uid: user.id, recId: found.record.id });
    json(res, 200, { cid, options, name: user.name });
  },

  'POST /api/recovery/verify': async (req, res) => {
    const body = await readBody(req);
    const c = takeChallenge(body.cid);
    if (!c || c.purpose !== 'recover') return json(res, 400, { error: 'challenge expired — try again' });
    const credential = await verifyNewCredential(res, body, c);
    if (!credential) return;
    // Everything from here to saveDb() is synchronous, so two ceremonies racing on one code
    // can't both see it unused: the first marks it, the second finds it marked.
    const rec = db.recovery.find(r => r.id === c.recId);
    const user = db.users.find(u => u.id === c.uid);
    if (!rec || rec.userId !== c.uid || rec.usedAt || rec.revokedAt || !(rec.exp > Date.now()) || !user || user.disabled)
      return json(res, 400, { error: BAD_CODE });
    if (db.creds.find(x => x.id === credential.id && x.userId !== user.id)) return json(res, 409, { error: 'credential already registered' });
    rec.usedAt = new Date().toISOString();
    const removed = credsOf(user.id).length;
    db.creds = db.creds.filter(x => x.userId !== user.id);
    storeCredential(user, credential, body, 'recovery', req);
    // Whoever has the lost device keeps its cookie until expiry otherwise: end every session.
    user.sv = sessionVersion(user) + 1;
    const tok = makeSession(user);
    notify(user, 'recovery.used', sessionKeyOf(tok), { device: deviceOf(req, body) });
    authEvent('recovery.used', { userId: user.id, recId: rec.id, credId: credential.id.slice(0, 12), removedPasskeys: removed, ip: clientIp(req, TRUST_PROXY_HOPS) });
    saveDb();
    json(res, 200, { user: { id: user.id, name: user.name, admin: isAdmin(user) } }, { 'Set-Cookie': sessionCookie(user, tok) });
  },

  'GET /api/data': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    try {
      const state = JSON.parse(fs.readFileSync(stateFile(user.id), 'utf8'));
      json(res, 200, { state });
    } catch { json(res, 200, { state: null }); }
  },

  'PUT /api/data': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    const body = await readBody(req);
    if (!body.state || typeof body.state !== 'object') return json(res, 400, { error: 'state required' });
    delete body.state.active;              // in-progress workouts stay device-local
    atomicWrite(stateFile(user.id), JSON.stringify(body.state));
    json(res, 200, { ok: true, ts: body.state._ts || null });
  },

  'GET /api/push/public-key': async (req, res) => json(res, 200, { key: vapid.publicKey }),

  'POST /api/push/subscribe': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    const body = await readBody(req);
    const sub = body.subscription;
    if (!sub?.endpoint || !sub?.keys?.p256dh || !sub?.keys?.auth) return json(res, 400, { error: 'invalid subscription' });
    db.subs = db.subs.filter(s => s.endpoint !== sub.endpoint);
    db.subs.push({ userId: user.id, endpoint: sub.endpoint, keys: sub.keys, created: new Date().toISOString() });
    saveDb();
    json(res, 200, { ok: true });
  },

  'POST /api/push/unsubscribe': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    const body = await readBody(req);
    db.subs = db.subs.filter(s => !(s.userId === user.id && s.endpoint === body.endpoint));
    saveDb();
    json(res, 200, { ok: true });
  },

  'POST /api/push/test': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    await sendPush(user.id, { title: 'openGym', body: 'Test notification ✅ — this is what alerts look like.', tag: 'test' });
    json(res, 200, { ok: true });
  },

  'POST /api/push/rest-timer': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    const body = await readBody(req);
    const sec = Math.max(1, Math.min(3600, Math.round(+body.seconds || 0)));
    if (!sec) return json(res, 400, { error: 'seconds required' });
    scheduleRestTimer(user.id, sec);
    json(res, 200, { ok: true });
  },

  'POST /api/push/rest-timer/cancel': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    cancelRestTimer(user.id);
    json(res, 200, { ok: true });
  },

  // Live-workout heartbeat: client pings while a workout is on screen; { active:false } drops it.
  'POST /api/activity': async (req, res) => {
    const user = readSession(req);
    if (!user) return json(res, 401, { error: 'not signed in' });
    const body = await readBody(req);
    if (body.active) {
      presence.set(user.id, {
        name: String(body.name || '').slice(0, 60),
        exIdx: +body.exIdx || 0, exTotal: +body.exTotal || 0,
        setsDone: +body.setsDone || 0, setsTotal: +body.setsTotal || 0,
        startedAt: +body.startedAt || Date.now(),
        updatedAt: Date.now()
      });
    } else presence.delete(user.id);
    json(res, 200, { ok: true });
  },

  /* ---------- admin dashboard ---------- */
  // One row per user, cheap enough for a personal instance (reads each state file once).
  'GET /api/admin/users': async (req, res) => {
    if (!requireAdmin(req, res)) return;
    const users = db.users.map(u => {
      const S = readState(u.id) || {};
      const workouts = S.workouts || [];
      const last = workouts[workouts.length - 1];
      return {
        id: u.id, name: u.name, created: u.created || null,
        disabled: !!u.disabled, admin: isAdmin(u), invitedBy: u.invitedBy || null,
        workouts: workouts.length,
        lastWorkout: last ? last.d : null,
        lastSync: S._ts || null,
        hasPush: db.subs.some(s => s.userId === u.id),
        passkeys: credsOf(u.id).length,
        live: livePresence(u.id)
      };
    });
    json(res, 200, { users, invite_only: INVITE_ONLY, now: Date.now() });
  },

  // Drill-down: full workout history + body-weight log for one user.
  'GET /api/admin/user': async (req, res) => {
    if (!requireAdmin(req, res)) return;
    const id = new URL(req.url, 'http://x').searchParams.get('id');
    const u = db.users.find(x => x.id === id);
    if (!u) return json(res, 404, { error: 'no such user' });
    const S = readState(u.id) || {};
    json(res, 200, {
      user: { id: u.id, name: u.name, created: u.created || null, disabled: !!u.disabled, admin: isAdmin(u), invitedBy: u.invitedBy || null },
      passkeys: credsOf(u.id).length,
      recovery: activeRecovery(db.recovery, u.id),   // { id, created, exp } or null — never the hash
      unit: S.unit || 'kg',
      lastSync: S._ts || null,
      routines: (S.routines || []).map(r => ({ id: r.id, name: r.name, emoji: r.emoji, count: (r.ex || []).length })),
      bodyweight: S.bodyweight || [],
      workouts: (S.workouts || []).slice().reverse()   // newest first for display
    });
  },

  'POST /api/admin/user/disable': async (req, res) => {
    if (!requireAdmin(req, res)) return;
    const body = await readBody(req);
    const u = db.users.find(x => x.id === body.id);
    if (!u) return json(res, 404, { error: 'no such user' });
    if (isAdmin(u)) return json(res, 400, { error: 'cannot disable an admin' });
    u.disabled = !!body.disabled;
    if (u.disabled) presence.delete(u.id);   // drop them off "training now" at once
    saveDb();
    json(res, 200, { ok: true, id: u.id, disabled: u.disabled });
  },

  'GET /api/admin/invites': async (req, res) => {
    if (!requireAdmin(req, res)) return;
    // resolve usedBy uid → name for display
    const invites = db.invites.map(i => ({
      ...i, usedByName: i.usedBy ? (db.users.find(u => u.id === i.usedBy) || {}).name || null : null
    }));
    json(res, 200, { invites, invite_only: INVITE_ONLY });
  },

  'POST /api/admin/invites/new': async (req, res) => {
    const admin = requireAdmin(req, res); if (!admin) return;
    const body = await readBody(req);
    let code;
    // 16 hex chars = 64 bits, up from 8 chars / 32 bits. The app has no rate limiting by design
    // (that's the reverse proxy's job) and /api/register/options tells a caller whether a code is
    // good, so the code itself has to be the thing that isn't worth guessing. Codes already in
    // db.json keep working — validation is an exact string compare, never a length or format check.
    do { code = crypto.randomBytes(8).toString('hex').toUpperCase(); } while (db.invites.some(i => i.code === code));
    const invite = { code, note: String(body.note || '').slice(0, 60), createdBy: admin.id, created: new Date().toISOString() };
    db.invites.push(invite);
    saveDb();
    json(res, 200, { invite });
  },

  'POST /api/admin/invites/revoke': async (req, res) => {
    if (!requireAdmin(req, res)) return;
    const body = await readBody(req);
    const inv = db.invites.find(i => i.code === String(body.code || '').toUpperCase());
    if (!inv) return json(res, 404, { error: 'no such code' });
    if (inv.usedBy) return json(res, 400, { error: 'already used — cannot revoke' });
    db.invites = db.invites.filter(i => i.code !== inv.code);
    saveDb();
    json(res, 200, { ok: true });
  },

  // Recovery code for a user who lost their passkey. Shown to the admin
  // once, in this response; stored as an HMAC; one live code per user (a new one revokes the old).
  'POST /api/admin/recovery/new': async (req, res) => {
    const admin = requireAdmin(req, res); if (!admin) return;
    if (overLimit(req, res, 'adminRecovery', 'ip', clientIp(req, TRUST_PROXY_HOPS))) return;
    if (overLimit(req, res, 'adminRecovery', 'user', admin.id)) return;
    const body = await readBody(req);
    // A code lets someone in and, since recovery removes every earlier
    // passkey, locks the owner out. So the admin's cookie alone is not enough: the same step-up
    // as adding a passkey, with its own purpose, from one of the ADMIN's passkeys. (Revoking a
    // code stays cookie-only: it lets nobody in, and it must be quick when a code went astray.)
    if (!takeGrant(body.grant, admin, req, 'recovery-issue')) return json(res, 403, { error: 'confirm with one of your passkeys first' });
    const u = db.users.find(x => x.id === body.id);
    if (!u) return json(res, 404, { error: 'no such user' });
    if (u.disabled) return json(res, 400, { error: 'account is disabled — enable it first' });
    // No admin account, the issuer's own included: a code is a way into an
    // account, and admins are recovered by hand (db.json), not by another admin's click, and not
    // by whoever holds an admin's cookie.
    if (isAdmin(u)) return json(res, 400, { error: 'cannot issue a recovery code for an admin account' });
    const hours = Math.min(72, Math.max(1, Math.round(+body.hours || RECOVERY_HOURS)));
    const now = Date.now();
    for (const r of db.recovery) if (r.userId === u.id && !r.usedAt && !r.revokedAt && r.exp > now) r.revokedAt = new Date(now).toISOString();
    const code = newRecoveryCode();
    const rec = {
      id: crypto.randomBytes(9).toString('base64url'), userId: u.id, hash: hashCode(SECRET, code),
      created: new Date(now).toISOString(), createdBy: admin.id, exp: now + hours * 3600000
    };
    db.recovery.push(rec);
    authEvent('recovery.issued', { userId: u.id, by: admin.id, recId: rec.id, exp: rec.exp, ip: clientIp(req, TRUST_PROXY_HOPS) });
    saveDb();
    json(res, 200, { code, exp: rec.exp, user: { id: u.id, name: u.name } });
  },

  'POST /api/admin/recovery/revoke': async (req, res) => {
    const admin = requireAdmin(req, res); if (!admin) return;
    if (overLimit(req, res, 'adminRecovery', 'ip', clientIp(req, TRUST_PROXY_HOPS))) return;
    if (overLimit(req, res, 'adminRecovery', 'user', admin.id)) return;
    const body = await readBody(req);
    const now = Date.now();
    let n = 0;
    for (const r of db.recovery) if (r.userId === body.id && !r.usedAt && !r.revokedAt && r.exp > now) { r.revokedAt = new Date(now).toISOString(); n++; }
    if (n) { authEvent('recovery.revoked', { userId: body.id, by: admin.id, ip: clientIp(req, TRUST_PROXY_HOPS) }); saveDb(); }
    json(res, 200, { ok: true, revoked: n });
  },

  /* ---------- AI Coach ---------- */
  // Routes live in coach/routes.js and are handed the helpers above rather than importing
  // them: they are closures over db and SECRET, and passing them in keeps that module free of
  // a cycle. Every one of them is inert while the feature is unconfigured.
  ...coachRoutes({ json, readBody, readSession, requireAdmin })
};

// The sign-in screen's routes: the only ones that answer without a session when GUEST_MODE=0.
const PUBLIC_ROUTES = new Set([
  'GET /api/health', 'GET /api/config',
  'POST /api/register/options', 'POST /api/register/verify',
  'POST /api/login/options', 'POST /api/login/verify', 'POST /api/logout',
  'POST /api/recovery/options', 'POST /api/recovery/verify'
]);

/* ---------- Coach: boot recovery, notifications, scheduled reviews ---------- */
// A job that was running when the process died is not coming back; say so rather than leaving
// a spinner that never resolves.
coachJobs.recoverOnBoot();
// A ready proposal is the one Coach event worth a notification. Failures and "nothing to
// change" stay silent on purpose (FR-38/E4).
coachJobs.setProposalHook((uid, pending) => {
  const n = (pending?.changes || []).length;
  if (!n) return;
  sendPush(uid, {
    title: 'Your Coach has been reading',
    body: n === 1 ? '1 suggestion after this week' : `${n} suggestions after this week`,
    tag: 'coach-proposal', url: '#/coach'
  });
});
startCadence({ users: () => db.users, userNow });

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const key = req.method + ' ' + url.pathname;
  const handler = routes[key];
  if (!handler) return json(res, 404, { error: 'not found' });
  // Cross-site writes. SameSite=Lax still sends the cookie from a page on
  // any other subdomain of the same registrable domain (same site for the browser),
  // and a text/plain body needs no CORS preflight. So every request that can change something
  // must be JSON and come from the app's own origin, exactly. Browsers send Origin on every
  // non-GET/HEAD request; one without it is not the app, so it is refused too.
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    const ctype = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
    if (ctype !== 'application/json') return json(res, 415, { error: 'content-type must be application/json' });
    if (req.headers.origin !== ORIGIN) return json(res, 403, { error: 'cross-origin request refused' });
  }
  // GUEST_MODE=0: deny by default. Only what the sign-in screen needs answers without a session;
  // every other route — today's and any added later — is 401 before its handler runs.
  if (!GUEST_MODE && !PUBLIC_ROUTES.has(key) && !readSession(req)) return json(res, 401, { error: 'not signed in' });
  try { await handler(req, res); }
  catch (e) {
    console.error(key, e);
    if (!res.headersSent) json(res, 500, { error: 'server error' });
  }
}).listen(PORT, () => console.log(`gym-api on :${PORT} (rpID=${RP_ID}, origin=${ORIGIN})`));
