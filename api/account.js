/* Account access helpers: rate limiting, client IP behind proxies and
   one-time recovery codes. Pure functions over plain objects so they can be tested on their own;
   server.js owns db.json and the routes. Recovery codes are bearer secrets: only an HMAC of the
   code is ever stored or logged, and the code itself is shown once, to the admin who made it. */
import crypto from 'node:crypto';

/* ---------- rate limiting (in-memory, fixed window) ---------- */
// One limiter per route family. hit(key) counts the attempt and says whether it is allowed;
// over the limit it returns the seconds until the window resets. Memory is bounded by sweeping
// expired windows on every call to sweep() (server.js runs it on an interval).
export function rateLimiter({ max, windowMs }) {
  const hits = new Map(); // key -> { n, reset }
  return {
    hit(key, now = Date.now()) {
      let h = hits.get(key);
      if (!h || h.reset <= now) { h = { n: 0, reset: now + windowMs }; hits.set(key, h); }
      h.n++;
      // `first` marks the first refusal of the window, so a caller can log once, not per request.
      if (h.n > max) return { ok: false, first: h.n === max + 1, retryAfter: Math.max(1, Math.ceil((h.reset - now) / 1000)) };
      return { ok: true };
    },
    sweep(now = Date.now()) { for (const [k, h] of hits) if (h.reset <= now) hits.delete(k); },
    size: () => hits.size
  };
}

/* ---------- client IP ---------- */
// `hops` = how many reverse proxies we trust in front of the API (nginx alone = 1, Traefik +
// nginx = 2). Each trusted proxy appends the address it saw to X-Forwarded-For, so the client
// is the entry `hops` places from the right once the socket peer is appended. Anything further
// left was written by the client and is ignored, which is what makes the header unspoofable.
// If the chain is shorter than `hops`, some proxy that should have written an entry didn't (or
// the request skipped it): the socket peer is then the only address nobody but the network
// chose, so that is the answer — never an entry the client may have written.
export function clientIp(req, hops = 0) {
  const peer = String(req.socket?.remoteAddress || '').replace(/^::ffff:/, '');
  if (!hops) return peer;
  const chain = [...forwardedFor(req), peer];
  const i = chain.length - 1 - hops;
  return (i >= 0 ? chain[i] : peer).replace(/^::ffff:/, '');
}
// The X-Forwarded-For entries as received (for logging how long the chain was).
export function forwardedFor(req) {
  return String(req.headers?.['x-forwarded-for'] || '').split(',').map(s => s.trim()).filter(Boolean);
}

/* ---------- recovery codes ---------- */
// 20 symbols of Crockford base32 (no I, L, O, U) = 100 bits, shown in groups of four.
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export const RECOVERY_LEN = 20;

export function newRecoveryCode() {
  const bytes = crypto.randomBytes(RECOVERY_LEN);
  let s = '';
  for (const b of bytes) s += ALPHABET[b & 31];
  return s.match(/.{4}/g).join('-');
}

// What the user typed -> canonical form. Spaces, dashes and case don't matter, and the letters
// Crockford leaves out are read as the digits they look like (O -> 0, I/L -> 1).
export function normalizeCode(input) {
  return String(input || '').toUpperCase().replace(/[^A-Z0-9]/g, '')
    .replace(/O/g, '0').replace(/[IL]/g, '1').slice(0, 64);
}

// HMAC under a key derived from the instance secret: a stolen db.json alone doesn't let anyone
// test guesses offline, 100 bits of entropy makes a slow KDF unnecessary, and the derived key
// keeps these MACs apart from the session-cookie MACs made with the secret itself.
export function hashCode(secret, code) {
  const key = crypto.createHmac('sha256', secret).update('opengym recovery-code key v1').digest();
  return crypto.createHmac('sha256', key).update(normalizeCode(code)).digest('base64url');
}

// Every stored record is compared, valid or not, in constant time per record, so the response
// time doesn't say how close a guess came or which record it hit.
export function findRecovery(records, secret, code, now = Date.now()) {
  const want = Buffer.from(hashCode(secret, code));
  let hit = null;
  for (const r of records || []) {
    const have = Buffer.from(String(r.hash || ''));
    const same = have.length === want.length && crypto.timingSafeEqual(have, want);
    if (same && !hit) hit = r;
  }
  if (!hit) return { ok: false, reason: 'unknown' };
  if (hit.usedAt) return { ok: false, reason: 'used', record: hit };
  if (hit.revokedAt) return { ok: false, reason: 'revoked', record: hit };
  if (!(hit.exp > now)) return { ok: false, reason: 'expired', record: hit };
  return { ok: true, record: hit };
}

// What the admin panel may see about a user's recovery state. Never the hash.
export function activeRecovery(records, userId, now = Date.now()) {
  const r = (records || []).find(x => x.userId === userId && !x.usedAt && !x.revokedAt && x.exp > now);
  return r ? { id: r.id, created: r.created, exp: r.exp } : null;
}
