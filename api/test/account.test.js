import test from 'node:test';
import assert from 'node:assert/strict';
import { rateLimiter, clientIp, newRecoveryCode, normalizeCode, hashCode, findRecovery, activeRecovery } from '../account.js';

const SECRET = 'a'.repeat(64);

/* ---------------- rate limiter ---------------- */

test('the limiter lets the allowed attempts through and refuses the next one', () => {
  const rl = rateLimiter({ max: 3, windowMs: 60000 });
  for (let i = 0; i < 3; i++) assert.equal(rl.hit('ip:1', 0).ok, true);
  const no = rl.hit('ip:1', 1000);
  assert.equal(no.ok, false);
  assert.equal(no.retryAfter, 59);
  assert.equal(no.first, true, 'the first refusal is flagged, to be logged once');
  assert.equal(rl.hit('ip:1', 1001).first, false, 'later refusals are not');
});

test('the limiter counts keys apart and forgets a window once it is over', () => {
  const rl = rateLimiter({ max: 1, windowMs: 1000 });
  assert.equal(rl.hit('ip:1', 0).ok, true);
  assert.equal(rl.hit('ip:1', 10).ok, false);
  assert.equal(rl.hit('ip:2', 10).ok, true, 'another key has its own budget');
  assert.equal(rl.hit('ip:1', 1000).ok, true, 'a new window starts clean');
  rl.sweep(5000);
  assert.equal(rl.size(), 0);
});

/* ---------------- client IP ---------------- */

const req = (peer, xff) => ({ socket: { remoteAddress: peer }, headers: xff ? { 'x-forwarded-for': xff } : {} });

test('with no trusted proxy the socket peer is the client, whatever the header says', () => {
  assert.equal(clientIp(req('::ffff:10.0.0.9', '1.2.3.4'), 0), '10.0.0.9');
});

test('behind nginx (one hop) the address nginx appended is the client; a forged entry is ignored', () => {
  assert.equal(clientIp(req('172.18.0.3', '203.0.113.7'), 1), '203.0.113.7');
  assert.equal(clientIp(req('172.18.0.3', '6.6.6.6, 203.0.113.7'), 1), '203.0.113.7');
});

test('behind Traefik and nginx (two hops) the client is two places from the right', () => {
  assert.equal(clientIp(req('172.18.0.3', '6.6.6.6, 203.0.113.7, 172.30.0.2'), 2), '203.0.113.7');
});

/* ---------------- recovery codes ---------------- */

test('a recovery code has 100 bits in five groups of four and survives sloppy typing', () => {
  const code = newRecoveryCode();
  assert.match(code, /^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){4}$/);
  assert.notEqual(newRecoveryCode(), code);
  const sloppy = ' ' + code.toLowerCase().replace(/-/g, ' ') + ' ';
  assert.equal(normalizeCode(sloppy), code.replace(/-/g, ''));
  assert.equal(normalizeCode('o0-il1'), '00111', 'O reads as 0, I and L as 1');
});

test('only the hash is comparable, and it depends on the instance secret', () => {
  const code = newRecoveryCode();
  const h = hashCode(SECRET, code);
  assert.ok(!h.includes(code.replace(/-/g, '')));
  assert.equal(hashCode(SECRET, code.toLowerCase()), h);
  assert.notEqual(hashCode('b'.repeat(64), code), h);
});

test('a valid code is found; used, revoked, expired and unknown ones are not (each says why)', () => {
  const now = 1_000_000;
  const mk = (code, extra) => ({ id: code, userId: 'u1', hash: hashCode(SECRET, code), exp: now + 1000, ...extra });
  const records = [
    mk('GOOD'), mk('USED', { usedAt: 'x' }), mk('GONE', { revokedAt: 'x' }), mk('OLD0', { exp: now - 1 })
  ];
  assert.equal(findRecovery(records, SECRET, 'good', now).ok, true);
  assert.equal(findRecovery(records, SECRET, 'USED', now).reason, 'used');
  assert.equal(findRecovery(records, SECRET, 'GONE', now).reason, 'revoked');
  assert.equal(findRecovery(records, SECRET, 'OLD0', now).reason, 'expired');
  assert.equal(findRecovery(records, SECRET, 'NOPE', now).reason, 'unknown');
  assert.equal(findRecovery([], SECRET, '', now).ok, false);
});

test('the admin view of a recovery code never carries its hash', () => {
  const now = 1_000_000;
  const records = [{ id: 'r1', userId: 'u1', hash: 'HASH', created: 'c', exp: now + 5 }];
  assert.deepEqual(activeRecovery(records, 'u1', now), { id: 'r1', created: 'c', exp: now + 5 });
  assert.equal(activeRecovery(records, 'u2', now), null);
  assert.equal(activeRecovery(records, 'u1', now + 5), null, 'expired is not active');
});
