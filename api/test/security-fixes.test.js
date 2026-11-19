/* Security tests: step-up for passkey changes and for issuing recovery codes, recovery that
 * removes earlier passkeys, same-origin JSON writes, client IP behind proxies, ORIGIN at boot.
 * Each attack case sits next to the closest legitimate request, which must still pass.
 * Runs the real server.js.
 */
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, cookieFor, credRow, RP_ID, ORIGIN, SECRET } from './server-harness.mjs';
import { softAuthenticator } from './authenticator.mjs';
import { hashCode } from '../account.js';

const dev = (o = {}) => softAuthenticator({ rpId: RP_ID, origin: ORIGIN, ...o });
const CODE = 'V1C0-V1C0-V1C0-V1C0-V1C0';
const kAdm = dev(), kVic = dev(), kAdm2 = dev(), kBob = dev();
const ENV = { GUEST_MODE: '0', TRUST_PROXY_HOPS: '1', AUTH_LIMIT_IP: '1000', AUTH_LIMIT_USER: '1000' };
const seed = () => ({
  users: [
    { id: 'adm1', name: 'Admin', admin: true }, { id: 'adm2', name: 'Admin2', admin: true },
    { id: 'vic1', name: 'Victima' }, { id: 'bob1', name: 'Bob' }
  ],
  creds: [credRow(kAdm, 'adm1'), credRow(kAdm2, 'adm2'), credRow(kVic, 'vic1'), credRow(kBob, 'bob1')],
  recovery: [{ id: 'rv', userId: 'vic1', hash: hashCode(SECRET, CODE), created: new Date().toISOString(), exp: Date.now() + 3600000 }]
});

let s;
before(async () => { s = await startServer({ db: seed(), env: ENV }); });
after(async () => { await s?.stop(); });

const credsOf = uid => s.db().creds.filter(c => c.userId === uid);
const svOf = uid => s.db().users.find(u => u.id === uid).sv || 0;
const cookie = (uid, exp) => cookieFor(uid, svOf(uid), exp);

async function login(srv, auth) {
  const o = await srv.call('POST', '/api/login/options');
  return srv.call('POST', '/api/login/verify', { body: { cid: o.data.cid, credential: auth.authenticate(o.data.options) } });
}
/** Proves possession of `auth` inside the session `ck`; returns the response (grant in data). */
async function stepUp(srv, ck, auth, purpose) {
  const o = await srv.call('POST', '/api/passkeys/stepup/options', { cookie: ck, body: { purpose } });
  if (o.status !== 200) return o;
  return srv.call('POST', '/api/passkeys/stepup/verify', { cookie: ck, body: { cid: o.data.cid, credential: auth.authenticate(o.data.options) } });
}
/** Admin issues a recovery code the way the panel does: step-up first. */
async function adminIssue(srv, ck, id, key = kAdm) {
  const su = await stepUp(srv, ck, key, 'recovery-issue');
  if (su.status !== 200) return su;
  return srv.call('POST', '/api/admin/recovery/new', { cookie: ck, body: { id, grant: su.data.grant } });
}
async function addWithGrant(srv, ck, grant, auth) {
  const o = await srv.call('POST', '/api/passkeys/options', { cookie: ck, body: { grant } });
  if (o.status !== 200) return o;
  return srv.call('POST', '/api/passkeys/verify', { cookie: ck, body: { cid: o.data.cid, credential: auth.register(o.data.options) } });
}

/* ================= a stolen cookie must not become a permanent passkey ================= */

test('bad: with only the cookie no passkey can be added — options refuse without a step-up grant', async () => {
  const stolen = cookie('vic1');
  const before = credsOf('vic1').length;
  const o = await s.call('POST', '/api/passkeys/options', { cookie: stolen, body: {} });
  assert.equal(o.status, 403);
  const forged = await s.call('POST', '/api/passkeys/options', { cookie: stolen, body: { grant: 'made-up' } });
  assert.equal(forged.status, 403);
  assert.equal(credsOf('vic1').length, before);
});

test('bad: the step-up needs a passkey of THIS user — an attacker key or another user\'s is refused', async () => {
  const stolen = cookie('vic1');
  const unknown = await stepUp(s, stolen, dev(), 'add');
  assert.notEqual(unknown.status, 200);
  const someoneElse = await stepUp(s, stolen, kBob, 'add');
  assert.equal(someoneElse.status, 403);
  assert.equal(someoneElse.data.grant, undefined);
});

test('twin: a fresh assertion with her own passkey lets the user add one, once', async () => {
  const ck = cookie('vic1');
  const su = await stepUp(s, ck, kVic, 'add');
  assert.equal(su.status, 200, JSON.stringify(su.data));
  assert.ok(su.data.grant);
  const phone = dev();
  const add = await addWithGrant(s, ck, su.data.grant, phone);
  assert.equal(add.status, 200, JSON.stringify(add.data));
  assert.ok(credsOf('vic1').some(c => c.id === phone.id));
  // single use
  const again = await s.call('POST', '/api/passkeys/options', { cookie: ck, body: { grant: su.data.grant } });
  assert.equal(again.status, 403);
});

test('bad: a grant is bound to the session and to its purpose', async () => {
  const ck = cookie('vic1');
  const otherSession = cookie('vic1', Date.now() + 7200000);   // same user, another cookie
  const su = await stepUp(s, ck, kVic, 'add');
  assert.equal((await s.call('POST', '/api/passkeys/options', { cookie: otherSession, body: { grant: su.data.grant } })).status, 403, 'other session');
  const su2 = await stepUp(s, ck, kVic, 'remove');
  assert.equal((await s.call('POST', '/api/passkeys/options', { cookie: ck, body: { grant: su2.data.grant } })).status, 403, 'remove grant used to add');
  const su3 = await stepUp(s, ck, kVic, 'nonsense');
  assert.equal(su3.status, 400);
});

test('bad: a grant older than STEPUP_MAX_AGE_S is refused (twin: the same flow inside the window works)', async () => {
  const k = dev();
  const t = await startServer({ db: { users: [{ id: 'u1', name: 'U' }], creds: [credRow(k, 'u1')] }, env: { ...ENV, STEPUP_MAX_AGE_S: '1' } });
  try {
    const ck = cookieFor('u1');
    const late = await stepUp(t, ck, k, 'add');
    await new Promise(r => setTimeout(r, 1300));
    assert.equal((await t.call('POST', '/api/passkeys/options', { cookie: ck, body: { grant: late.data.grant } })).status, 403);
    const fresh = await stepUp(t, ck, k, 'add');
    assert.equal((await t.call('POST', '/api/passkeys/options', { cookie: ck, body: { grant: fresh.data.grant } })).status, 200);
  } finally { await t.stop(); }
});

test('recovery removes every earlier passkey — the lost device (and any planted key) stops working', async () => {
  // Victim has kVic plus the phone added above. Simulate a key planted before this fix.
  const planted = dev();
  const t = await startServer({
    db: { ...seed(), creds: [...seed().creds, { ...credRow(planted, 'vic1') }] }, env: ENV
  });
  try {
    assert.equal((await login(t, planted)).status, 200, 'planted key works before recovery');
    const o = await t.call('POST', '/api/recovery/options', { body: { code: CODE } });
    const fresh = dev();
    const v = await t.call('POST', '/api/recovery/verify', { body: { cid: o.data.cid, credential: fresh.register(o.data.options) } });
    assert.equal(v.status, 200);
    const left = t.db().creds.filter(c => c.userId === 'vic1').map(c => c.id);
    assert.deepEqual(left, [fresh.id], 'only the new passkey is left');
    assert.notEqual((await login(t, planted)).status, 200, 'planted key no longer signs in');
    assert.notEqual((await login(t, kVic)).status, 200, 'lost device no longer signs in');
    assert.equal((await login(t, fresh)).data.user.id, 'vic1', 'twin: the new one does');
    assert.equal((await login(t, kBob)).data.user.id, 'bob1', "other users' passkeys untouched");
    assert.ok(t.db().authLog.some(e => e.type === 'recovery.used' && e.removedPasskeys === 2));
  } finally { await t.stop(); }
});

test('the user lists her passkeys (device, added, last used) and nobody else\'s', async () => {
  await login(s, kVic);   // stamps lastUsed
  const r = await s.call('GET', '/api/passkeys', { cookie: cookie('vic1') });
  assert.equal(r.status, 200);
  const ids = r.data.passkeys.map(p => p.id);
  assert.ok(ids.includes(kVic.id));
  assert.ok(!ids.includes(kBob.id));
  const mine = r.data.passkeys.find(p => p.id === kVic.id);
  assert.ok(mine.lastUsed, 'last use recorded at sign-in');
  assert.equal(mine.publicKey, undefined, 'no key material in the list');
  assert.equal((await s.call('GET', '/api/passkeys')).status, 401);
});

test('removing a passkey needs a step-up (bad: cookie only), works with one (twin), never the last one', async () => {
  const k1 = dev(), k2 = dev();
  const t = await startServer({ db: { users: [{ id: 'u1', name: 'U' }, { id: 'u2', name: 'V' }], creds: [credRow(k1, 'u1'), credRow(k2, 'u1'), credRow(dev(), 'u2')] }, env: ENV });
  try {
    const ck = cookieFor('u1');
    assert.equal((await t.call('POST', '/api/passkeys/remove', { cookie: ck, body: { id: k2.id } })).status, 403, 'cookie only');
    const addGrant = (await stepUp(t, ck, k1, 'add')).data.grant;
    assert.equal((await t.call('POST', '/api/passkeys/remove', { cookie: ck, body: { id: k2.id, grant: addGrant } })).status, 403, 'add grant');
    const other = t.db().creds.find(c => c.userId === 'u2').id;
    let g = (await stepUp(t, ck, k1, 'remove')).data.grant;
    assert.equal((await t.call('POST', '/api/passkeys/remove', { cookie: ck, body: { id: other, grant: g } })).status, 404, "another user's passkey");
    g = (await stepUp(t, ck, k1, 'remove')).data.grant;
    const ok = await t.call('POST', '/api/passkeys/remove', { cookie: ck, body: { id: k2.id, grant: g } });
    assert.equal(ok.status, 200);
    assert.equal(ok.data.passkeys, 1);
    assert.notEqual((await login(t, k2)).status, 200, 'removed passkey no longer signs in');
    g = (await stepUp(t, ck, k1, 'remove')).data.grant;
    assert.equal((await t.call('POST', '/api/passkeys/remove', { cookie: ck, body: { id: k1.id, grant: g } })).status, 400, 'last one stays');
    assert.ok(t.db().authLog.some(e => e.type === 'passkey.removed' && e.userId === 'u1'));
  } finally { await t.stop(); }
});

test('other sessions see a security notice at their next load; the acting session does not; ack clears it', async () => {
  const k1 = dev();
  const t = await startServer({ db: { users: [{ id: 'u1', name: 'U' }], creds: [credRow(k1, 'u1')] }, env: ENV });
  try {
    const here = cookieFor('u1'), elsewhere = cookieFor('u1', 0, Date.now() + 7200000);
    const g = (await stepUp(t, here, k1, 'add')).data.grant;
    assert.equal((await addWithGrant(t, here, g, dev())).status, 200);
    const meHere = await t.call('GET', '/api/me', { cookie: here });
    assert.deepEqual(meHere.data.notices, [], 'the device that did it is not told');
    const meThere = await t.call('GET', '/api/me', { cookie: elsewhere });
    assert.equal(meThere.data.notices.length, 1);
    assert.equal(meThere.data.notices[0].type, 'passkey.added');
    assert.equal((await t.call('POST', '/api/notices/ack', { cookie: elsewhere })).status, 200);
    assert.deepEqual((await t.call('GET', '/api/me', { cookie: elsewhere })).data.notices, []);
    assert.ok(t.db().authLog.some(e => e.type === 'passkey.added'));
  } finally { await t.stop(); }
});

/* ================= no cross-site writes ================= */

test('bad: text/plain or a foreign or missing Origin is refused on every write; twin: JSON from ORIGIN passes', async () => {
  const t = await startServer({ db: seed(), env: ENV });
  try {
    const adm = cookieFor('adm1');
    const writes = [
      ['POST', '/api/admin/recovery/revoke', { id: 'vic1' }],
      ['POST', '/api/admin/user/disable', { id: 'bob1', disabled: false }],
      ['PUT', '/api/data', { state: { workouts: [] } }],
      ['POST', '/api/logout/all', {}]
    ];
    for (const [m, p, body] of writes) {
      const raw = JSON.stringify(body);
      const plain = await t.call(m, p, { cookie: adm, ctype: 'text/plain', raw });
      assert.equal(plain.status, 415, `${p} text/plain`);
      const sub = await t.call(m, p, { cookie: adm, raw, origin: 'https://other.example.com' });
      assert.equal(sub.status, 403, `${p} foreign origin`);
      const none = await t.call(m, p, { cookie: adm, raw, origin: null });
      assert.equal(none.status, 403, `${p} no origin`);
      const lookalike = await t.call(m, p, { cookie: adm, raw, origin: ORIGIN + '.evil.example' });
      assert.equal(lookalike.status, 403, `${p} look-alike origin`);
    }
    assert.equal(t.db().users.find(u => u.id === 'bob1').disabled, undefined, 'nothing changed');
    // Twin: same writes, as the app sends them.
    for (const [m, p, body] of writes) {
      const ok = await t.call(m, p, { cookie: cookieFor('adm1', t.db().users.find(u => u.id === 'adm1').sv || 0), body });
      assert.equal(ok.status, 200, `${p} from the app`);
    }
    // Also guards the public sign-in handshakes, and charset is fine.
    assert.equal((await t.call('POST', '/api/login/options', { origin: 'https://other.example.com' })).status, 403);
    assert.equal((await t.call('POST', '/api/login/options', { ctype: 'application/json; charset=utf-8' })).status, 200);
    // Reads are unaffected.
    assert.equal((await t.call('GET', '/api/config', { origin: null })).status, 200);
  } finally { await t.stop(); }
});

/* ================= a short X-Forwarded-For chain never lets the client pick its IP ================= */

test('bad: hops=2 but the request carries only the client\'s own entry — rotating it buys no new budget', async () => {
  const t = await startServer({ db: seed(), env: { ...ENV, TRUST_PROXY_HOPS: '2', AUTH_LIMIT_IP: '5' } });
  try {
    let n429 = 0;
    for (let i = 0; i < 12; i++) {
      const r = await t.call('POST', '/api/recovery/options', { body: { code: 'NOPE' }, headers: { 'X-Forwarded-For': '203.0.113.' + i } });
      if (r.status === 429) n429++;
    }
    assert.equal(n429, 7, 'counted against the connection, not the header');
  } finally { await t.stop(); }
});

test('twin: a full chain (client, Traefik) with hops=2 keeps clients apart', async () => {
  const t = await startServer({ db: seed(), env: { ...ENV, TRUST_PROXY_HOPS: '2', AUTH_LIMIT_IP: '3' } });
  try {
    for (let i = 0; i < 3; i++) await t.call('POST', '/api/recovery/options', { body: { code: 'NOPE' }, headers: { 'X-Forwarded-For': '203.0.113.1, 172.30.0.2' } });
    assert.equal((await t.call('POST', '/api/recovery/options', { body: { code: 'NOPE' }, headers: { 'X-Forwarded-For': '203.0.113.1, 172.30.0.2' } })).status, 429);
    assert.equal((await t.call('POST', '/api/recovery/options', { body: { code: 'NOPE' }, headers: { 'X-Forwarded-For': '203.0.113.2, 172.30.0.2' } })).status, 400);
  } finally { await t.stop(); }
});

test('an unknown code is logged with the IP the server settled on (how to measure TRUST_PROXY_HOPS)', async () => {
  const t = await startServer({ db: seed(), env: { ...ENV, TRUST_PROXY_HOPS: '1' } });
  try {
    await t.call('POST', '/api/recovery/options', { body: { code: 'NOPE' }, headers: { 'X-Forwarded-For': '192.0.2.77, 198.51.100.9' } });
    const line = t.log.split('\n').find(l => l.includes('"recovery.refused"') && l.includes('"unknown"'));
    assert.ok(line, 'logged');
    assert.ok(line.includes('"ip":"198.51.100.9"') && line.includes('"xff":2'), line);
    assert.ok(!(t.db().authLog || []).some(e => e.reason === 'unknown'), 'guesses go to the log only, not to db.json');
  } finally { await t.stop(); }
});

/* ================= no admin takes another admin's account ================= */

test('bad: no recovery code for an admin account (another admin or oneself); twin: for a normal user it works', async () => {
  assert.equal((await adminIssue(s, cookie('adm1'), 'adm2')).status, 400);
  assert.equal((await adminIssue(s, cookie('adm1'), 'adm1')).status, 400);
  assert.equal((await adminIssue(s, cookie('adm1'), 'bob1')).status, 200);
});

/* ================= informational ================= */

test('with GUEST_MODE=0 /api/health says nothing about users (twin: open instances keep the count)', async () => {
  assert.deepEqual((await s.call('GET', '/api/health')).data, { ok: true });
  const t = await startServer({ db: seed() });
  try { assert.equal((await t.call('GET', '/api/health')).data.users, 4); } finally { await t.stop(); }
});

test('a signed cookie whose expiry is not a number is expired (twin: a numeric one is fine)', async () => {
  assert.equal((await s.call('GET', '/api/me', { cookie: cookieFor('bob1', svOf('bob1'), 'abc') })).status, 401);
  assert.equal((await s.call('GET', '/api/me', { cookie: cookieFor('bob1', svOf('bob1')) })).status, 200);
});

/* ================= issuing recovery codes; ORIGIN at boot ================= */

test('bad: an admin cookie alone can no longer issue a code and lock a user out', async () => {
  const t = await startServer({ db: seed(), env: ENV });
  try {
    const adm = cookieFor('adm1');
    const noGrant = await t.call('POST', '/api/admin/recovery/new', { cookie: adm, body: { id: 'vic1' } });
    assert.equal(noGrant.status, 403);
    assert.equal(noGrant.data.code, undefined);
    const forged = await t.call('POST', '/api/admin/recovery/new', { cookie: adm, body: { id: 'vic1', grant: 'made-up' } });
    assert.equal(forged.status, 403);
    // A grant for another purpose does not do either.
    const addGrant = (await stepUp(t, adm, kAdm, 'add')).data.grant;
    assert.equal((await t.call('POST', '/api/admin/recovery/new', { cookie: adm, body: { id: 'vic1', grant: addGrant } })).status, 403);
    // A thief's own authenticator can't produce the admin's step-up.
    assert.notEqual((await stepUp(t, adm, dev(), 'recovery-issue')).status, 200);
    // The victim still gets in with the passkey she had.
    assert.equal((await login(t, kVic)).data.user.id, 'vic1');
    assert.equal(t.db().creds.filter(c => c.userId === 'vic1').length, 1);
  } finally { await t.stop(); }
});

test('twin: with the admin\'s own passkey (step-up "recovery-issue") the code is issued, once per grant', async () => {
  const t = await startServer({ db: seed(), env: ENV });
  try {
    const adm = cookieFor('adm1');
    const su = await stepUp(t, adm, kAdm, 'recovery-issue');
    assert.equal(su.status, 200);
    const ok = await t.call('POST', '/api/admin/recovery/new', { cookie: adm, body: { id: 'vic1', grant: su.data.grant } });
    assert.equal(ok.status, 200);
    assert.match(ok.data.code, /^[0-9A-Z]{4}(-[0-9A-Z]{4}){4}$/);
    const again = await t.call('POST', '/api/admin/recovery/new', { cookie: adm, body: { id: 'vic1', grant: su.data.grant } });
    assert.equal(again.status, 403, 'single use');
    // Revoking stays a plain admin action: it gives nobody access (decision documented in the LEEME).
    assert.equal((await t.call('POST', '/api/admin/recovery/revoke', { cookie: adm, body: { id: 'vic1' } })).status, 200);
  } finally { await t.stop(); }
});

test('ORIGIN with a trailing slash is normalised and announced at boot (twin: writes from the real origin pass)', async () => {
  const t = await startServer({ db: seed(), env: { ...ENV, ORIGIN: ORIGIN + '/' } });
  try {
    assert.match(t.log, /ORIGIN .*normali[sz]ed/i);
    assert.equal((await t.call('POST', '/api/login/options')).status, 200, 'the browser sends no slash');
    assert.equal((await t.call('PUT', '/api/data', { cookie: cookieFor('bob1'), body: { state: { workouts: [] } } })).status, 200);
  } finally { await t.stop(); }
});

test('an ORIGIN that is not a URL, or plain http on a real host, is called out at boot', async () => {
  const bad = await startServer({ db: seed(), env: { ...ENV, ORIGIN: 'gym.example.com' } });
  try { assert.match(bad.log, /ORIGIN .*not a valid origin/i); } finally { await bad.stop(); }
  const plain = await startServer({ db: seed(), env: { ...ENV, ORIGIN: 'http://gym.example.com' } });
  try { assert.match(plain.log, /ORIGIN .*https/i); } finally { await plain.stop(); }
  const ok = await startServer({ db: seed(), env: ENV });   // http://localhost:8080: fine for local use
  try { assert.doesNotMatch(ok.log, /ORIGIN /); } finally { await ok.stop(); }
});
