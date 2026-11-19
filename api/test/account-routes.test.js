/* Route tests for multi-device passkeys, admin-issued recovery codes, rate limits and the
 * no-guest gate. Each bad case sits next to its good twin: the
 * same request that must fail, and the closest one that must pass. Runs the real server.js.
 */
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, cookieFor, credRow, RP_ID, ORIGIN, SECRET } from './server-harness.mjs';
import { softAuthenticator } from './authenticator.mjs';
import { hashCode } from '../account.js';

const dev = (o = {}) => softAuthenticator({ rpId: RP_ID, origin: ORIGIN, ...o });
const b64u = s => Buffer.from(s).toString('base64url');

// Codes seeded straight into db.json (hashed, as the server stores them): the only way to have
// one that is already expired without waiting a day.
const EXPIRED = 'EXP1-EXP1-EXP1-EXP1-EXP1';
const FOR_BOB = 'B0B0-B0B0-B0B0-B0B0-B0B0';
const FOR_EVE = 'EVE0-EVE0-EVE0-EVE0-EVE0';
const HOUR = 3600000;

const aliceWin = dev(), bobOld = dev(), adminKey = dev();
let srv;

function seed() {
  const now = Date.now();
  return {
    users: [
      { id: 'admin1', name: 'Admin', admin: true, created: '2026-11-01T00:00:00Z' },
      { id: 'alice1', name: 'Alice', created: '2026-11-01T00:00:00Z' },
      { id: 'bob1', name: 'Bob', created: '2026-11-01T00:00:00Z' },
      { id: 'eve1', name: 'Eve', created: '2026-11-01T00:00:00Z', disabled: true }
    ],
    creds: [credRow(adminKey, 'admin1'), credRow(aliceWin, 'alice1'), credRow(bobOld, 'bob1')],
    recovery: [
      { id: 'rexp', userId: 'alice1', hash: hashCode(SECRET, EXPIRED), created: new Date(now - 30 * HOUR).toISOString(), exp: now - 6 * HOUR },
      { id: 'rbob', userId: 'bob1', hash: hashCode(SECRET, FOR_BOB), created: new Date(now).toISOString(), exp: now + 24 * HOUR },
      { id: 'reve', userId: 'eve1', hash: hashCode(SECRET, FOR_EVE), created: new Date(now).toISOString(), exp: now + 24 * HOUR }
    ]
  };
}

before(async () => { srv = await startServer({ db: seed(), env: { AUTH_LIMIT_IP: '1000', AUTH_LIMIT_USER: '1000' } }); });
after(async () => { await srv?.stop(); });

const ADMIN = cookieFor('admin1'), ALICE = cookieFor('alice1'), BOB = cookieFor('bob1');

async function login(auth) {
  const o = await srv.call('POST', '/api/login/options', { body: {} });
  const v = await srv.call('POST', '/api/login/verify', { body: { cid: o.data.cid, credential: auth.authenticate(o.data.options) } });
  return v;
}
async function addPasskey(cookie, auth) {
  const o = await srv.call('POST', '/api/passkeys/options', { body: {}, cookie });
  if (o.status !== 200) return o;
  return srv.call('POST', '/api/passkeys/verify', { body: { cid: o.data.cid, credential: auth.register(o.data.options) }, cookie });
}
async function recover(code, auth) {
  const o = await srv.call('POST', '/api/recovery/options', { body: { code } });
  if (o.status !== 200) return o;
  return srv.call('POST', '/api/recovery/verify', { body: { cid: o.data.cid, credential: auth.register(o.data.options) } });
}
const credsOf = uid => srv.db().creds.filter(c => c.userId === uid);

/* ================= 1. a second passkey on the same profile ================= */

test('adding a passkey needs a session (bad) — and with one it lands on the same user (twin)', async () => {
  const usersBefore = srv.db().users.length;
  const anon = await srv.call('POST', '/api/passkeys/options', { body: {} });
  assert.equal(anon.status, 401);

  const iphone = dev();
  const o = await srv.call('POST', '/api/passkeys/options', { body: {}, cookie: ALICE });
  assert.equal(o.status, 200);
  assert.equal(o.data.options.user.id, b64u('alice1'), 'the authenticator files it under the same user handle');
  assert.equal(o.data.options.authenticatorSelection.userVerification, 'required');
  assert.ok(o.data.options.excludeCredentials.some(c => c.id === aliceWin.id), 'the passkey she already has is excluded');
  const v = await srv.call('POST', '/api/passkeys/verify', { body: { cid: o.data.cid, credential: iphone.register(o.data.options) }, cookie: ALICE });
  assert.equal(v.status, 200, JSON.stringify(v.data));
  assert.equal(v.data.passkeys, 2);

  const db = srv.db();
  assert.equal(db.users.length, usersBefore, 'no new profile was created');
  assert.deepEqual(credsOf('alice1').map(c => c.id).sort(), [aliceWin.id, iphone.id].sort());

  // Both devices sign in to the same profile.
  for (const auth of [aliceWin, iphone]) {
    const l = await login(auth);
    assert.equal(l.status, 200);
    assert.equal(l.data.user.id, 'alice1');
  }
});

test("one user's add-passkey ceremony can't be finished in another user's session", async () => {
  const before = srv.db().creds.length;
  const o = await srv.call('POST', '/api/passkeys/options', { body: {}, cookie: ALICE });
  const v = await srv.call('POST', '/api/passkeys/verify', { body: { cid: o.data.cid, credential: dev().register(o.data.options) }, cookie: BOB });
  assert.equal(v.status, 403);
  assert.equal(srv.db().creds.length, before);
});

test('adding a passkey without user verification is refused (bad) — with it, accepted (twin)', async () => {
  const before = credsOf('bob1').length;
  const noUv = await addPasskey(BOB, dev({ uv: false }));
  assert.equal(noUv.status, 400);
  assert.equal(credsOf('bob1').length, before);
  const withUv = await addPasskey(BOB, dev());
  assert.equal(withUv.status, 200);
  assert.equal(credsOf('bob1').length, before + 1);
});

test('the same authenticator twice is a conflict, not a second row', async () => {
  const again = await addPasskey(ALICE, aliceWin);
  assert.equal(again.status, 409);
});

test("an add-passkey challenge can't be replayed at sign-up to clone the profile", async () => {
  const usersBefore = srv.db().users.length;
  const o = await srv.call('POST', '/api/passkeys/options', { body: {}, cookie: ALICE });
  const r = await srv.call('POST', '/api/register/verify', { body: { cid: o.data.cid, credential: dev().register(o.data.options) } });
  assert.equal(r.status, 400);
  assert.equal(srv.db().users.length, usersBefore);
  assert.equal(srv.db().users.filter(u => u.id === 'alice1').length, 1);
});

test('plain sign-up still makes a new profile (the original flow is untouched)', async () => {
  const o = await srv.call('POST', '/api/register/options', { body: { name: 'Carol' } });
  assert.equal(o.status, 200);
  const v = await srv.call('POST', '/api/register/verify', { body: { cid: o.data.cid, credential: dev().register(o.data.options) } });
  assert.equal(v.status, 200);
  assert.equal(v.data.user.name, 'Carol');
});

/* ================= 2. admin-issued recovery codes ================= */

test('only an admin can issue a recovery code', async () => {
  assert.equal((await srv.call('POST', '/api/admin/recovery/new', { body: { id: 'alice1' } })).status, 401);
  assert.equal((await srv.call('POST', '/api/admin/recovery/new', { body: { id: 'alice1' }, cookie: BOB })).status, 403);
  assert.equal((await srv.call('POST', '/api/admin/recovery/new', { body: { id: 'nobody' }, cookie: ADMIN })).status, 404);
});

test('a code recovers the account on a new device: same user, passkey bound to it, old sessions ended', async () => {
  const issued = await srv.call('POST', '/api/admin/recovery/new', { body: { id: 'alice1' }, cookie: ADMIN });
  assert.equal(issued.status, 200);
  const { code, exp } = issued.data;
  assert.match(code, /^[0-9A-Z]{4}(-[0-9A-Z]{4}){4}$/);
  assert.ok(exp > Date.now() + 23 * HOUR && exp <= Date.now() + 24 * HOUR, 'expires in 24 h by default');

  // Stored and logged only as a hash.
  const raw = JSON.stringify(srv.db());
  assert.ok(!raw.includes(code) && !raw.includes(code.replace(/-/g, '')), 'db.json never holds the code');
  assert.ok(!srv.log.includes(code) && !srv.log.includes(code.replace(/-/g, '')), 'the log never holds the code');
  assert.ok(srv.db().authLog.some(e => e.type === 'recovery.issued' && e.userId === 'alice1' && e.by === 'admin1'));

  // The admin panel sees that a code is pending, never the code or its hash.
  const detail = await srv.call('GET', '/api/admin/user?id=alice1', { cookie: ADMIN });
  assert.equal(detail.data.recovery.exp, exp);
  assert.equal(detail.data.recovery.hash, undefined);
  assert.equal(detail.data.passkeys, credsOf('alice1').length);

  const usersBefore = srv.db().users.length;
  const svBefore = srv.db().users.find(u => u.id === 'alice1').sv || 0;
  const phone = dev();
  const o = await srv.call('POST', '/api/recovery/options', { body: { code: code.toLowerCase() } });
  assert.equal(o.status, 200);
  assert.equal(o.data.name, 'Alice');
  assert.equal(o.data.options.user.id, b64u('alice1'));
  const v = await srv.call('POST', '/api/recovery/verify', { body: { cid: o.data.cid, credential: phone.register(o.data.options) } });
  assert.equal(v.status, 200, JSON.stringify(v.data));
  assert.equal(v.data.user.id, 'alice1');
  assert.ok(v.cookie, 'signed in on the new device');

  const db = srv.db();
  assert.equal(db.users.length, usersBefore, 'no new profile');
  assert.ok(credsOf('alice1').some(c => c.id === phone.id));
  assert.equal(db.users.find(u => u.id === 'alice1').sv, svBefore + 1, 'cookies on the lost device stop working');
  assert.equal((await srv.call('GET', '/api/me', { cookie: ALICE })).status, 401, 'the old cookie is dead');
  assert.equal((await srv.call('GET', '/api/me', { cookie: v.cookie })).data.user.id, 'alice1', 'the new one works');
  assert.ok(db.authLog.some(e => e.type === 'recovery.used' && e.userId === 'alice1'));
  assert.ok(!JSON.stringify(db).includes(code.replace(/-/g, '')));

  // The new passkey signs in on its own afterwards.
  const l = await login(phone);
  assert.equal(l.data.user.id, 'alice1');

  // Used once: a second go is refused and adds nothing.
  const before = db.creds.length;
  const again = await recover(code, dev());
  assert.equal(again.status, 400);
  assert.equal(srv.db().creds.length, before);
});

test('an expired code is refused (bad); a live code issued the same way works (twin)', async () => {
  const before = srv.db().creds.length;
  const old = await recover(EXPIRED, dev());
  assert.equal(old.status, 400);
  assert.equal(srv.db().creds.length, before);

  const live = await recover(FOR_BOB, dev());
  assert.equal(live.status, 200);
  assert.equal(live.data.user.id, 'bob1', "Bob's code opens Bob's account and nobody else's");
});

test('a code binds to its own user: the verify step ignores any user the client claims', async () => {
  const code = (await srv.call('POST', '/api/admin/recovery/new', { body: { id: 'bob1' }, cookie: ADMIN })).data.code;
  const aliceBefore = credsOf('alice1').length;
  const o = await srv.call('POST', '/api/recovery/options', { body: { code } });
  const auth = dev();
  const cred = auth.register(o.data.options);
  const v = await srv.call('POST', '/api/recovery/verify', { body: { cid: o.data.cid, credential: cred, userId: 'alice1', uid: 'alice1' }, cookie: ALICE });
  assert.equal(v.status, 200);
  assert.equal(v.data.user.id, 'bob1');
  assert.equal(credsOf('alice1').length, aliceBefore);
  assert.ok(credsOf('bob1').some(c => c.id === auth.id));
});

test('issuing a new code kills the previous one (bad); the new one works (twin)', async () => {
  const first = (await srv.call('POST', '/api/admin/recovery/new', { body: { id: 'bob1' }, cookie: ADMIN })).data.code;
  const second = (await srv.call('POST', '/api/admin/recovery/new', { body: { id: 'bob1' }, cookie: ADMIN })).data.code;
  assert.equal((await srv.call('POST', '/api/recovery/options', { body: { code: first } })).status, 400);
  assert.equal((await srv.call('POST', '/api/recovery/options', { body: { code: second } })).status, 200);
});

test('a revoked code is refused (bad); a fresh one after it works (twin)', async () => {
  const code = (await srv.call('POST', '/api/admin/recovery/new', { body: { id: 'bob1' }, cookie: ADMIN })).data.code;
  const bobNow = cookieFor('bob1', srv.db().users.find(u => u.id === 'bob1').sv || 0);
  assert.equal((await srv.call('GET', '/api/me', { cookie: bobNow })).status, 200, 'a live, non-admin session');
  assert.equal((await srv.call('POST', '/api/admin/recovery/revoke', { body: { id: 'bob1' }, cookie: bobNow })).status, 403);
  const rv = await srv.call('POST', '/api/admin/recovery/revoke', { body: { id: 'bob1' }, cookie: ADMIN });
  assert.equal(rv.status, 200);
  assert.equal((await srv.call('POST', '/api/recovery/options', { body: { code } })).status, 400);
  const fresh = (await srv.call('POST', '/api/admin/recovery/new', { body: { id: 'bob1' }, cookie: ADMIN })).data.code;
  assert.equal((await recover(fresh, dev())).status, 200);
});

test("a disabled account can't be recovered, and no code can be issued for it", async () => {
  assert.equal((await recover(FOR_EVE, dev())).status, 400);
  assert.equal((await srv.call('POST', '/api/admin/recovery/new', { body: { id: 'eve1' }, cookie: ADMIN })).status, 400);
});

test('one code, two ceremonies started in parallel: only one of them gets in', async () => {
  const code = (await srv.call('POST', '/api/admin/recovery/new', { body: { id: 'bob1' }, cookie: ADMIN })).data.code;
  const [o1, o2] = await Promise.all([1, 2].map(() => srv.call('POST', '/api/recovery/options', { body: { code } })));
  const [a1, a2] = [dev(), dev()];
  const [v1, v2] = await Promise.all([
    srv.call('POST', '/api/recovery/verify', { body: { cid: o1.data.cid, credential: a1.register(o1.data.options) } }),
    srv.call('POST', '/api/recovery/verify', { body: { cid: o2.data.cid, credential: a2.register(o2.data.options) } })
  ]);
  assert.deepEqual([v1.status, v2.status].sort(), [200, 400]);
});

test('a recovery ceremony from the wrong origin is refused and burns nothing', async () => {
  const code = (await srv.call('POST', '/api/admin/recovery/new', { body: { id: 'bob1' }, cookie: ADMIN })).data.code;
  const o = await srv.call('POST', '/api/recovery/options', { body: { code } });
  const bad = await srv.call('POST', '/api/recovery/verify', { body: { cid: o.data.cid, credential: dev().register(o.data.options, { origin: 'https://evil.example' }) } });
  assert.equal(bad.status, 400);
  assert.equal((await recover(code, dev())).status, 200, 'the code is still good for the real device');
});

/* ================= 3. config and the no-guest gate ================= */

test('the instance says whether guests are allowed — on by default, like the original', async () => {
  const c = await srv.call('GET', '/api/config');
  assert.equal(c.data.guest_mode, true);
});

const DATA_ROUTES = [
  ['GET', '/api/me'], ['GET', '/api/data'], ['PUT', '/api/data', { state: { workouts: [] } }],
  ['POST', '/api/logout/all'], ['POST', '/api/push/subscribe', { subscription: { endpoint: 'x', keys: { p256dh: 'x', auth: 'x' } } }],
  ['POST', '/api/push/unsubscribe', { endpoint: 'x' }], ['POST', '/api/push/test'], ['POST', '/api/push/rest-timer', { seconds: 60 }],
  ['POST', '/api/push/rest-timer/cancel'], ['POST', '/api/activity', { active: false }],
  ['POST', '/api/passkeys/options'], ['POST', '/api/passkeys/verify'],
  ['GET', '/api/admin/users'], ['GET', '/api/admin/user?id=alice1'], ['POST', '/api/admin/user/disable', { id: 'bob1' }],
  ['GET', '/api/admin/invites'], ['POST', '/api/admin/invites/new'], ['POST', '/api/admin/invites/revoke', { code: 'X' }],
  ['POST', '/api/admin/recovery/new', { id: 'bob1' }], ['POST', '/api/admin/recovery/revoke', { id: 'bob1' }],
  ['GET', '/api/coach/status'], ['POST', '/api/coach/plan'], ['POST', '/api/coach/review'],
  ['POST', '/api/coach/pending/resolve'], ['POST', '/api/coach/forget'], ['GET', '/api/admin/coach']
];
// Public in the original (instance facts, no user data); GUEST_MODE=0 closes them too.
const OPEN_IN_ORIGINAL = [['GET', '/api/coach/disclosure'], ['GET', '/api/push/public-key']];
// What the sign-in screen needs; answers without a session in every mode.
const SIGN_IN_SCREEN = [['GET', '/api/health'], ['GET', '/api/config'], ['POST', '/api/login/options'], ['POST', '/api/logout']];

test('without a cookie no data or account route answers (bad); with a valid one they do (twin)', async () => {
  for (const [m, p, body] of DATA_ROUTES) {
    const r = await srv.call(m, p, m === 'GET' ? {} : { body: body || {} });
    assert.ok(r.status === 401, `${m} ${p} without a session answered ${r.status}`);
  }
  // A forged cookie (right shape, wrong signature) is no better than none.
  const forged = 'gymsid=bob1:' + (Date.now() + 1e6) + ':0.AAAA';
  assert.equal((await srv.call('GET', '/api/data', { cookie: forged })).status, 401);

  const me = await srv.call('GET', '/api/me', { cookie: cookieFor('bob1', srv.db().users.find(u => u.id === 'bob1').sv || 0) });
  assert.equal(me.status, 200);
  assert.equal((await srv.call('GET', '/api/data', { cookie: ADMIN })).status, 200);
  assert.equal((await srv.call('GET', '/api/admin/users', { cookie: ADMIN })).status, 200);
});

test('GUEST_MODE=0: without a cookie every route but the sign-in screen is 401 (bad); with one, all answer (twin)', async () => {
  const s = await startServer({ db: seed(), env: { GUEST_MODE: '0' } });
  try {
    assert.equal((await s.call('GET', '/api/config')).data.guest_mode, false);
    for (const [m, p, body] of [...DATA_ROUTES, ...OPEN_IN_ORIGINAL]) {
      const r = await s.call(m, p, m === 'GET' ? {} : { body: body || {} });
      assert.equal(r.status, 401, `${m} ${p} without a session answered ${r.status}`);
    }
    // A route nobody has listed is closed too: deny by default.
    assert.equal((await s.call('GET', '/api/coach/disclosure', { cookie: 'gymsid=forged.AAAA' })).status, 401);
    for (const [m, p] of SIGN_IN_SCREEN) {
      const r = await s.call(m, p, m === 'GET' ? {} : { body: {} });
      assert.equal(r.status, 200, `${m} ${p} is needed to sign in but answered ${r.status}`);
    }
    // Twin: the same routes with a valid session.
    for (const [m, p] of [['GET', '/api/me'], ['GET', '/api/data'], ...OPEN_IN_ORIGINAL]) {
      assert.equal((await s.call(m, p, { cookie: ALICE })).status, 200, `${m} ${p} with a session`);
    }
    assert.equal((await s.call('GET', '/api/admin/users', { cookie: ADMIN })).status, 200);
  } finally { await s.stop(); }
});

test('with guests allowed (the default) the original public routes stay public', async () => {
  for (const [m, p] of OPEN_IN_ORIGINAL) assert.equal((await srv.call(m, p)).status, 200, `${m} ${p}`);
});

/* ================= 4. rate limits on the new routes ================= */

test('recovery attempts are capped per IP (bad); another IP still gets through (twin)', async () => {
  const s = await startServer({ db: seed(), env: { AUTH_LIMIT_IP: '3', AUTH_LIMIT_USER: '100', TRUST_PROXY_HOPS: '1' } });
  try {
    const from = ip => ({ 'X-Forwarded-For': ip });
    for (let i = 0; i < 3; i++) {
      const r = await s.call('POST', '/api/recovery/options', { body: { code: 'WRONG' + i }, headers: from('198.51.100.1') });
      assert.equal(r.status, 400);
    }
    const blocked = await s.call('POST', '/api/recovery/options', { body: { code: FOR_BOB }, headers: from('198.51.100.1') });
    assert.equal(blocked.status, 429);
    assert.ok(+blocked.headers.get('retry-after') > 0);
    // A forged left-most entry doesn't buy a fresh budget: nginx's own entry is what counts.
    const spoof = await s.call('POST', '/api/recovery/options', { body: { code: FOR_BOB }, headers: from('9.9.9.9, 198.51.100.1') });
    assert.equal(spoof.status, 429);
    const other = await s.call('POST', '/api/recovery/options', { body: { code: FOR_BOB }, headers: from('198.51.100.2') });
    assert.equal(other.status, 200);
  } finally { await s.stop(); }
});

test('add-passkey attempts are capped per user (bad); another user is unaffected (twin)', async () => {
  const s = await startServer({ db: seed(), env: { AUTH_LIMIT_IP: '100', AUTH_LIMIT_USER: '2' } });
  try {
    for (let i = 0; i < 2; i++) assert.equal((await s.call('POST', '/api/passkeys/options', { body: {}, cookie: ALICE })).status, 200);
    assert.equal((await s.call('POST', '/api/passkeys/options', { body: {}, cookie: ALICE })).status, 429);
    assert.equal((await s.call('POST', '/api/passkeys/options', { body: {}, cookie: BOB })).status, 200);
  } finally { await s.stop(); }
});

test('recovery attempts on one account are capped per user, whichever IP they come from', async () => {
  const s = await startServer({ db: seed(), env: { AUTH_LIMIT_IP: '100', AUTH_LIMIT_USER: '2', TRUST_PROXY_HOPS: '1' } });
  try {
    for (let i = 0; i < 2; i++) {
      const r = await s.call('POST', '/api/recovery/options', { body: { code: FOR_BOB }, headers: { 'X-Forwarded-For': '203.0.113.' + i } });
      assert.equal(r.status, 200);
    }
    const r = await s.call('POST', '/api/recovery/options', { body: { code: FOR_BOB }, headers: { 'X-Forwarded-For': '203.0.113.9' } });
    assert.equal(r.status, 429);
  } finally { await s.stop(); }
});

test('issuing recovery codes is capped too', async () => {
  const s = await startServer({ db: seed(), env: { AUTH_LIMIT_IP: '100', AUTH_LIMIT_USER: '2' } });
  try {
    for (let i = 0; i < 2; i++) assert.equal((await s.call('POST', '/api/admin/recovery/new', { body: { id: 'bob1' }, cookie: ADMIN })).status, 200);
    assert.equal((await s.call('POST', '/api/admin/recovery/new', { body: { id: 'bob1' }, cookie: ADMIN })).status, 429);
  } finally { await s.stop(); }
});
