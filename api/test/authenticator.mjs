/* A software passkey for the API tests: an ES256 key pair that answers
 * WebAuthn registration and authentication ceremonies the way a platform authenticator would,
 * with attestation "none". No browser, no CBOR dependency — the tiny encoder below covers the
 * types an attestation object uses. Test-only; never shipped in the image.
 */
import crypto from 'node:crypto';

/* ---------- minimal CBOR encoder (ints, byte strings, text, maps) ---------- */
function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 0x100) return Buffer.from([(major << 5) | 24, n]);
  if (n < 0x10000) { const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b; }
  const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(n, 1); return b;
}
export function cbor(v) {
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === 'string') { const s = Buffer.from(v, 'utf8'); return Buffer.concat([head(3, s.length), s]); }
  if (Buffer.isBuffer(v) || v instanceof Uint8Array) return Buffer.concat([head(2, v.length), Buffer.from(v)]);
  if (v instanceof Map) {
    const parts = [head(5, v.size)];
    for (const [k, x] of v) parts.push(cbor(k), cbor(x));
    return Buffer.concat(parts);
  }
  throw new Error('cbor: unsupported ' + typeof v);
}

const b64u = buf => Buffer.from(buf).toString('base64url');
const sha256 = data => crypto.createHash('sha256').update(data).digest();

/**
 * @param {object} o
 * @param {string} o.rpId        relying party id (e.g. 'localhost')
 * @param {string} o.origin      origin the "browser" reports (e.g. 'http://localhost:8080')
 * @param {boolean} [o.uv=true]  whether the authenticator reports user verification
 */
export function softAuthenticator({ rpId, origin, uv = true }) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const credId = crypto.randomBytes(32);
  let counter = 0;
  let userHandle = null;
  const flags = 0x01 | (uv ? 0x04 : 0);   // UP (+ UV)

  const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));

  function clientData(type, challenge, overrideOrigin) {
    return Buffer.from(JSON.stringify({ type, challenge, origin: overrideOrigin || origin, crossOrigin: false }));
  }

  return {
    id: b64u(credId),
    /** The COSE public key as server.js stores it in db.creds[].publicKey. */
    publicKeyB64u: b64u(cose),
    get userHandle() { return userHandle; },
    set userHandle(v) { userHandle = v; },
    /** Answer navigator.credentials.create() for the server's options JSON. */
    register(options, { origin: o2 } = {}) {
      userHandle = options.user.id;  // base64url, as the server sent it
      const authData = Buffer.concat([
        sha256(Buffer.from(rpId)), Buffer.from([flags | 0x40]), Buffer.alloc(4),
        Buffer.alloc(16), Buffer.from([0, credId.length]), credId, cose
      ]);
      const attestationObject = cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
      return {
        id: b64u(credId), rawId: b64u(credId), type: 'public-key',
        clientExtensionResults: {}, authenticatorAttachment: 'platform',
        response: {
          clientDataJSON: b64u(clientData('webauthn.create', options.challenge, o2)),
          attestationObject: b64u(attestationObject), transports: ['internal']
        }
      };
    },
    /** Answer navigator.credentials.get() for the server's options JSON. */
    authenticate(options) {
      counter++;
      const c = Buffer.alloc(4); c.writeUInt32BE(counter);
      const authData = Buffer.concat([sha256(Buffer.from(rpId)), Buffer.from([flags]), c]);
      const cd = clientData('webauthn.get', options.challenge);
      const signature = crypto.sign('sha256', Buffer.concat([authData, sha256(cd)]), privateKey);
      return {
        id: b64u(credId), rawId: b64u(credId), type: 'public-key',
        clientExtensionResults: {}, authenticatorAttachment: 'platform',
        response: {
          clientDataJSON: b64u(cd), authenticatorData: b64u(authData),
          signature: b64u(signature), userHandle
        }
      };
    }
  };
}
