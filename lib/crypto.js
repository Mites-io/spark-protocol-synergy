/**
 * @module gateway/crypto
 *
 * RSA + AES + HMAC primitives the spark handshake needs, built on Node's
 * built-in `crypto` module. This replaces the legacy `ursa` calls in
 * `custom-packages/spark-protocol-synergy/lib/ICrypto.js` — same wire bytes,
 * zero native dependencies, no Node 8 / Ubuntu 16.04 lock-in.
 *
 * **Wire contract (do not change — see CLAUDE.md §8):**
 * - RSA uses **PKCS#1 v1.5 padding**, not OAEP. Particle firmware will not
 *   negotiate any other padding scheme; if you switch to OAEP the handshake
 *   silently fails with a length mismatch on the device side.
 * - "Sign" is raw RSA `privateEncrypt(hash)`; "verify" is `publicDecrypt`
 *   followed by constant-time compare against the expected hash. This is
 *   the legacy `ICrypto.sign / verify` behaviour and matches what the
 *   Photon firmware computes on handshake stage 4.
 * - AES-128-CBC session: the 40-byte session material is split as
 *     `key  = sessionKey[0..16]`
 *     `iv   = sessionKey[16..32]`
 *     `salt = sessionKey[32..40]`   (unused; reserved by the upstream protocol)
 * - HMAC-SHA1 over the AES ciphertext authenticates each frame.
 *
 * All exported functions are pure: they accept the key + input, return the
 * output, and never touch module-level state. The `worker_threads` pool in
 * `crypto-pool.js` is a parallel-RSA wrapper around these same functions.
 *
 * @see `CryptoPool` (gateway/crypto-pool) — worker_threads pool wrapping these RSA ops.
 * @see `runHandshake` (gateway/handshake) — the six-stage handshake that consumes them.
 */

import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  createPrivateKey,
  createPublicKey,
  privateDecrypt,
  privateEncrypt,
  publicDecrypt,
  publicEncrypt,
  randomBytes,
  timingSafeEqual,
  constants,
} from 'node:crypto';

const RSA_PKCS1 = constants.RSA_PKCS1_PADDING;

/**
 * Parse an RSA public key from PEM (SubjectPublicKeyInfo) or DER bytes.
 * Accepts the on-disk shapes used by the spark stack:
 * `keys/srv_keys/default_key.pub.pem`, `default_key.pub.der`,
 * `keys/core_keys/<id>.pub.pem`.
 *
 * @param {Buffer|string} keyMaterial
 * @returns {import('node:crypto').KeyObject}
 */
export function loadPublicKey(keyMaterial) {
  const looksPem =
    typeof keyMaterial === 'string' ||
    (Buffer.isBuffer(keyMaterial) && keyMaterial.slice(0, 5).toString('ascii') === '-----');
  if (looksPem) return createPublicKey(keyMaterial);
  return createPublicKey({ key: keyMaterial, format: 'der', type: 'spki' });
}

/**
 * Parse an RSA private key from PEM. Optional passphrase for legacy keys
 * that were generated with one; the new stack defaults to none.
 *
 * @param {Buffer|string} keyMaterial
 * @param {Buffer|string} [passphrase]
 * @returns {import('node:crypto').KeyObject}
 */
export function loadPrivateKey(keyMaterial, passphrase) {
  return createPrivateKey(passphrase ? { key: keyMaterial, passphrase } : keyMaterial);
}

/**
 * RSA encrypt with a public key, PKCS#1 v1.5 padding.
 * @param {import('node:crypto').KeyObject} publicKey
 * @param {Buffer|Uint8Array} plaintext
 * @returns {Buffer}
 */
export function rsaEncrypt(publicKey, plaintext) {
  return publicEncrypt({ key: publicKey, padding: RSA_PKCS1 }, plaintext);
}

/**
 * RSA decrypt with a private key, PKCS#1 v1.5 padding.
 * @param {import('node:crypto').KeyObject} privateKey
 * @param {Buffer|Uint8Array} ciphertext
 * @returns {Buffer}
 */
export function rsaDecrypt(privateKey, ciphertext) {
  return privateDecrypt({ key: privateKey, padding: RSA_PKCS1 }, ciphertext);
}

/**
 * Raw RSA sign: encrypts `hash` with the private key (PKCS#1 v1.5). The
 * verifier recovers the hash via `publicDecrypt` and compares byte-for-byte.
 * Matches legacy `ICrypto.sign` — the Photon firmware uses this shape on
 * handshake stage 4.
 *
 * @param {import('node:crypto').KeyObject} privateKey
 * @param {Buffer|Uint8Array} hash
 * @returns {Buffer} signature (RSA modulus size, e.g. 256 bytes at 2048-bit)
 */
export function rsaSign(privateKey, hash) {
  return privateEncrypt({ key: privateKey, padding: RSA_PKCS1 }, hash);
}

/**
 * Verify a raw RSA signature: `publicDecrypt(signature)` must equal `hash`.
 * Returns false on any decrypt failure rather than throwing. Constant-time
 * compare on the success path.
 *
 * @param {import('node:crypto').KeyObject} publicKey
 * @param {Buffer|Uint8Array} hash
 * @param {Buffer|Uint8Array} signature
 * @returns {boolean}
 */
export function rsaVerify(publicKey, hash, signature) {
  let recovered;
  try {
    recovered = publicDecrypt({ key: publicKey, padding: RSA_PKCS1 }, signature);
  } catch {
    return false;
  }
  if (recovered.length !== hash.length) return false;
  return timingSafeEqual(recovered, hash);
}

/**
 * @typedef {Object} AesParams
 * @property {Buffer} key 16-byte AES key (sessionKey[0..16])
 * @property {Buffer} iv  16-byte initial IV (sessionKey[16..32])
 */

/**
 * Split the 40-byte session material into AES-128-CBC key + IV per the
 * spark protocol. The trailing 8 bytes are the "salt" slot — unused on the
 * wire today but reserved by upstream.
 *
 * @param {Buffer|Uint8Array} sessionKey
 * @returns {AesParams}
 * @throws {RangeError} if `sessionKey` is shorter than 32 bytes.
 */
export function deriveAesParams(sessionKey) {
  if (sessionKey.length < 32) {
    throw new RangeError(`session key too short: ${sessionKey.length} bytes (need >= 32)`);
  }
  const buf = Buffer.isBuffer(sessionKey) ? sessionKey : Buffer.from(sessionKey);
  return {
    key: buf.subarray(0, 16),
    iv:  buf.subarray(16, 32),
  };
}

/**
 * AES-128-CBC encrypt one frame. The caller owns IV state — the gateway
 * session rolls the IV forward using the last ciphertext block (legacy
 * `CryptoStream` behaviour). Output is PKCS#7-padded to a 16-byte multiple.
 *
 * @param {Buffer} key 16 bytes
 * @param {Buffer} iv  16 bytes
 * @param {Buffer|Uint8Array} plaintext
 * @returns {Buffer}
 */
export function aesEncrypt(key, iv, plaintext) {
  const cipher = createCipheriv('aes-128-cbc', key, iv);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

/**
 * AES-128-CBC decrypt one frame. See {@link aesEncrypt} for IV semantics.
 *
 * Padding follows the firmware's lightssl convention, not strict PKCS#7:
 * `lightssl_message_channel.cpp::wrap` computes `buflen = (msglen & ~15) + 16`
 * and pads with `buflen - msglen` bytes (0..15), then `receive()` strips
 * `buf[packet_size-1]` bytes unconditionally. That diverges from PKCS#7 in
 * one case — when plaintext length is an exact multiple of 16 the firmware
 * adds *no* padding, so Node's default `setAutoPadding(true)` rejects the
 * frame with "bad decrypt". We mirror the firmware: strip exactly `lastByte`
 * bytes if it's in [1,16], else strip none.
 *
 * @param {Buffer} key
 * @param {Buffer} iv
 * @param {Buffer|Uint8Array} ciphertext
 * @returns {Buffer}
 */
export function aesDecrypt(key, iv, ciphertext) {
  const decipher = createDecipheriv('aes-128-cbc', key, iv);
  decipher.setAutoPadding(false);
  const raw = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  const pad = raw[raw.length - 1];
  return (pad >= 1 && pad <= 16) ? raw.subarray(0, raw.length - pad) : raw;
}

/**
 * HMAC-SHA1 digest authenticating an AES ciphertext frame.
 *
 * @param {Buffer|Uint8Array} ciphertext
 * @param {Buffer|Uint8Array} key
 * @returns {Buffer} 20-byte digest
 */
export function hmacSha1(ciphertext, key) {
  return createHmac('sha1', key).update(ciphertext).digest();
}

/**
 * Cryptographically random bytes. Used for handshake nonces and 40-byte
 * session-material generation.
 *
 * @param {number} size
 * @returns {Buffer}
 */
export function randomBuffer(size) {
  return randomBytes(size);
}
