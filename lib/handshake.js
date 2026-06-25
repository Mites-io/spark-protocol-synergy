/**
 * @module gateway/handshake
 *
 * The six-stage spark handshake (ported from
 * `custom-packages/spark-protocol-synergy/lib/Handshake.js`). Wire bytes
 * exactly match the legacy protocol; see CLAUDE.md §8 — the firmware
 * contract is frozen.
 *
 * **Stages:**
 *
 * 1. **SEND_NONCE** — server writes 40 random bytes plaintext to the
 *    socket.
 * 2. **READ_COREID** — device replies with a 256-byte RSA-PKCS#1v1.5
 *    blob encrypted with the server's public key. Decrypted plaintext
 *    is `[40-byte nonce ‖ 12-byte device id ‖ optional DER device
 *    pubkey]`. The nonce must echo what we sent.
 * 3. **GET_COREKEY** — look up `keys/core_keys/<coreId>.pub.pem`. If
 *    absent and the device sent an inline pubkey, quarantine it as
 *    `<coreId>_handshake.pub.pem` and fail (operator must promote).
 * 4. **SEND_SESSIONKEY** — generate 40 bytes of session material; RSA
 *    encrypt with device pubkey (128 B at RSA-1024); HMAC-SHA1 the
 *    ciphertext with the session material; RSA-sign the HMAC with the
 *    server private key (256 B at RSA-2048). Send `ct ‖ sig` = 384 B.
 *    From this point all traffic is AES-128-CBC, key = `session[0..16]`,
 *    initial IV = `session[16..32]`, with each side rolling its own IV
 *    forward (next IV = first 16 bytes of the most recent ciphertext, per
 *    firmware convention — see {@link module:gateway/session}).
 * 5. **GET_HELLO** — read one length-prefixed AES-encrypted frame.
 *    Decrypt with the initial IV. Payload is a CoAP "Hello" whose
 *    message-id seeds `recvCounter`; the optional 4-byte body is
 *    `[productId u16][firmwareVersion u16]`.
 * 6. **SEND_HELLO** — server picks a random 16-bit `sendCounter`;
 *    AES-encrypts a CoAP Hello; sends one framed payload. Roll the
 *    outbound IV forward to the first 16 bytes of the ciphertext just sent.
 *
 * The handshake is implemented as an async function (not a state
 * machine class) because the natural control flow is sequential awaits.
 * I/O is injected via the `io` interface so tests can drive both ends
 * in-memory without sockets.
 */

import { Buffer } from 'node:buffer';

import {
  aesDecrypt,
  aesEncrypt,
  deriveAesParams,
  hmacSha1,
  randomBuffer,
} from './crypto.js';
import { Code, Option, Type, decode as coapDecode, encode as coapEncode } from './coap.js';

const NONCE_BYTES = 40;
const ID_BYTES = 12;
const SESSION_BYTES = 40;

/**
 * @typedef {Object} HandshakeIO
 * @property {(buf: Buffer) => void} write   Plaintext write to the socket.
 * @property {(n: number) => Promise<Buffer>} readBytes
 *   Read exactly `n` plaintext bytes.
 * @property {() => Promise<Buffer>} readFrame
 *   Read one length-prefixed payload (post-stage-4).
 * @property {(buf: Buffer) => void} writeFrame
 *   Write one length-prefixed payload (post-stage-4).
 */

/**
 * @typedef {Object} HandshakeProgress
 *   Mutated in-place by `runHandshake` so the caller can read the last
 *   stage reached + the device id (if learned) even when the handshake
 *   throws. Optional — pass `{}` and inspect after the call.
 * @property {('SEND_NONCE'|'READ_COREID'|'GET_COREKEY'|'SEND_SESSIONKEY'|'GET_HELLO'|'SEND_HELLO'|'DONE')} [stage]
 * @property {string} [coreId] populated when stage 2 finishes.
 *
 * @typedef {Object} HandshakeOptions
 * @property {HandshakeIO} io
 * @property {import('./crypto-pool.js').CryptoPool} crypto
 * @property {string} serverPrivKeyPem PEM-encoded server RSA private key.
 * @property {(coreId: string, inlineDer: Buffer|null) => Promise<string|null>} loadCoreKey
 *   Resolves to the device's canonical pubkey PEM, or null to fail closed.
 * @property {HandshakeProgress} [progress]
 */

/**
 * @typedef {Object} HandshakeResult
 * @property {string} coreId        24-char hex.
 * @property {Buffer} sessionKey    Raw 40 bytes.
 * @property {Buffer} aesKey        16-byte AES-128 key.
 * @property {Buffer} ivIn          Inbound IV after stage 5 (16 bytes).
 * @property {Buffer} ivOut         Outbound IV after stage 6 (16 bytes).
 * @property {number} recvCounter   Initial recv counter (device's Hello id).
 * @property {number} sendCounter   Initial send counter (our random id).
 * @property {number=} productId
 * @property {number=} firmwareVersion
 */

/** Handshake-specific error type so the session can distinguish causes. */
export class HandshakeError extends Error {
  constructor(message, fields = {}) {
    super(message);
    this.name = 'HandshakeError';
    Object.assign(this, fields);
  }
}

/**
 * Run the six-stage handshake to completion. Resolves with the AES
 * session state needed to spin up a `Session`. Rejects with
 * {@link HandshakeError} on any protocol failure.
 *
 * @param {HandshakeOptions} opts
 * @returns {Promise<HandshakeResult>}
 */
export async function runHandshake(opts) {
  const { io, crypto, serverPrivKeyPem, loadCoreKey, progress = {} } = opts;

  // Stage 1: SEND_NONCE
  progress.stage = 'SEND_NONCE';
  const nonce = randomBuffer(NONCE_BYTES);
  io.write(nonce);

  // Stage 2: READ_COREID — 256-byte RSA-2048 ciphertext from the device.
  progress.stage = 'READ_COREID';
  const ciphertext = await io.readBytes(256);
  let plaintext;
  try {
    plaintext = await crypto.decrypt(serverPrivKeyPem, ciphertext);
  } catch (err) {
    throw new HandshakeError('RSA decrypt failed', { cause: err.message });
  }
  if (plaintext.length < NONCE_BYTES + ID_BYTES) {
    throw new HandshakeError('plaintext too small', { length: plaintext.length });
  }
  if (!plaintext.subarray(0, NONCE_BYTES).equals(nonce)) {
    throw new HandshakeError('nonce mismatch');
  }
  const coreId = plaintext.subarray(NONCE_BYTES, NONCE_BYTES + ID_BYTES).toString('hex');
  progress.coreId = coreId;
  const inlineDer = plaintext.length > NONCE_BYTES + ID_BYTES
    ? Buffer.from(plaintext.subarray(NONCE_BYTES + ID_BYTES))
    : null;

  // Stage 3: GET_COREKEY
  progress.stage = 'GET_COREKEY';
  const corePubPem = await loadCoreKey(coreId, inlineDer);
  if (!corePubPem) {
    throw new HandshakeError('core key not found', { coreId });
  }

  // Stage 4: SEND_SESSIONKEY
  progress.stage = 'SEND_SESSIONKEY';
  const sessionKey = randomBuffer(SESSION_BYTES);
  const sessionCiphertext = await crypto.encrypt(corePubPem, sessionKey);
  const hmac = hmacSha1(sessionCiphertext, sessionKey);
  const signature = await crypto.sign(serverPrivKeyPem, hmac);
  io.write(Buffer.concat([sessionCiphertext, signature]));

  const { key: aesKey, iv: sessionIv } = deriveAesParams(sessionKey);
  // Both directions start from the same IV; each side rolls forward independently.
  const ivInitial = Buffer.from(sessionIv);

  // Stage 5: GET_HELLO — one AES-128-CBC frame from the device.
  progress.stage = 'GET_HELLO';
  const helloFrameIn = await io.readFrame();
  let helloPlain;
  try {
    helloPlain = aesDecrypt(aesKey, ivInitial, helloFrameIn);
  } catch (err) {
    throw new HandshakeError('hello AES decrypt failed', { cause: err.message });
  }
  let helloMsg;
  try {
    helloMsg = coapDecode(helloPlain);
  } catch (err) {
    throw new HandshakeError('hello CoAP parse failed', { cause: err.message });
  }
  const recvCounter = helloMsg.messageId;
  let productId;
  let firmwareVersion;
  if (helloMsg.payload.length >= 4) {
    productId = helloMsg.payload.readUInt16BE(0);
    firmwareVersion = helloMsg.payload.readUInt16BE(2);
  }
  const ivIn = Buffer.from(helloFrameIn.subarray(0, 16));

  // Stage 6: SEND_HELLO
  progress.stage = 'SEND_HELLO';
  const sendCounter = randomBuffer(2).readUInt16BE(0);
  const helloPlainOut = coapEncode({
    type: Type.NON,
    code: Code.POST,
    messageId: sendCounter,
    token: Buffer.alloc(0),
    options: [{ number: Option.UriPath, value: Buffer.from('h') }],
  });
  const helloFrameOut = aesEncrypt(aesKey, ivInitial, helloPlainOut);
  io.writeFrame(helloFrameOut);
  const ivOut = Buffer.from(helloFrameOut.subarray(0, 16));

  progress.stage = 'DONE';
  return {
    coreId,
    sessionKey,
    aesKey,
    ivIn,
    ivOut,
    recvCounter,
    sendCounter,
    productId,
    firmwareVersion,
  };
}
