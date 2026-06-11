/**
 * @module gateway/session
 *
 * One `Session` per Photon TCP connection. Owns the socket through the
 * full handshake and the post-handshake message loop:
 *
 *   1. `run()` accepts inbound bytes, drives the handshake, then loops
 *      reading length-prefixed AES-128-CBC frames.
 *   2. Each frame is decrypted with the current `ivIn`, CoAP-parsed,
 *      classified by name, and emitted as a `message` event. The
 *      session auto-ACKs CoAP `Ping` so the device's keepalive doesn't
 *      time out (Phase 1.4 — higher-level message handling lives in the
 *      gateway consumer).
 *   3. Outbound messages built via `send()` go through the inverse
 *      pipeline: CoAP-encode → AES encrypt with current `ivOut` →
 *      length-prefix frame → socket write.
 *
 * **Rolling IV invariant** (must hold every frame): after each
 * encrypt/decrypt, `ivIn` / `ivOut` becomes the *first 16 bytes of the
 * ciphertext just processed*. The firmware does this with the explicit
 * `memcpy(iv_send, buf, 16)` after `mbedtls_aes_crypt_cbc` overrides
 * mbedtls's own last-block iv update (see
 * `lightssl_message_channel.cpp:146-150` and `spark_protocol.cpp:395-407`).
 * The legacy `CryptoStream.js` matches that. For a single-block message
 * "first 16" and "last 16" are the same buffer — get this wrong and
 * multi-block frames desync the chain.
 *
 * **Idle disconnect** at 2 minutes of no inbound bytes — matches the
 * legacy slave's behaviour.
 *
 * Events (via `EventEmitter`):
 * - `handshake` — emitted when stage 6 completes; payload is the
 *   handshake result (see {@link runHandshake}).
 * - `message` — every classified inbound message; payload is a
 *   {@link SessionMessage}.
 * - `error` — a protocol-level failure; payload is an `Error`.
 * - `close` — emitted exactly once when the session ends; no payload.
 */

import { EventEmitter } from 'node:events';
import { randomBytes } from 'node:crypto';

import { aesDecrypt, aesEncrypt } from './crypto.js';
import { encodeFrame } from './chunking.js';
import { Code, Option, Type, decode as coapDecode, encode as coapEncode } from './coap.js';
import { Messages as MESSAGE_SPEC, classify } from './messages.js';
import { runHandshake } from './handshake.js';

const IDLE_TIMEOUT_MS = 2 * 60 * 1000;
const DEFAULT_REQUEST_TIMEOUT_MS = 5000;

class ByteQueue {
  constructor() {
    this._buf = Buffer.alloc(0);
    this._waiters = [];
    this._closed = false;
  }
  push(b) {
    this._buf = Buffer.concat([this._buf, b]);
    this._drain();
  }
  close() {
    this._closed = true;
    this._drain();
  }
  _drain() {
    while (this._waiters.length > 0) {
      const w = this._waiters[0];
      if (this._buf.length >= w.want) {
        this._waiters.shift();
        const out = Buffer.from(this._buf.subarray(0, w.want));
        this._buf = Buffer.from(this._buf.subarray(w.want));
        w.resolve(out);
      } else if (this._closed) {
        this._waiters.shift();
        w.reject(new Error('socket closed'));
      } else break;
    }
  }
  read(n) {
    return new Promise((resolve, reject) => {
      this._waiters.push({ want: n, resolve, reject });
      this._drain();
    });
  }
}

/**
 * @typedef {Object} SessionOptions
 * @property {import('node:net').Socket} socket
 * @property {import('./crypto-pool.js').CryptoPool} crypto
 * @property {string} serverPrivKeyPem
 * @property {(coreId: string, inlineDer: Buffer|null) => Promise<string|null>} loadCoreKey
 * @property {number} [idleTimeoutMs] default 120000
 *
 * @typedef {Object} SessionMessage
 *   Payload of the `message` event.
 * @property {string} name  classified spark message name (a `Messages` key)
 * @property {import('./coap.js').CoapMessage} msg  the decoded CoAP message
 */

/**
 * One Photon's connection: owns the TCP socket from accept through the
 * spark handshake and the post-handshake encrypted message loop, and
 * exposes {@link Session#send} (fire-and-forget) and
 * {@link Session#request} (token-correlated request/response). Created by
 * `Gateway` (gateway/server) per inbound connection; registered in the
 * `DeviceRegistry` (registry/memory) on handshake success. See the module header for
 * the rolling-IV invariant this class must maintain every frame.
 */
export class Session extends EventEmitter {
  /** @param {SessionOptions} opts */
  constructor(opts) {
    super();
    this.socket = opts.socket;
    this._crypto = opts.crypto;
    this._serverPriv = opts.serverPrivKeyPem;
    this._loadCoreKey = opts.loadCoreKey;
    this._idleMs = opts.idleTimeoutMs ?? IDLE_TIMEOUT_MS;

    this._queue = new ByteQueue();
    this._state = 'opening';
    this._idleTimer = null;
    /** @type {Map<string, {resolve: (msg: import('./coap.js').CoapMessage) => void, reject: (err: Error) => void, timer: NodeJS.Timeout}>} */
    this._pending = new Map();

    /** @type {string|null} */ this.coreId = null;
    /** @type {Buffer|null} */ this.aesKey = null;
    /** @type {Buffer|null} */ this.ivIn = null;
    /** @type {Buffer|null} */ this.ivOut = null;
    this.recvCounter = 0;
    this.sendCounter = 0;
    this.lastHeard = Date.now();
    this.productId = undefined;
    this.firmwareVersion = undefined;

    this.remoteAddress = this.socket.remoteAddress ?? null;

    this._io = {
      write: (b) => { this.socket.write(b); },
      readBytes: (n) => this._queue.read(n),
      readFrame: async () => {
        // Inbound frames are `[2B len][1B 0xFF sync][len B ciphertext]`,
        // per firmware `SparkProtocol::wrap`. The sync byte is consumed and
        // discarded; the firmware uses it as a self-resync marker, the
        // server only needs to skip past it. See gateway/chunking.js.
        const head = await this._queue.read(3);
        const len = head.readUInt16BE(0);
        return this._queue.read(len);
      },
      writeFrame: (b) => { this.socket.write(encodeFrame(b)); },
    };

    this.socket.on('data', (chunk) => this._onData(chunk));
    this.socket.on('error', (err) => this._onSocketError(err));
    this.socket.on('close', () => this._onSocketClose());
  }

  _onData(chunk) {
    this.lastHeard = Date.now();
    this._resetIdleTimer();
    this._queue.push(chunk);
  }

  _resetIdleTimer() {
    if (this._idleTimer) clearTimeout(this._idleTimer);
    this._idleTimer = setTimeout(() => {
      this.emit('error', new Error('idle timeout'));
      this.disconnect();
    }, this._idleMs);
  }

  _onSocketError(err) {
    this.emit('error', err);
    this.disconnect();
  }

  _onSocketClose() {
    this._finalize();
  }

  _finalize() {
    if (this._state === 'closed') return;
    this._state = 'closed';
    if (this._idleTimer) clearTimeout(this._idleTimer);
    for (const p of this._pending.values()) {
      clearTimeout(p.timer);
      p.reject(new Error('session closed'));
    }
    this._pending.clear();
    this._queue.close();
    this.emit('close');
  }

  /** Drive the handshake, then loop reading frames. Fire-and-forget. */
  async run() {
    this._resetIdleTimer();
    this._handshakeProgress = {};
    try {
      this._state = 'handshaking';
      const result = await runHandshake({
        io: this._io,
        crypto: this._crypto,
        serverPrivKeyPem: this._serverPriv,
        loadCoreKey: this._loadCoreKey,
        progress: this._handshakeProgress,
      });
      Object.assign(this, {
        coreId: result.coreId,
        aesKey: result.aesKey,
        ivIn: result.ivIn,
        ivOut: result.ivOut,
        recvCounter: result.recvCounter,
        sendCounter: result.sendCounter,
        productId: result.productId,
        firmwareVersion: result.firmwareVersion,
        sessionKey: result.sessionKey,
      });
      this._state = 'connected';
      this.emit('handshake', result);

      while (this._state === 'connected') {
        const frame = await this._io.readFrame();
        this._handleFrame(frame);
      }
    } catch (err) {
      this._handshakeError = err;
      if (this._state !== 'closed') {
        this.emit('error', err);
        this.disconnect();
      }
    }
  }

  _handleFrame(ciphertext) {
    let plaintext;
    try {
      plaintext = aesDecrypt(this.aesKey, this.ivIn, ciphertext);
    } catch (err) {
      this.emit('error', new Error(`AES decrypt failed: ${err.message}`));
      this.disconnect();
      return;
    }
    this.ivIn = Buffer.from(ciphertext.subarray(0, 16));

    let msg;
    try {
      msg = coapDecode(plaintext);
    } catch (err) {
      this.emit('error', new Error(`CoAP decode failed: ${err.message}`));
      return;
    }
    this.recvCounter = msg.messageId;
    const name = classify(msg);

    if (name === 'Ping') {
      this._sendPlain(coapEncode({
        type: Type.ACK, code: Code.Empty, messageId: msg.messageId, token: msg.token,
      }));
      return;
    }

    // Correlate to an outstanding `request()` by token. Empty ACKs from
    // the device (e.g. a separate ack-then-payload split) carry an empty
    // token and fall through to the `message` event, where the operator
    // route handler ignores them while waiting for the real payload.
    if (msg.token.length > 0) {
      const key = msg.token.toString('hex');
      const pending = this._pending.get(key);
      if (pending) {
        this._pending.delete(key);
        clearTimeout(pending.timer);
        pending.resolve(msg);
        return;
      }
    }

    this.emit('message', { name, msg });
  }

  /**
   * Send a named message with a fresh random token and resolve when the
   * device echoes that token back on its response. The response is
   * matched purely on token, so it does not need to be in the
   * `Messages` classification table (the spark response types —
   * `FunctionReturn`, `VariableValue`, `RaiseYourHandReturn` — vary in
   * CoAP code/type and do not carry a Uri-Path).
   *
   * @param {string} name request message name (a `Messages` key)
   * @param {{ payload?: Buffer, options?: import('./coap.js').CoapOption[],
   *           timeoutMs?: number }} [opts]
   * @returns {Promise<import('./coap.js').CoapMessage>}
   */
  request(name, opts = {}) {
    if (this._state !== 'connected') {
      return Promise.reject(new Error('session not connected'));
    }
    // Tokens are 1 byte to match the firmware's spark contract — the
    // legacy `SparkCore.getNextToken()` runs a counter modulo 256 and
    // sends a single-byte token, and the firmware's response path
    // echoes back exactly that one byte. Sending a 4-byte token still
    // wraps in a valid CoAP frame, but the device responds with a
    // 1-byte token, so the correlation map never matches and the
    // request times out. Verified against the real Photon (firmware v2)
    // on 2026-05-14.
    const token = randomBytes(1);
    const key = token.toString('hex');
    const timeoutMs = opts.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._pending.delete(key);
        reject(new Error(`device request '${name}' timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      this._pending.set(key, { resolve, reject, timer });
      try {
        this.send(name, { payload: opts.payload, options: opts.options, token });
      } catch (err) {
        this._pending.delete(key);
        clearTimeout(timer);
        reject(err);
      }
    });
  }

  /**
   * Build, encrypt, and send a named outbound message. Returns the
   * message id used.
   *
   * Defaults: new message, `messageId` allocated from `sendCounter`,
   * empty token, type/code from the named spec. Override `messageId` and
   * `token` when sending a *response* — the device pairs replies back to
   * its original request by matching those fields. `type` can also be
   * overridden (e.g. ACK) when the response shape differs from the spec.
   *
   * @param {string} name a `Messages` key (gateway/messages)
   * @param {{ payload?: Buffer, options?: import('./coap.js').CoapOption[],
   *           messageId?: number, token?: Buffer, type?: number }} [opts]
   * @returns {number} the message id sent
   */
  send(name, opts = {}) {
    const spec = MESSAGE_SPEC[name];
    if (!spec) throw new Error(`unknown message: ${name}`);
    let messageId;
    if (opts.messageId === undefined) {
      messageId = this.sendCounter & 0xFFFF;
      this.sendCounter = (this.sendCounter + 1) & 0xFFFF;
    } else {
      messageId = opts.messageId & 0xFFFF;
    }
    const options = [];
    if (spec.uri) options.push({ number: Option.UriPath, value: Buffer.from(spec.uri) });
    if (opts.options) options.push(...opts.options);
    const plain = coapEncode({
      type: opts.type ?? spec.type,
      code: spec.code,
      messageId,
      token: opts.token ?? Buffer.alloc(0),
      options,
      payload: opts.payload,
    });
    this._sendPlain(plain);
    return messageId;
  }

  _sendPlain(plain) {
    const ct = aesEncrypt(this.aesKey, this.ivOut, plain);
    this.ivOut = Buffer.from(ct.subarray(0, 16));
    this.socket.write(encodeFrame(ct));
  }

  /** Close the underlying socket and emit `close` exactly once. */
  disconnect() {
    if (this._state === 'closed') return;
    try { this.socket.end(); } catch { /* socket already gone */ }
    this._finalize();
  }
}

