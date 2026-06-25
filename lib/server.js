/**
 * @module gateway/server
 *
 * TCP listener for Photon connections. Accepts on the configured port,
 * spawns a {@link Session} per connection, and on successful handshake
 * registers it with the `DeviceRegistry`. Disconnects unregister.
 *
 * The server is intentionally thin — most of the per-device intelligence
 * lives in `Session`. The handshake itself runs on the main event loop;
 * its RSA operations dispatch to the worker_threads pool so a reconnect
 * storm of 500 devices doesn't stall the accept loop (Phase 4 will
 * stress-test this).
 *
 * Events (via `EventEmitter`):
 * - `listening` — listener bound; payload is the `AddressInfo`.
 * - `connection` — raw socket accepted, before handshake; payload
 *   `{ remote, socket }`.
 * - `session` — handshake succeeded; emitted as `(session, { durationMs })`
 *   where `session` is the {@link Session} and `durationMs` is how long the
 *   handshake took. The second arg lets a host record timing without the
 *   gateway knowing what a metric is.
 * - `handshake_failed` — handshake threw (useful for log/metrics); payload
 *   `{ remote, coreId, stage, result, durationMs, error }`, where `result`
 *   is the classified failure reason and `durationMs` is the elapsed time.
 * - `session_disconnected` — a registered session closed; payload
 *   `{ coreId, reason, durationMs }`. Lets ops see fleet-wide drops
 *   grouped by `reason` without scraping per-device close lines.
 * - `error` — listener error after bind; payload is an `Error`.
 */

import { EventEmitter } from 'node:events';
import { createServer } from 'node:net';

import { Session } from './session.js';

/**
 * @typedef {Object} GatewayOptions
 * @property {number} port
 * @property {string} [host] Default `0.0.0.0`
 * @property {import('./crypto-pool.js').CryptoPool} crypto
 * @property {string} serverPrivKeyPem
 * @property {(coreId: string, inlineDer: Buffer|null) => Promise<string|null>} loadCoreKey
 * @property {import('../registry/memory.js').DeviceRegistry} registry
 */

/**
 * The device-facing TCP listener. `start()` binds the port and resolves
 * with the bound address; each accepted socket gets a {@link Session}
 * that drives the handshake. On success the session is registered in the
 * `DeviceRegistry`; on close it is unregistered. `stop()` disconnects
 * every live session and closes the listener. Intentionally thin — the
 * per-device protocol logic lives in `Session`.
 */
export class Gateway extends EventEmitter {
  /** @param {GatewayOptions} opts */
  constructor(opts) {
    super();
    this._opts = opts;
    /** @type {import('node:net').Server|null} */
    this._server = null;
    /** @type {Set<Session>} */
    this._sessions = new Set();
  }

  /**
   * Start listening. Resolves with the bound address once `listen()`
   * fires; rejects if the bind fails (port in use, etc.).
   *
   * @returns {Promise<import('node:net').AddressInfo>}
   */
  start() {
    return new Promise((resolve, reject) => {
      this._server = createServer((socket) => this._onConnection(socket));
      this._server.once('error', reject);
      this._server.listen(this._opts.port, this._opts.host ?? '0.0.0.0', () => {
        this._server.off('error', reject);
        const addr = this._server.address();
        this._server.on('error', (err) => this.emit('error', err));
        this.emit('listening', addr);
        resolve(addr);
      });
    });
  }

  _onConnection(socket) {
    socket.setNoDelay(true);
    const remote = `${socket.remoteAddress}:${socket.remotePort}`;
    this.emit('connection', { remote, socket });

    const session = new Session({
      socket,
      crypto: this._opts.crypto,
      serverPrivKeyPem: this._opts.serverPrivKeyPem,
      loadCoreKey: this._opts.loadCoreKey,
    });
    this._sessions.add(session);

    let handshakeSucceeded = false;
    const handshakeStartedAt = process.hrtime.bigint();

    session.on('error', () => { /* captured on session._handshakeError */ });
    session.once('handshake', () => {
      handshakeSucceeded = true;
      const durationMs = Math.round(Number(process.hrtime.bigint() - handshakeStartedAt) / 1e6);
      this._opts.registry.register(session);
      this.emit('session', session, { durationMs });
    });
    session.once('close', () => {
      this._sessions.delete(session);
      const wasRegistered = !!session.coreId && handshakeSucceeded;
      if (session.coreId) this._opts.registry.unregister(session.coreId);
      const durationMs = Math.round(Number(process.hrtime.bigint() - handshakeStartedAt) / 1e6);
      if (!handshakeSucceeded) {
        const stage = session._handshakeProgress?.stage ?? 'unknown';
        const result = handshakeFailureReason(session._handshakeError, stage);
        this.emit('handshake_failed', {
          remote,
          coreId: session._handshakeProgress?.coreId ?? null,
          stage,
          result,
          durationMs,
          error: session._handshakeError ?? null,
        });
      } else if (wasRegistered) {
        const reason = disconnectReason(session._handshakeError);
        this.emit('session_disconnected', { coreId: session.coreId, reason, durationMs });
      }
    });

    session.run().catch(() => { /* error already captured on session */ });
  }

  /**
   * Stop accepting new connections and disconnect every in-flight
   * session. Resolves once the listener has closed.
   *
   * @returns {Promise<void>}
   */
  stop() {
    return new Promise((resolve) => {
      if (!this._server) return resolve();
      for (const s of this._sessions) s.disconnect();
      this._sessions.clear();
      this._server.close(() => resolve());
    });
  }

  /** @returns {import('node:net').AddressInfo|null} */
  address() {
    return this._server ? this._server.address() : null;
  }

  /** Active session count (handshaked + still handshaking). */
  get sessionCount() {
    return this._sessions.size;
  }
}

function handshakeFailureReason(err, stage) {
  if (!err) return stage === 'unknown' ? 'socket_closed' : 'aborted';
  const m = err.message ?? '';
  if (m.includes('RSA decrypt')) return 'rsa_fail';
  if (m.includes('nonce mismatch')) return 'nonce_mismatch';
  if (m.includes('AES decrypt')) return 'aes_hello_fail';
  if (m.includes('CoAP parse')) return 'hello_parse_fail';
  if (m.includes('core key not found')) return 'missing_core_key';
  if (m === 'idle timeout') return 'timeout';
  return 'error';
}

function disconnectReason(err) {
  if (!err) return 'peer_close';
  const m = err.message ?? '';
  if (m === 'idle timeout') return 'idle';
  if (m.includes('AES decrypt')) return 'aes_fail';
  return 'error';
}
