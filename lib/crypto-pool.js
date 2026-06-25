/**
 * @module gateway/crypto-pool
 *
 * `worker_threads` pool that runs the RSA operations from
 * {@link module:gateway/crypto} off the main event loop.
 *
 * Why this exists: a 500-device cold-start storm sends ~500 handshake
 * decryptions in a few seconds. At ~1 ms each on a single core, that's a
 * 500 ms event-loop stall that delays every other connection's progress.
 * Sharded across N worker threads it parallelises onto N cores and the
 * event loop stays responsive for I/O. AES/HMAC are sub-microsecond and
 * stay on the main thread — moving them to workers would cost more in
 * postMessage than it saves.
 *
 * **Bounded by design** (Principle 5): pool size is fixed at construction
 * (default `os.availableParallelism()`); when all workers are busy, new
 * tasks queue in memory rather than spawning more workers. The queue depth
 * is observable via {@link CryptoPool#stats} for `/metrics`.
 *
 * Keys cross the thread boundary as PEM strings; each worker caches parsed
 * `KeyObject`s in an LRU so hot device keys only pay the parse cost once
 * per worker lifetime.
 */

import { EventEmitter } from 'node:events';
import { availableParallelism } from 'node:os';
import { Worker } from 'node:worker_threads';

const WORKER_URL = new URL('./crypto-worker.js', import.meta.url);

/**
 * @typedef {Object} CryptoPoolStats
 * @property {number} workers Total worker threads in the pool.
 * @property {number} idle Workers currently waiting for a task.
 * @property {number} queued Tasks waiting because every worker is busy.
 * @property {number} inflight Tasks dispatched but not yet responded.
 */

/**
 * Bounded worker_threads pool exposing parallel RSA encrypt / decrypt /
 * sign / verify. All operations are Promise-returning.
 *
 * Emits an `error` event (from `EventEmitter`) if a worker thread itself
 * errors; per-task failures reject the returned Promise instead.
 */
export class CryptoPool extends EventEmitter {
  /**
   * @param {{ size?: number }} [opts]
   *   `size`: number of worker threads. Defaults to
   *   `os.availableParallelism()`. Phase 4 load testing decides whether to
   *   oversubscribe (RSA is CPU-bound with nothing else competing).
   */
  constructor(opts = {}) {
    super();
    const size = opts.size ?? availableParallelism();
    /** @type {Worker[]} */
    this._workers = [];
    /** @type {Worker[]} */
    this._idle = [];
    /** @type {{ message: object }[]} */
    this._queue = [];
    this._nextId = 1;
    /** @type {Map<number, { resolve: (b: Buffer) => void, reject: (e: Error) => void }>} */
    this._pending = new Map();
    this._closed = false;
    for (let i = 0; i < size; i++) this._spawn();
  }

  _spawn() {
    const w = new Worker(WORKER_URL);
    w.on('message', (msg) => this._onMessage(w, msg));
    w.on('error', (err) => this.emit('error', err));
    this._workers.push(w);
    this._idle.push(w);
  }

  _onMessage(worker, msg) {
    const pending = this._pending.get(msg.id);
    if (!pending) return;
    this._pending.delete(msg.id);
    if (msg.error) pending.reject(new Error(msg.error));
    else pending.resolve(Buffer.from(msg.result.buffer, msg.result.byteOffset, msg.result.byteLength));
    this._release(worker);
  }

  _release(worker) {
    const next = this._queue.shift();
    if (next) worker.postMessage(next.message);
    else this._idle.push(worker);
  }

  _dispatch(message) {
    return new Promise((resolve, reject) => {
      if (this._closed) {
        reject(new Error('CryptoPool is closed'));
        return;
      }
      const id = this._nextId++;
      message.id = id;
      this._pending.set(id, { resolve, reject });
      const worker = this._idle.pop();
      if (worker) worker.postMessage(message);
      else this._queue.push({ message });
    });
  }

  /**
   * RSA-PKCS#1v1.5 encrypt with a public key.
   * @param {string} publicKeyPem
   * @param {Buffer|Uint8Array} plaintext
   * @returns {Promise<Buffer>}
   */
  encrypt(publicKeyPem, plaintext) {
    return this._dispatch({ op: 'encrypt', keyPem: publicKeyPem, data: plaintext });
  }

  /**
   * RSA-PKCS#1v1.5 decrypt with a private key.
   * @param {string} privateKeyPem
   * @param {Buffer|Uint8Array} ciphertext
   * @returns {Promise<Buffer>}
   */
  decrypt(privateKeyPem, ciphertext) {
    return this._dispatch({ op: 'decrypt', keyPem: privateKeyPem, data: ciphertext });
  }

  /**
   * Raw RSA sign (privateEncrypt of the hash) — see `rsaSign` in
   * gateway/crypto for the wire contract.
   * @param {string} privateKeyPem
   * @param {Buffer|Uint8Array} hash
   * @returns {Promise<Buffer>}
   */
  sign(privateKeyPem, hash) {
    return this._dispatch({ op: 'sign', keyPem: privateKeyPem, data: hash });
  }

  /**
   * Verify a raw RSA signature against an expected hash.
   * @param {string} publicKeyPem
   * @param {Buffer|Uint8Array} hash
   * @param {Buffer|Uint8Array} signature
   * @returns {Promise<boolean>}
   */
  async verify(publicKeyPem, hash, signature) {
    const result = await this._dispatch({
      op: 'verify',
      keyPem: publicKeyPem,
      data: hash,
      extra: signature,
    });
    return result.length === 1 && result[0] === 1;
  }

  /**
   * Snapshot of pool occupancy for `/metrics`.
   * @returns {CryptoPoolStats}
   */
  stats() {
    return {
      workers: this._workers.length,
      idle: this._idle.length,
      queued: this._queue.length,
      inflight: this._pending.size,
    };
  }

  /**
   * Terminate every worker. Pending tasks reject with "CryptoPool closed".
   * @returns {Promise<void>}
   */
  async close() {
    if (this._closed) return;
    this._closed = true;
    const workers = this._workers.splice(0);
    this._idle.length = 0;
    this._queue.length = 0;
    await Promise.all(workers.map((w) => w.terminate()));
    for (const { reject } of this._pending.values()) reject(new Error('CryptoPool closed'));
    this._pending.clear();
  }
}
