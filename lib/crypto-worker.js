/**
 * @module gateway/crypto-worker
 *
 * Worker thread for {@link module:gateway/crypto-pool|CryptoPool}. Receives
 * `{ id, op, keyPem, data, extra? }` messages on `parentPort` and posts back
 * `{ id, result }` or `{ id, error }`.
 *
 * Each worker maintains a small LRU of parsed `KeyObject`s keyed by the PEM
 * string, so a hot device's public key is parsed once per worker lifetime
 * rather than once per handshake. The LRU is bounded to keep memory linear
 * with the active device set (Principle 5).
 */

import { parentPort } from 'node:worker_threads';
import {
  loadPrivateKey,
  loadPublicKey,
  rsaDecrypt,
  rsaEncrypt,
  rsaSign,
  rsaVerify,
} from './crypto.js';

const LRU_MAX = 64;
const pubCache = new Map();
const privCache = new Map();

function lruGet(cache, pem) {
  const hit = cache.get(pem);
  if (hit === undefined) return undefined;
  cache.delete(pem);
  cache.set(pem, hit);
  return hit;
}

function lruSet(cache, pem, obj) {
  cache.set(pem, obj);
  if (cache.size > LRU_MAX) {
    const oldest = cache.keys().next().value;
    cache.delete(oldest);
  }
}

function getPub(pem) {
  let k = lruGet(pubCache, pem);
  if (!k) {
    k = loadPublicKey(pem);
    lruSet(pubCache, pem, k);
  }
  return k;
}

function getPriv(pem) {
  let k = lruGet(privCache, pem);
  if (!k) {
    k = loadPrivateKey(pem);
    lruSet(privCache, pem, k);
  }
  return k;
}

parentPort.on('message', (msg) => {
  try {
    let result;
    switch (msg.op) {
      case 'encrypt':
        result = rsaEncrypt(getPub(msg.keyPem), msg.data);
        break;
      case 'decrypt':
        result = rsaDecrypt(getPriv(msg.keyPem), msg.data);
        break;
      case 'sign':
        result = rsaSign(getPriv(msg.keyPem), msg.data);
        break;
      case 'verify': {
        const ok = rsaVerify(getPub(msg.keyPem), msg.data, msg.extra);
        result = Buffer.from([ok ? 1 : 0]);
        break;
      }
      default:
        throw new Error(`unknown op: ${msg.op}`);
    }
    parentPort.postMessage({ id: msg.id, result });
  } catch (err) {
    parentPort.postMessage({ id: msg.id, error: err.message });
  }
});
