import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import {
  aesDecrypt,
  aesEncrypt,
  deriveAesParams,
  hmacSha1,
  loadPrivateKey,
  loadPublicKey,
  randomBuffer,
  rsaDecrypt,
  rsaEncrypt,
  rsaSign,
  rsaVerify,
} from '../lib/crypto.js';

const here = dirname(fileURLToPath(import.meta.url));
const KEY_DIR = resolve(here, 'fixtures', 'srv_keys');

const privPem = readFileSync(resolve(KEY_DIR, 'default_key.pem'));
const pubPem = readFileSync(resolve(KEY_DIR, 'default_key.pub.pem'));
const pubDer = readFileSync(resolve(KEY_DIR, 'default_key.pub.der'));

const priv = loadPrivateKey(privPem);
const pub = loadPublicKey(pubPem);
const pubFromDer = loadPublicKey(pubDer);

test('RSA PKCS#1 v1.5 round-trips a 40-byte handshake nonce', () => {
  const nonce = randomBuffer(40);
  const ciphertext = rsaEncrypt(pub, nonce);
  assert.equal(ciphertext.length, 256, 'RSA-2048 ciphertext is 256 bytes');
  const recovered = rsaDecrypt(priv, ciphertext);
  assert.deepEqual(recovered, nonce);
});

test('public key loads identically from PEM and DER', () => {
  const nonce = randomBuffer(40);
  const recovered = rsaDecrypt(priv, rsaEncrypt(pubFromDer, nonce));
  assert.deepEqual(recovered, nonce);
});

test('RSA sign / verify round-trips a 20-byte SHA-1 hash', () => {
  const hash = randomBuffer(20);
  const signature = rsaSign(priv, hash);
  assert.equal(rsaVerify(pub, hash, signature), true);
});

test('RSA verify rejects a tampered signature', () => {
  const hash = randomBuffer(20);
  const signature = rsaSign(priv, hash);
  signature[0] ^= 0xff;
  assert.equal(rsaVerify(pub, hash, signature), false);
});

test('RSA verify rejects a hash with the wrong length', () => {
  const hash = randomBuffer(20);
  const signature = rsaSign(priv, hash);
  assert.equal(rsaVerify(pub, randomBuffer(16), signature), false);
});

test('AES-128-CBC round-trips a 40-byte session-material plaintext', () => {
  const sessionKey = randomBuffer(40);
  const { key, iv } = deriveAesParams(sessionKey);
  assert.equal(key.length, 16);
  assert.equal(iv.length, 16);
  const plaintext = randomBuffer(40);
  const ciphertext = aesEncrypt(key, iv, plaintext);
  const recovered = aesDecrypt(key, iv, ciphertext);
  assert.deepEqual(recovered, plaintext);
});

test('deriveAesParams rejects under-length session keys', () => {
  assert.throws(() => deriveAesParams(Buffer.alloc(31)), /too short/);
});

test('HMAC-SHA1 is deterministic and 20 bytes', () => {
  const key = randomBuffer(40);
  const ciphertext = Buffer.from('the quick brown fox');
  const d1 = hmacSha1(ciphertext, key);
  const d2 = hmacSha1(ciphertext, key);
  assert.equal(d1.length, 20);
  assert.deepEqual(d1, d2);
});
