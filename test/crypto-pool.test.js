import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

import { CryptoPool } from '../lib/crypto-pool.js';

const here = dirname(fileURLToPath(import.meta.url));
const KEY_DIR = resolve(here, 'fixtures', 'srv_keys');
const privPem = readFileSync(resolve(KEY_DIR, 'default_key.pem'), 'utf8');
const pubPem = readFileSync(resolve(KEY_DIR, 'default_key.pub.pem'), 'utf8');

const pool = new CryptoPool({ size: 2 });
after(() => pool.close());

test('CryptoPool round-trips a 40-byte handshake nonce', async () => {
  const nonce = Buffer.from('0123456789abcdef0123456789abcdef01234567');
  const ciphertext = await pool.encrypt(pubPem, nonce);
  assert.equal(ciphertext.length, 256);
  const recovered = await pool.decrypt(privPem, ciphertext);
  assert.deepEqual(Buffer.from(recovered), nonce);
});

test('CryptoPool sign/verify round-trips a 20-byte hash', async () => {
  const hash = Buffer.from('the-quick-brown-fox.');
  const sig = await pool.sign(privPem, hash);
  assert.equal(await pool.verify(pubPem, hash, sig), true);
});

test('CryptoPool handles concurrent ops beyond worker count', async () => {
  const tasks = Array.from({ length: 8 }, async () => {
    const nonce = Buffer.alloc(40);
    for (let i = 0; i < 40; i++) nonce[i] = Math.floor(Math.random() * 256);
    const ct = await pool.encrypt(pubPem, nonce);
    const pt = await pool.decrypt(privPem, ct);
    assert.deepEqual(Buffer.from(pt), nonce);
  });
  await Promise.all(tasks);
});

test('CryptoPool.stats() reflects configured size', () => {
  const s = pool.stats();
  assert.equal(s.workers, 2);
  assert.equal(s.idle + s.inflight, 2);
});

test('CryptoPool.close() rejects pending tasks', async () => {
  const p2 = new CryptoPool({ size: 1 });
  const nonce = Buffer.alloc(40);
  const pending = p2.encrypt(pubPem, nonce);
  await p2.close();
  await assert.rejects(pending, /CryptoPool closed|Worker is terminat/);
});
