/**
 * End-to-end handshake test. A virtual device is built from an RSA-1024
 * keypair generated on the fly; the server side is the real
 * `runHandshake`. The two sides exchange bytes through an in-memory
 * Duplex-like pair. Verifies the full 6-stage flow finishes cleanly and
 * the resulting session state is sane.
 */

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  constants,
  createHmac,
  generateKeyPairSync,
  privateDecrypt,
  publicDecrypt,
  publicEncrypt,
} from 'node:crypto';

import { CryptoPool } from '../lib/crypto-pool.js';
import { aesDecrypt, aesEncrypt } from '../lib/crypto.js';
import { Code, Option, Type, decode as coapDecode, encode as coapEncode } from '../lib/coap.js';
import { runHandshake, HandshakeError } from '../lib/handshake.js';
import { makeFsCoreKeyLoader } from '../lib/core-keys.js';

const here = dirname(fileURLToPath(import.meta.url));
const KEY_DIR = resolve(here, 'fixtures', 'srv_keys');
const serverPrivPem = readFileSync(join(KEY_DIR, 'default_key.pem'), 'utf8');
const serverPubPem = readFileSync(join(KEY_DIR, 'default_key.pub.pem'), 'utf8');

const RSA_PKCS1 = constants.RSA_PKCS1_PADDING;

class ByteQueue {
  constructor() {
    this._buf = Buffer.alloc(0);
    this._waiters = [];
  }
  push(b) {
    this._buf = Buffer.concat([this._buf, b]);
    this._drain();
  }
  _drain() {
    while (this._waiters.length > 0 && this._buf.length >= this._waiters[0].want) {
      const w = this._waiters.shift();
      const out = Buffer.from(this._buf.subarray(0, w.want));
      this._buf = Buffer.from(this._buf.subarray(w.want));
      w.resolve(out);
    }
  }
  read(n) {
    return new Promise((resolve) => {
      this._waiters.push({ want: n, resolve });
      this._drain();
    });
  }
}

function ioPair() {
  const aToB = new ByteQueue();
  const bToA = new ByteQueue();
  // Asymmetric framing — matches the production firmware contract:
  //   device -> server frames: [len_hi][len_lo][0xFF sync][payload]
  //   server -> device frames: [len_hi][len_lo][payload]
  // See gateway/chunking.js.
  const server = {
    write: (b) => bToA.push(b),
    readBytes: (n) => aToB.read(n),
    readFrame: async () => {
      const head = await aToB.read(3);
      const len = head.readUInt16BE(0);
      return await aToB.read(len);
    },
    writeFrame: (b) => {
      const head = Buffer.alloc(2);
      head.writeUInt16BE(b.length, 0);
      bToA.push(head);
      bToA.push(b);
    },
  };
  const device = {
    write: (b) => aToB.push(b),
    readBytes: (n) => bToA.read(n),
    readFrame: async () => {
      const head = await bToA.read(2);
      const len = head.readUInt16BE(0);
      return await bToA.read(len);
    },
    writeFrame: (b) => {
      const head = Buffer.alloc(3);
      head.writeUInt16BE(b.length, 0);
      head[2] = 0xFF;
      aToB.push(head);
      aToB.push(b);
    },
  };
  return { server, device };
}

async function simulateDevice({ io, coreIdHex, devicePrivPem }) {
  // Stage 1 in: 40-byte nonce.
  const nonce = await io.readBytes(40);

  // Stage 2 out: RSA-encrypt [nonce ‖ coreId] with server pub.
  const idBuf = Buffer.from(coreIdHex, 'hex');
  const plain = Buffer.concat([nonce, idBuf]);
  io.write(publicEncrypt({ key: serverPubPem, padding: RSA_PKCS1 }, plain));

  // Stage 4 in: 384 bytes = 128 (RSA-1024 ciphertext) + 256 (RSA-2048 signature).
  const sessBlob = await io.readBytes(384);
  const sessCt = sessBlob.subarray(0, 128);
  const signature = sessBlob.subarray(128, 384);
  const sessionKey = privateDecrypt({ key: devicePrivPem, padding: RSA_PKCS1 }, sessCt);
  const expectedHmac = createHmac('sha1', sessionKey).update(sessCt).digest();
  const recoveredHmac = publicDecrypt({ key: serverPubPem, padding: RSA_PKCS1 }, signature);
  if (!expectedHmac.equals(recoveredHmac)) throw new Error('virtual device: HMAC mismatch');

  // Stage 5 out: AES-encrypted Hello with messageId we'll verify on the server side.
  const aesKey = sessionKey.subarray(0, 16);
  const aesIv = Buffer.from(sessionKey.subarray(16, 32));
  const helloMessageId = 0xABCD;
  const helloPlain = coapEncode({
    type: Type.NON,
    code: Code.POST,
    messageId: helloMessageId,
    token: Buffer.alloc(0),
    options: [{ number: Option.UriPath, value: Buffer.from('h') }],
    payload: Buffer.from([0x00, 0x05, 0x00, 0x03]),
  });
  const helloCt = aesEncrypt(aesKey, aesIv, helloPlain);
  io.writeFrame(helloCt);

  // Stage 6 in: server Hello back.
  const serverHelloFrame = await io.readFrame();
  const serverHelloPlain = aesDecrypt(aesKey, aesIv, serverHelloFrame);
  const serverHello = coapDecode(serverHelloPlain);

  return { sessionKey, helloMessageId, serverHello };
}

function generateDeviceKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
  return {
    pub: publicKey.export({ type: 'spki', format: 'pem' }),
    priv: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

const pool = new CryptoPool({ size: 2 });
after(() => pool.close());

test('runHandshake completes against a virtual device', async () => {
  const coreId = '36001f000247343337373738';
  const { pub: devicePubPem, priv: devicePrivPem } = generateDeviceKeypair();
  const loadCoreKey = async (id) => (id === coreId ? devicePubPem : null);
  const { server, device } = ioPair();

  const serverPromise = runHandshake({ io: server, crypto: pool, serverPrivKeyPem: serverPrivPem, loadCoreKey });
  const devicePromise = simulateDevice({ io: device, coreIdHex: coreId, devicePrivPem });

  const [serverResult, deviceResult] = await Promise.all([serverPromise, devicePromise]);

  assert.equal(serverResult.coreId, coreId);
  assert.equal(serverResult.recvCounter, 0xABCD);
  assert.equal(serverResult.productId, 5);
  assert.equal(serverResult.firmwareVersion, 3);
  assert.equal(serverResult.sessionKey.length, 40);
  assert.equal(serverResult.aesKey.length, 16);
  assert.equal(serverResult.ivIn.length, 16);
  assert.equal(serverResult.ivOut.length, 16);
  assert.deepEqual(Buffer.from(serverResult.sessionKey), deviceResult.sessionKey);
  assert.equal(deviceResult.serverHello.code, Code.POST);
});

test('runHandshake rejects when the device sends a wrong nonce', async () => {
  const coreId = '36001f000247343337343337';
  const { pub: devicePubPem } = generateDeviceKeypair();
  const loadCoreKey = async () => devicePubPem;
  const { server, device } = ioPair();

  const serverPromise = runHandshake({ io: server, crypto: pool, serverPrivKeyPem: serverPrivPem, loadCoreKey });
  // Device-side: consume the nonce but reply with garbage.
  (async () => {
    await device.readBytes(40);
    const idBuf = Buffer.from(coreId, 'hex');
    const wrongNonce = Buffer.alloc(40, 0xAA);
    const garbage = Buffer.concat([wrongNonce, idBuf]);
    device.write(publicEncrypt({ key: serverPubPem, padding: RSA_PKCS1 }, garbage));
  })();

  await assert.rejects(serverPromise, (err) => err instanceof HandshakeError && /nonce/.test(err.message));
});

test('runHandshake fails closed when the core key is unknown', async () => {
  const coreId = '36001f000247000000000001';
  const { pub: devicePubPem, priv: devicePrivPem } = generateDeviceKeypair();
  const loadCoreKey = async () => null;
  const { server, device } = ioPair();

  const serverPromise = runHandshake({ io: server, crypto: pool, serverPrivKeyPem: serverPrivPem, loadCoreKey });
  (async () => {
    const nonce = await device.readBytes(40);
    const plain = Buffer.concat([nonce, Buffer.from(coreId, 'hex')]);
    device.write(publicEncrypt({ key: serverPubPem, padding: RSA_PKCS1 }, plain));
  })().catch(() => {});

  await assert.rejects(serverPromise, (err) => err instanceof HandshakeError && /core key not found/.test(err.message));
  // Mark devicePrivPem as referenced for the linter; not used after failure.
  assert.ok(devicePrivPem);
});

test('makeFsCoreKeyLoader quarantines an inline pubkey when canonical is missing', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'mites-keys-'));
  try {
    const loader = makeFsCoreKeyLoader(tmp);
    const coreId = '36001f000247000000000002';
    const { pub: devicePubPem } = generateDeviceKeypair();
    // Build a DER blob from the PEM so we can pass it as "inline".
    const der = Buffer.from(
      devicePubPem.replace(/-----.*?-----/g, '').replace(/\s+/g, ''),
      'base64',
    );

    const first = await loader(coreId, der);
    assert.equal(first, null, 'no canonical key yet → fail closed');

    const quarantine = join(tmp, `${coreId}_handshake.pub.pem`);
    const quarantined = readFileSync(quarantine, 'utf8');
    assert.match(quarantined, /BEGIN PUBLIC KEY/);

    // Operator promotes the key.
    writeFileSync(join(tmp, `${coreId}.pub.pem`), quarantined);
    const second = await loader(coreId, null);
    assert.equal(second, quarantined);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test('makeFsCoreKeyLoader rejects invalid device ids', async () => {
  const loader = makeFsCoreKeyLoader('/tmp');
  await assert.rejects(loader('NOT-HEX', null), /invalid device id/);
  await assert.rejects(loader('36001f', null), /invalid device id/);
});
