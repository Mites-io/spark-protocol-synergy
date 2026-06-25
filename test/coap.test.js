import { test } from 'node:test';
import assert from 'node:assert/strict';

import { Code, Option, Type, decode, encode, uriPath, uriQuery } from '../lib/coap.js';

test('encode/decode round-trips a minimal CON GET with no options', () => {
  const original = { type: Type.CON, code: Code.GET, messageId: 0x1234, token: Buffer.from([0x42]) };
  const wire = encode(original);
  const parsed = decode(wire);
  assert.equal(parsed.type, Type.CON);
  assert.equal(parsed.code, Code.GET);
  assert.equal(parsed.messageId, 0x1234);
  assert.deepEqual(parsed.token, Buffer.from([0x42]));
  assert.equal(parsed.options.length, 0);
  assert.equal(parsed.payload.length, 0);
});

test('encode/decode round-trips a POST with Uri-Path and payload', () => {
  const original = {
    type: Type.NON,
    code: Code.POST,
    messageId: 0xCAFE,
    token: Buffer.alloc(0),
    options: [
      { number: Option.UriPath, value: Buffer.from('m') },
    ],
    payload: Buffer.from('sensor-blob-here'),
  };
  const parsed = decode(encode(original));
  assert.equal(parsed.code, Code.POST);
  assert.equal(parsed.messageId, 0xCAFE);
  assert.equal(uriPath(parsed), 'm');
  assert.deepEqual(parsed.payload, Buffer.from('sensor-blob-here'));
});

test('encode/decode handles multiple Uri-Path segments', () => {
  const msg = {
    type: Type.CON, code: Code.POST, messageId: 1,
    options: [
      { number: Option.UriPath, value: Buffer.from('f') },
      { number: Option.UriPath, value: Buffer.from('setSpeaker') },
    ],
  };
  const parsed = decode(encode(msg));
  assert.equal(uriPath(parsed), 'f/setSpeaker');
});

test('encode/decode preserves Uri-Query options', () => {
  const msg = {
    type: Type.CON, code: Code.POST, messageId: 2,
    options: [
      { number: Option.UriPath, value: Buffer.from('f') },
      { number: Option.UriQuery, value: Buffer.from('beep=1') },
    ],
  };
  const parsed = decode(encode(msg));
  assert.deepEqual(uriQuery(parsed), ['beep=1']);
});

test('encode/decode handles an extended-length option value (>12 bytes)', () => {
  const long = Buffer.alloc(50, 0xab);
  const msg = {
    type: Type.NON, code: Code.POST, messageId: 3,
    options: [{ number: Option.UriPath, value: long }],
  };
  const parsed = decode(encode(msg));
  assert.deepEqual(parsed.options[0].value, long);
});

test('decode rejects an unsupported CoAP version', () => {
  const buf = Buffer.from([0xC0, 0x01, 0x00, 0x01]);
  assert.throws(() => decode(buf), /version/);
});

test('decode rejects a truncated message', () => {
  assert.throws(() => decode(Buffer.from([0x40, 0x01])), /too short/);
});

test('decode parses a header-only ACK (Ping reply shape)', () => {
  const ack = encode({ type: Type.ACK, code: Code.Empty, messageId: 99, token: Buffer.alloc(0) });
  const parsed = decode(ack);
  assert.equal(parsed.type, Type.ACK);
  assert.equal(parsed.code, Code.Empty);
  assert.equal(parsed.messageId, 99);
});
