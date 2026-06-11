import { test } from 'node:test';
import assert from 'node:assert/strict';

import { encodeDeviceFrame, encodeFrame, FrameReader } from '../lib/chunking.js';

test('encodeFrame prepends a 2-byte big-endian length (server -> device, no sync)', () => {
  const payload = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  const framed = encodeFrame(payload);
  assert.equal(framed.length, 6);
  assert.equal(framed.readUInt16BE(0), 4);
  assert.deepEqual(framed.subarray(2), payload);
});

test('encodeDeviceFrame inserts a 0xFF sync byte after the length (device -> server)', () => {
  const payload = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
  const framed = encodeDeviceFrame(payload);
  assert.equal(framed.length, 7);
  assert.equal(framed.readUInt16BE(0), 4);
  assert.equal(framed[2], 0xFF);
  assert.deepEqual(framed.subarray(3), payload);
});

test('FrameReader emits a single complete frame', () => {
  const reader = new FrameReader();
  const payload = Buffer.from('hello world');
  const frames = reader.feed(encodeDeviceFrame(payload));
  assert.equal(frames.length, 1);
  assert.deepEqual(frames[0], payload);
});

test('FrameReader splits a buffer carrying multiple frames', () => {
  const reader = new FrameReader();
  const a = Buffer.from('first');
  const b = Buffer.from('second');
  const chunk = Buffer.concat([encodeDeviceFrame(a), encodeDeviceFrame(b)]);
  const frames = reader.feed(chunk);
  assert.equal(frames.length, 2);
  assert.deepEqual(frames[0], a);
  assert.deepEqual(frames[1], b);
});

test('FrameReader stitches a frame across multiple feeds', () => {
  const reader = new FrameReader();
  const payload = Buffer.from('split-across-tcp-packets');
  const framed = encodeDeviceFrame(payload);
  assert.deepEqual(reader.feed(framed.subarray(0, 1)), []);
  assert.deepEqual(reader.feed(framed.subarray(1, 5)), []);
  const tail = reader.feed(framed.subarray(5));
  assert.equal(tail.length, 1);
  assert.deepEqual(tail[0], payload);
});

test('FrameReader holds back a partial header', () => {
  const reader = new FrameReader();
  assert.deepEqual(reader.feed(Buffer.from([0x00])), []);
  const second = reader.feed(Buffer.concat([Buffer.from([0x03, 0xFF]), Buffer.from('abc')]));
  assert.equal(second.length, 1);
  assert.deepEqual(second[0], Buffer.from('abc'));
});

test('encodeFrame rejects payloads larger than 65535 bytes', () => {
  const oversized = Buffer.alloc(65536);
  assert.throws(() => encodeFrame(oversized), /16-bit length prefix/);
});
