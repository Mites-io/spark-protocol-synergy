/**
 * @module gateway/chunking
 *
 * Length-prefixed TCP framing for the spark protocol. The two directions
 * are **asymmetric** — the firmware's `SparkProtocol::wrap`
 * (`Mites-Firmware/PhotonCore/communication/src/spark_protocol.cpp:1108`)
 * emits a 3-byte header on every outbound message, but its receive path
 * reads the body unconditionally with `blocking_receive(queue, len)` and
 * never validates a sync byte. The legacy `ChunkingStream` matched that
 * shape, and we do too:
 *
 *     device → server:  [length_hi][length_lo][0xFF sync][...len bytes]
 *     server → device:  [length_hi][length_lo][...len bytes]
 *
 * The 0xFF sync byte exists to let the device's *own* receive logic resync
 * a stream that started mid-frame — but the firmware's spark-protocol
 * receive doesn't actually use it; only the JS chunker did. We still emit
 * device-side test frames with it via {@link encodeDeviceFrame} so the
 * synthetic-device tests exercise the same byte shape as a real Photon.
 *
 * Both functions allocate new buffers for emitted frames so the underlying
 * pooled TCP buffers can be GC'd promptly.
 */

const SYNC_BYTE = 0xFF;

/**
 * Wrap `payload` in a 2-byte big-endian length prefix. Used for
 * server-to-device sends (no sync byte — firmware receive ignores it).
 *
 * @param {Buffer} payload
 * @returns {Buffer}
 * @throws {RangeError} if `payload` exceeds the 16-bit length prefix (65535 bytes).
 */
export function encodeFrame(payload) {
  if (payload.length > 0xFFFF) {
    throw new RangeError(`payload ${payload.length} bytes exceeds 16-bit length prefix`);
  }
  const out = Buffer.allocUnsafe(2 + payload.length);
  out.writeUInt16BE(payload.length, 0);
  payload.copy(out, 2);
  return out;
}

/**
 * Encode a frame in the device-side ("inbound to server") wire shape:
 * `[len_hi][len_lo][0xFF][payload]`. Used only by tests that simulate
 * a Photon so the synthetic frames exercise the real wire format.
 *
 * @param {Buffer} payload
 * @returns {Buffer}
 * @throws {RangeError} if `payload` exceeds the 16-bit length prefix (65535 bytes).
 */
export function encodeDeviceFrame(payload) {
  if (payload.length > 0xFFFF) {
    throw new RangeError(`payload ${payload.length} bytes exceeds 16-bit length prefix`);
  }
  const out = Buffer.allocUnsafe(3 + payload.length);
  out.writeUInt16BE(payload.length, 0);
  out[2] = SYNC_BYTE;
  payload.copy(out, 3);
  return out;
}

/**
 * Stateful framer that consumes arbitrary TCP byte chunks and emits whole
 * device-side payloads. Skips the 1-byte 0xFF sync header after the
 * length. Survives partial frames across multiple `feed()` calls.
 */
export class FrameReader {
  constructor() {
    /** @type {Buffer} */
    this._buf = Buffer.alloc(0);
  }

  /**
   * Append `chunk` to the internal buffer and return any complete payloads.
   *
   * @param {Buffer} chunk
   * @returns {Buffer[]}
   */
  feed(chunk) {
    this._buf = this._buf.length === 0 ? chunk : Buffer.concat([this._buf, chunk]);
    const frames = [];
    while (this._buf.length >= 3) {
      const len = this._buf.readUInt16BE(0);
      if (this._buf.length < 3 + len) break;
      frames.push(Buffer.from(this._buf.subarray(3, 3 + len)));
      this._buf = Buffer.from(this._buf.subarray(3 + len));
    }
    return frames;
  }
}
