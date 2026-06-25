/**
 * @module gateway/coap
 *
 * Minimal CoAP wire codec (RFC 7252), large enough to handle the spark
 * protocol and nothing else. No external deps: the legacy stack pulled in
 * `h5.coap` (unmaintained); `node-coap` carries UDP socket assumptions we
 * don't want. The CoAP frame format is small (~150 LOC) and pinning it
 * locally protects us from churn in either upstream (Principle 1).
 *
 * **Supported**:
 * - 4-byte header (Ver=01, Type 2b, TKL 4b, Code 8b, Message-ID 16b BE)
 * - Token (0..8 bytes)
 * - Options (Uri-Path, Uri-Query, Content-Format, Max-Age, ...) with the
 *   standard delta/length nibble encoding and 13/14 extended forms
 * - Payload marker 0xFF + payload bytes
 *
 * **Out of scope**: block-wise transfer, observe, deduplication and
 * retransmit. Those are higher-level concerns handled in `session.js`.
 */

/** CoAP message types. */
export const Type = Object.freeze({ CON: 0, NON: 1, ACK: 2, RST: 3 });

/** CoAP codes (`class.detail` packed as `(class << 5) | detail`). */
export const Code = Object.freeze({
  Empty:   0x00,
  GET:     0x01,
  POST:    0x02,
  PUT:     0x03,
  DELETE:  0x04,

  Created:             0x41,
  Deleted:             0x42,
  Valid:               0x43,
  Changed:             0x44,
  Content:             0x45,

  BadRequest:          0x80,
  Unauthorized:        0x81,
  NotFound:            0x84,
  MethodNotAllowed:    0x85,
  InternalServerError: 0xA0,
});

/** CoAP option numbers — only the ones the spark protocol uses. */
export const Option = Object.freeze({
  UriHost:       3,
  ETag:          4,
  UriPort:       7,
  LocationPath:  8,
  UriPath:      11,
  ContentFormat:12,
  MaxAge:       14,
  UriQuery:     15,
  Accept:       17,
  LocationQuery:20,
});

/**
 * @typedef {Object} CoapOption
 * @property {number} number Option number per RFC 7252 §5.10
 * @property {Buffer} value  Raw option value
 */

/**
 * @typedef {Object} CoapMessage
 * @property {number} type     One of {@link Type}
 * @property {number} code     One of {@link Code}
 * @property {number} messageId 16-bit unsigned, big-endian on the wire
 * @property {Buffer} [token]   0..8 bytes, defaults to empty
 * @property {CoapOption[]} [options]
 * @property {Buffer} [payload]
 */

/**
 * Serialise a {@link CoapMessage} to its wire bytes.
 *
 * @param {CoapMessage} msg
 * @returns {Buffer}
 */
export function encode(msg) {
  const token = msg.token ?? Buffer.alloc(0);
  if (token.length > 8) throw new RangeError('CoAP token max 8 bytes');

  const options = (msg.options ?? []).slice().sort((a, b) => a.number - b.number);

  const header = Buffer.alloc(4);
  header[0] = (0b01 << 6) | ((msg.type & 0x03) << 4) | (token.length & 0x0F);
  header[1] = msg.code & 0xFF;
  header.writeUInt16BE(msg.messageId & 0xFFFF, 2);

  const parts = [header, token];
  let prev = 0;
  for (const opt of options) {
    const delta = opt.number - prev;
    if (delta < 0) throw new RangeError('CoAP options must be in ascending order');
    parts.push(encodeOptionHeader(delta, opt.value.length), opt.value);
    prev = opt.number;
  }

  if (msg.payload && msg.payload.length > 0) {
    parts.push(Buffer.from([0xFF]), msg.payload);
  }
  return Buffer.concat(parts);
}

function encodeOptionHeader(delta, len) {
  const nibble = (v) => (v < 13 ? v : v < 269 ? 13 : 14);
  const dN = nibble(delta);
  const lN = nibble(len);
  const head = [(dN << 4) | lN];
  if (dN === 13) head.push(delta - 13);
  else if (dN === 14) { const b = Buffer.alloc(2); b.writeUInt16BE(delta - 269); head.push(b[0], b[1]); }
  if (lN === 13) head.push(len - 13);
  else if (lN === 14) { const b = Buffer.alloc(2); b.writeUInt16BE(len - 269); head.push(b[0], b[1]); }
  return Buffer.from(head);
}

/**
 * Parse a CoAP message off the wire.
 *
 * @param {Buffer} buf
 * @returns {CoapMessage}
 * @throws {Error} on malformed input
 */
export function decode(buf) {
  if (buf.length < 4) throw new Error('CoAP message too short');
  const version = (buf[0] >> 6) & 0x03;
  if (version !== 1) throw new Error(`CoAP version ${version} unsupported`);
  const type = (buf[0] >> 4) & 0x03;
  const tkl = buf[0] & 0x0F;
  if (tkl > 8) throw new Error(`CoAP token length ${tkl} > 8`);
  const code = buf[1];
  const messageId = buf.readUInt16BE(2);

  let pos = 4;
  if (buf.length < pos + tkl) throw new Error('CoAP token truncated');
  const token = Buffer.from(buf.subarray(pos, pos + tkl));
  pos += tkl;

  const options = [];
  let prev = 0;
  while (pos < buf.length) {
    if (buf[pos] === 0xFF) { pos += 1; break; }
    const head = buf[pos++];
    let delta = (head >> 4) & 0x0F;
    let len = head & 0x0F;
    if (delta === 15 || len === 15) throw new Error('CoAP option uses reserved nibble 15');
    if (delta === 13) delta = 13 + buf[pos++];
    else if (delta === 14) { delta = 269 + buf.readUInt16BE(pos); pos += 2; }
    if (len === 13) len = 13 + buf[pos++];
    else if (len === 14) { len = 269 + buf.readUInt16BE(pos); pos += 2; }
    const number = prev + delta;
    if (pos + len > buf.length) throw new Error('CoAP option value truncated');
    options.push({ number, value: Buffer.from(buf.subarray(pos, pos + len)) });
    pos += len;
    prev = number;
  }

  const payload = pos < buf.length ? Buffer.from(buf.subarray(pos)) : Buffer.alloc(0);
  return { type, code, messageId, token, options, payload };
}

/**
 * Join `Uri-Path` option values into a single slash-separated string.
 * @param {CoapMessage} msg
 * @returns {string}
 */
export function uriPath(msg) {
  return msg.options
    .filter((o) => o.number === Option.UriPath)
    .map((o) => o.value.toString('utf8'))
    .join('/');
}

/**
 * Extract `Uri-Query` option values as a string array.
 * @param {CoapMessage} msg
 * @returns {string[]}
 */
export function uriQuery(msg) {
  return msg.options
    .filter((o) => o.number === Option.UriQuery)
    .map((o) => o.value.toString('utf8'));
}
