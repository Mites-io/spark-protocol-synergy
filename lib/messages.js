/**
 * @module gateway/messages
 *
 * Named spark messages — the protocol vocabulary the Photon firmware
 * speaks. Each named message maps to a `(code, type, uri)` tuple that the
 * gateway uses to:
 * 1. Classify decoded inbound CoAP messages by name (`classify` below).
 * 2. Build outbound responses by name (`Messages.Hello`, etc.).
 *
 * Ported verbatim from the legacy
 * `custom-packages/spark-protocol-synergy/lib/Messages.js` `Spec` table.
 * Keep this table in sync with the firmware in
 * `Mites-Firmware/PhotonCore/communication/` — see CLAUDE.md §8 (upstream
 * contract). New messages require a coordinated firmware change.
 */

import { Code, Type, Option } from './coap.js';

/**
 * @typedef {Object} MessageSpec
 * @property {number} code  CoAP code (a `Code` value, e.g. `Code.POST`)
 * @property {number} type  CoAP type (a `Type` value, e.g. `Type.CON`)
 * @property {string} [uri] Single-character Uri-Path the firmware uses
 */

/**
 * The spark message vocabulary: name → `(code, type, uri)` spec. Frozen;
 * `classify()` reads it inbound and `Session.send()` reads it outbound.
 * @type {Record<string, MessageSpec>}
 */
export const Messages = Object.freeze({
  Hello:           { code: Code.POST,  type: Type.NON, uri: 'h' },
  KeyChange:       { code: Code.PUT,   type: Type.CON, uri: 'k' },
  UpdateBegin:     { code: Code.POST,  type: Type.CON, uri: 'u' },
  Chunk:           { code: Code.POST,  type: Type.CON, uri: 'c' },
  UpdateDone:      { code: Code.PUT,   type: Type.CON, uri: 'u' },
  FunctionCall:    { code: Code.POST,  type: Type.CON, uri: 'f' },
  VariableRequest: { code: Code.GET,   type: Type.CON, uri: 'v' },
  PrivateEvent:    { code: Code.POST,  type: Type.NON, uri: 'E' },
  PublicEvent:     { code: Code.POST,  type: Type.NON, uri: 'e' },
  SynergyProtocol: { code: Code.POST,  type: Type.NON, uri: 'm' },
  Attribute:       { code: Code.POST,  type: Type.NON, uri: 'a' },
  Describe:        { code: Code.GET,   type: Type.CON, uri: 'd' },
  GetTime:         { code: Code.GET,   type: Type.CON, uri: 't' },
  RaiseYourHand:   { code: Code.PUT,   type: Type.CON, uri: 's' },
  Ping:            { code: Code.Empty, type: Type.CON },

  // Server-originated responses. These don't carry a Uri-Path; the device
  // pairs them to its outstanding request via the echoed message id and
  // token. `send()` callers must pass the original request's `messageId`
  // and `token` so the device can match.
  GetTimeReturn:   { code: Code.Content, type: Type.ACK },
});

/**
 * Classify a decoded CoAP message as one of the named spark messages.
 *
 * Ping is special — it's an empty CON with no Uri-Path. Everything else
 * is matched on `(code, first Uri-Path segment)`.
 *
 * @param {import('./coap.js').CoapMessage} decoded
 * @returns {string|null} message name, or `null` if unrecognised
 */
export function classify(decoded) {
  if (decoded.code === Code.Empty && decoded.type === Type.CON) return 'Ping';

  const firstUriPath = decoded.options.find((o) => o.number === Option.UriPath);
  if (!firstUriPath) return null;
  const uri = firstUriPath.value.toString('utf8');

  for (const [name, spec] of Object.entries(Messages)) {
    if (spec.uri === uri && spec.code === decoded.code) return name;
  }
  return null;
}
