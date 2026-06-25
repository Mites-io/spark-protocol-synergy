/**
 * @module @mites-io/spark-protocol-synergy
 *
 * Public surface of the Mites spark/CoAP device-gateway library — the TCP
 * handshake and encrypted session layer that a Particle Photon speaks to.
 *
 * A host app wires these together: build a {@link CryptoPool}, give a
 * {@link Gateway} a core-key loader and the server private key, then listen
 * to the gateway's events. The library is deliberately ignorant of metrics,
 * logging, and storage — it emits events and decodes frames; the host
 * decides what those mean. See `Usage.md` for the integration walk-through
 * and `Implementation.md` for the protocol internals.
 */

// TCP listener + per-device session state machine.
export { Gateway } from './lib/server.js';
export { Session } from './lib/session.js';

// RSA worker-thread pool. The host owns its lifecycle (start / stop).
export { CryptoPool } from './lib/crypto-pool.js';

// Convenience filesystem-backed core-key loader. The Gateway takes
// `loadCoreKey` as an injected function, so a host may supply its own
// (database, KMS, …) instead of this one.
export { makeFsCoreKeyLoader } from './lib/core-keys.js';

// CoAP protocol constants — a host needs these to build request frames
// (operator commands, OTA) against the wire format.
export { Code, Option, Type } from './lib/coap.js';
