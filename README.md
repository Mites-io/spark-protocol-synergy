# @mites-io/spark-protocol-synergy

A TCP gateway library that speaks the Particle **Photon** "spark" protocol: it runs the device handshake (RSA to agree a key, then an AES-128-CBC encrypted session) and hands you decoded CoAP messages over plain Node `EventEmitter`s. It is the connection layer between a fleet of Photon sensor boards and whatever backend stores their data.

This is a rewrite of https://github.com/particle-iot/spark-protocol that uses modern Node builtins such as crypto, net, worker_threads, events to interact with the devices without requiring native dependencies.

## Status and scope

This is published primarily as the device-gateway layer for the Mites backend. It is a focused library, not a framework — it does the handshake and the encrypted session, emits events, and stops there. It does **not** decode any particular sensor payload, talk to any database, or expose any metrics; those are the host application's job, wired off the events this library emits. External use is welcome but unsupported: treat the published versions as a moving target gated by semver.

## License

LGPL-3.0

## Install

```bash
npm install @mites-io/spark-protocol-synergy
```

Requires Node ≥ 22.

## Wire it up

```js
import { CryptoPool, makeFsCoreKeyLoader, Gateway } from '@mites-io/spark-protocol-synergy';
import { readFileSync } from 'node:fs';

const crypto = new CryptoPool();                                  // RSA worker pool, sized to the CPU count
const serverPrivKeyPem = readFileSync('keys/srv_keys/default_key.pem', 'utf8');
const loadCoreKey = makeFsCoreKeyLoader('keys/core_keys');         // per-device public keys on disk

const gateway = new Gateway({
  port: 5683,
  crypto,
  serverPrivKeyPem,
  loadCoreKey,
  registry: myRegistry,        // any object with register(session) / unregister(coreId)
});

gateway.on('session', (session, { durationMs }) => {
  console.log('device online', session.coreId, `(${durationMs} ms)`);
  session.on('message', (msg) => { /* your sensor decode, your storage */ });
});
gateway.on('handshake_failed', ({ coreId, stage, result }) => {
  console.warn('handshake failed', coreId, 'at', stage, '-', result);
});

await gateway.start();
```

## Documentation

- **`Usage.md`** — the full integration guide: every constructor option, the complete event contract with payload shapes, sending requests to a device, building OTA / operator frames, and clean shutdown.
- **`Implementation.md`** — the protocol internals: the six-stage handshake byte-by-byte, the rolling-IV AES session, the CoAP codec, the TCP framing (and why it is asymmetric), the trust-on-first-use key model, and the RSA worker pool.

## The public API

| Export | What it is |
|---|---|
| `Gateway` | TCP listener; one `Session` per connection; emits the lifecycle events. |
| `Session` | Per-device state machine: drives the handshake, runs the message loop, exposes `send()` / `request()`. |
| `CryptoPool` | `worker_threads` pool for the handshake's RSA math. Host owns its lifecycle. |
| `makeFsCoreKeyLoader` | Convenience filesystem loader for per-device public keys. The `Gateway` takes `loadCoreKey` as an injected function, so you can supply your own (DB, KMS) instead. |
| `Code`, `Option`, `Type` | CoAP constants, for building request frames against the wire format. |
