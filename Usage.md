# Usage

How to embed this library in a backend. The library gives you a TCP listener that turns Photon connections into authenticated, decrypted message streams; everything above that — what the messages *mean*, where the data goes, what you measure — is yours.

## Prerequisites: two sets of keys

The spark handshake is mutual, so you need both halves on disk before a device can connect.

- **Server keypair** — one RSA-2048 keypair for this backend, e.g. `keys/srv_keys/default_key.pem` (private). Its public half is what gets flashed onto every device so the device can encrypt its first message to you. You pass the private PEM to the `Gateway`.
- **Per-device public keys** — one RSA-1024 public key per Photon, named by the device's 24-hex-char id: `keys/core_keys/<coreId>.pub.pem`. The handshake looks this up to verify the device is who it claims to be.

This library does not generate keys — that lives in your device-flashing tooling. It only *reads* them.

## 1. The crypto pool

The handshake's RSA operations are CPU-heavy, so they run in a `worker_threads` pool instead of on the event loop. Build one pool and share it across all connections.

```js
import { CryptoPool } from '@mites-io/spark-protocol-synergy';

const crypto = new CryptoPool();              // default size = os.availableParallelism()
// const crypto = new CryptoPool({ size: 4 }); // or pin the worker count

// Observe it for your own /metrics:
crypto.stats();   // → { workers, idle, inflight, queued }
```

On shutdown, call `await crypto.stop()` to terminate the workers.

## 2. The core-key loader

The `Gateway` resolves a device's public key through an injected `loadCoreKey(coreId, inlineDer)` function. The bundled filesystem implementation is the common case:

```js
import { makeFsCoreKeyLoader } from '@mites-io/spark-protocol-synergy';
const loadCoreKey = makeFsCoreKeyLoader('keys/core_keys');
```

If a device presents a key that is not yet on disk, the loader quarantines it as `<coreId>_handshake.pub.pem` and the handshake **fails closed** — an operator promotes the key by renaming the file (dropping the `_handshake` suffix). This is trust-on-first-use without auto-acceptance, so a stolen or spoofed Photon cannot self-register. If you want a different policy (database, KMS, auto-accept in a lab), pass your own async function with the same signature instead.

## 3. The registry contract

The `Gateway` registers a session on successful handshake and unregisters it on close, through any object you supply that implements two methods:

```js
const registry = {
  register(session)    { /* session.coreId is set; track it */ },
  unregister(coreId)   { /* device gone */ },
};
```

Use whatever you already have for device tracking; the library only needs those two calls.

## 4. Build and start the gateway

```js
import { Gateway } from '@mites-io/spark-protocol-synergy';
import { readFileSync } from 'node:fs';

const gateway = new Gateway({
  port: 5683,                                              // device-facing TCP port
  host: '0.0.0.0',                                         // optional, defaults to 0.0.0.0
  crypto,                                                  // the CryptoPool from step 1
  serverPrivKeyPem: readFileSync('keys/srv_keys/default_key.pem', 'utf8'),
  loadCoreKey,                                             // from step 2
  registry,                                                // from step 3
});

const addr = await gateway.start();   // resolves with the bound AddressInfo; rejects if the bind fails
```

`gateway.stop()` stops accepting, disconnects every live session, and closes the listener. `gateway.address()` and `gateway.sessionCount` are available for health checks.

## 5. The event contract

Everything operationally interesting is an event. The library records no metrics and writes no logs of its own — you attach meaning here.

| Event | Payload | When |
|---|---|---|
| `listening` | `AddressInfo` | listener bound |
| `connection` | `{ remote, socket }` | raw socket accepted, before handshake |
| `session` | `(session, { durationMs })` | handshake succeeded; `session.coreId` is set |
| `handshake_failed` | `{ remote, coreId, stage, result, durationMs, error }` | handshake ended without success |
| `session_disconnected` | `{ coreId, reason, durationMs }` | a registered session closed |
| `error` | `Error` | listener error after bind |

`handshake_failed` carries a classified `result` (`rsa_fail`, `nonce_mismatch`, `aes_hello_fail`, `hello_parse_fail`, `missing_core_key`, `timeout`, …) and the `stage` it died at, so you can chart where failures cluster without parsing error strings.

## 6. Talk to a device

Each `session` is itself an `EventEmitter`. Inbound device messages arrive already decrypted, CoAP-parsed, and classified:

```js
gateway.on('session', (session) => {
  session.on('message', ({ name, msg }) => {
    // name  — the classified spark message (e.g. a sensor stream key)
    // msg   — the decoded CoAP message: { code, type, messageId, token, options, payload }
    // decode msg.payload however your firmware encodes it, and store it.
  });
  session.on('close', () => { /* device gone */ });
});
```

Two ways to send to a device, both keyed by a `Messages` name:

```js
// Fire-and-forget — returns the message id sent.
session.send('UpdateBegin', { payload: someBuffer });

// Request/response — resolves with the device's CoAP reply (used by an operator API).
const reply = await session.request('VariableRequest', {
  options: [{ number: Option.UriPath, value: Buffer.from('temperature') }],
});
```

`Code`, `Option`, and `Type` are exported for building those option lists and for interpreting `msg.code` on replies — for example an over-the-air update driver constructs chunk frames with `Option.UriPath` and checks for `Code.Changed` acknowledgements.

## 7. Shutdown

```js
await gateway.stop();    // stop accepting, FIN every live session, close the listener
await crypto.stop();     // terminate the RSA worker threads
```

## A note on metrics and logging

This library deliberately has no opinion about either. The reference backend wires its Prometheus counters by subscribing to the events above — `connection` → an accept counter, `session` → a handshake-success counter plus a duration histogram off `durationMs`, `handshake_failed` → a failure counter labelled by `result`, and so on. Keeping that translation in the host is what lets the same library run unchanged under any observability stack.
