# Implementation

The protocol internals, for anyone debugging a handshake or porting the firmware side. The wire bytes here are fixed by Particle Photon firmware deployed in the field — this library matches the firmware, never the other way around. None of it is configurable.

## The six-stage handshake

A connection is plaintext until stage 4 completes, then AES-128-CBC for the rest of its life. `lib/handshake.js` runs the stages as a straight sequence of awaits; I/O is injected so both ends can be driven in-memory by tests without real sockets.

1. **SEND_NONCE.** The server writes 40 random plaintext bytes to the socket.
2. **READ_COREID.** The device replies with a 256-byte RSA-PKCS#1 v1.5 blob encrypted with the *server's* public key. Decrypted, the plaintext is `[40-byte nonce ‖ 12-byte device id ‖ optional DER device public key]`. The returned nonce must echo exactly what stage 1 sent; a mismatch aborts. The device id becomes the 24-hex-char `coreId`.
3. **GET_COREKEY.** The server looks up `keys/core_keys/<coreId>.pub.pem`. If it is missing but the device included an inline public key in stage 2, that key is quarantined to `<coreId>_handshake.pub.pem` and the handshake fails closed — acceptance is a deliberate operator action, never automatic (see *Key trust* below).
4. **SEND_SESSIONKEY.** The server generates 40 bytes of session material and sends `ciphertext ‖ signature` (384 bytes total): the 40 bytes RSA-encrypted with the *device's* public key (128 bytes at RSA-1024), followed by an RSA signature (256 bytes at RSA-2048) over the HMAC-SHA1 of that ciphertext keyed by the session material. From the session material: `aesKey = session[0..16]`, `initialIV = session[16..32]`. All subsequent traffic is AES-128-CBC.
5. **GET_HELLO.** The server reads one length-prefixed AES frame, decrypts it with the initial IV, and CoAP-parses a "Hello". Its message id seeds the inbound counter; an optional 4-byte body is `[productId u16][firmwareVersion u16]`.
6. **SEND_HELLO.** The server picks a random 16-bit send counter, AES-encrypts a CoAP Hello, and writes one framed payload. The handshake is now complete and the `session` event fires.

## The rolling-IV AES session

This is the single most error-prone detail. After every block-cipher operation, each side advances its IV to **the first 16 bytes of the ciphertext just processed** — inbound and outbound IVs roll independently.

This is *not* standard CBC chaining. The firmware does an explicit `memcpy(iv, buf, 16)` that overrides mbedtls's own last-block IV update, so the "next IV" is the *first* 16 bytes of the message, not the last. For a single-block (16-byte) message the first and last block are the same bytes, so the bug stays hidden; it only surfaces on multi-block frames, where getting it wrong silently desyncs the cipher chain and every later frame decrypts to garbage. `lib/session.js` owns this invariant and is the only writer of `ivIn` / `ivOut`.

The session loop, post-handshake: read a length-prefixed frame → AES-decrypt with `ivIn` → roll `ivIn` → CoAP-parse → classify → emit `message`. Outbound is the inverse: CoAP-encode → AES-encrypt with `ivOut` → roll `ivOut` → length-prefix → write. CoAP `Ping` is auto-ACKed so the device's keepalive does not trip the **2-minute idle disconnect**.

## TCP framing is asymmetric

The two directions do not use the same frame header — because the firmware does not.

```
device → server:  [length_hi][length_lo][0xFF sync][...length bytes]
server → device:  [length_hi][length_lo][...length bytes]
```

The firmware's transmit path writes a 3-byte header (including a `0xFF` sync byte), but its receive path reads the body unconditionally by length and never inspects a sync byte. So the server must *emit* 2-byte-prefixed frames (no sync) and *accept* 3-byte ones. The sync byte exists only for a receiver that wants to resync a stream it joined mid-frame; the firmware's own receiver does not use it. `lib/chunking.js` implements both shapes; `encodeDeviceFrame` produces the device-style (with sync) frame so synthetic-device tests exercise the exact byte layout a real Photon emits.

## The CoAP codec

`lib/coap.js` is a ~150-line CoAP codec (RFC 7252) covering exactly what the spark protocol needs and nothing more: the 4-byte header (Ver=01, 2-bit Type, 4-bit token length, 8-bit Code, 16-bit big-endian Message-ID), a 0–8-byte token, options with the standard delta/length nibble encoding plus the 13/14 extended forms, and the `0xFF` payload marker. Block-wise transfer, observe, dedup, and retransmit are deliberately out of scope — those are session-level concerns. It has no external dependencies on purpose: the older CoAP npm packages are either unmaintained or carry UDP-socket assumptions that do not fit a TCP stream.

`Code`, `Option`, and `Type` are exported so a host can build option lists (e.g. `Option.UriPath`) and interpret reply codes (e.g. `Code.Changed`).

## Named messages

`lib/messages.js` is the protocol vocabulary: each named spark message maps to a `(code, type, uri)` tuple. The codec uses it both ways — `classify()` names an inbound decoded CoAP message, and `Messages.<Name>` builds an outbound one. The table mirrors the firmware's message spec exactly; a new message is a coordinated firmware-and-library change, not a library-only one.

## Key trust (trust-on-first-use, no auto-promotion)

`lib/core-keys.js` resolves per-device public keys from `keys/core_keys/`:

- `<coreId>.pub.pem` — the canonical accepted key; handshake proceeds.
- `<coreId>_handshake.pub.pem` — a key the device offered inline that has *not* been accepted; handshake fails until an operator renames the file to promote it.

Acceptance is always an explicit human step. In a building full of devices, that prevents a stolen or cloned Photon from silently registering itself. A host that wants a different policy supplies its own `loadCoreKey` and ignores this module.

## The RSA worker pool

`lib/crypto-pool.js` runs only the RSA operations off the main thread. The motivating case is a cold-start storm: ~500 devices reconnecting within a few seconds means ~500 RSA decryptions, which at ~1 ms each would stall a single event loop for half a second and delay every other connection. Sharded across `os.availableParallelism()` worker threads, the RSA math parallelises onto multiple cores and the event loop stays free for I/O. AES and HMAC are sub-microsecond and stay on the main thread — moving them to workers would cost more in `postMessage` overhead than they save.

The pool size is fixed at construction; when every worker is busy, tasks queue in memory rather than spawning more workers, and the queue depth is observable via `CryptoPool#stats()`. Keys cross the thread boundary as PEM strings, and each worker caches parsed key objects in an LRU so a hot device key pays its parse cost once per worker, not once per handshake.
