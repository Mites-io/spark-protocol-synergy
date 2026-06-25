/**
 * @module gateway/core-keys
 *
 * Filesystem-backed lookup of per-device public keys. The handshake calls
 * `loadCoreKey(coreId, inlineDer)` to find the canonical pubkey for an
 * incoming device.
 *
 * Layout under `keys/core_keys/`:
 * - `<coreId>.pub.pem` — canonical accepted key. Handshake succeeds.
 * - `<coreId>_handshake.pub.pem` — quarantined key the device sent inline
 *   during stage 2. Handshake **fails closed**; an operator must rename
 *   the file (drop the `_handshake` suffix) to promote it.
 *
 * Trust-on-first-use without auto-promotion mirrors the legacy
 * `spark-protocol-synergy` behaviour and keeps key acceptance an explicit
 * human action — important for buildings where a stolen Photon could
 * otherwise auto-register.
 */

import { access, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

const DEVICE_ID_HEX = /^[0-9a-f]{24}$/;

/**
 * Validate a device id — exactly 24 hex chars (CLAUDE.md §7: input
 * validation at every trust boundary).
 *
 * @param {unknown} id
 * @returns {boolean}
 */
export function isValidDeviceId(id) {
  return typeof id === 'string' && DEVICE_ID_HEX.test(id);
}

/**
 * Build a `loadCoreKey(coreId, inlineDer)` function bound to the given
 * keys directory. Returns the canonical PEM if present, otherwise
 * quarantines any inline DER key under `<id>_handshake.pub.pem` and
 * resolves to `null` so the handshake fails closed.
 *
 * @param {string} keysDir Absolute or relative path to `keys/core_keys/`
 * @returns {(coreId: string, inlineDer: Buffer|null) => Promise<string|null>}
 *   The returned loader rejects (`@throws {Error}`) on an invalid device
 *   id or a filesystem error other than a missing canonical key.
 */
export function makeFsCoreKeyLoader(keysDir) {
  const dir = resolve(keysDir);
  return async function loadCoreKey(coreId, inlineDer) {
    if (!isValidDeviceId(coreId)) {
      throw new Error(`invalid device id: ${coreId}`);
    }

    const canonical = join(dir, `${coreId}.pub.pem`);
    try {
      return await readFile(canonical, 'utf8');
    } catch (err) {
      if (err.code !== 'ENOENT') throw err;
    }

    if (inlineDer && inlineDer.length > 0) {
      const quarantine = join(dir, `${coreId}_handshake.pub.pem`);
      try {
        await access(quarantine);
      } catch {
        await writeFile(quarantine, derToPem(inlineDer), { mode: 0o600 });
      }
    }
    return null;
  };
}

/**
 * Wrap DER (SubjectPublicKeyInfo) bytes as a PEM string.
 *
 * @param {Buffer} der
 * @returns {string}
 */
export function derToPem(der) {
  const b64 = der.toString('base64');
  const lines = ['-----BEGIN PUBLIC KEY-----'];
  for (let i = 0; i < b64.length; i += 64) lines.push(b64.slice(i, i + 64));
  lines.push('-----END PUBLIC KEY-----');
  return lines.join('\n') + '\n';
}
