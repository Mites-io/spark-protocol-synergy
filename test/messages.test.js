import { test } from 'node:test';
import assert from 'node:assert/strict';

import { Code, Option, Type, encode, decode } from '../lib/coap.js';
import { classify, Messages } from '../lib/messages.js';

test('classify identifies a Hello message', () => {
  const wire = encode({
    type: Type.NON, code: Code.POST, messageId: 1, token: Buffer.alloc(0),
    options: [{ number: Option.UriPath, value: Buffer.from('h') }],
  });
  assert.equal(classify(decode(wire)), 'Hello');
});

test('classify identifies a SynergyProtocol packet', () => {
  const wire = encode({
    type: Type.NON, code: Code.POST, messageId: 2, token: Buffer.alloc(0),
    options: [{ number: Option.UriPath, value: Buffer.from('m') }],
    payload: Buffer.from('opaque-sensor-blob'),
  });
  assert.equal(classify(decode(wire)), 'SynergyProtocol');
});

test('classify identifies a Ping (empty CON, no Uri-Path)', () => {
  const wire = encode({ type: Type.CON, code: Code.Empty, messageId: 3, token: Buffer.alloc(0) });
  assert.equal(classify(decode(wire)), 'Ping');
});

test('classify returns null for an unknown Uri-Path', () => {
  const wire = encode({
    type: Type.CON, code: Code.GET, messageId: 4, token: Buffer.alloc(0),
    options: [{ number: Option.UriPath, value: Buffer.from('xyz') }],
  });
  assert.equal(classify(decode(wire)), null);
});

test('Messages table covers all spark message names the firmware emits', () => {
  for (const name of ['Hello', 'Ping', 'SynergyProtocol', 'FunctionCall',
                      'VariableRequest', 'Describe', 'GetTime', 'RaiseYourHand']) {
    assert.ok(Messages[name], `${name} missing from Messages table`);
  }
});
