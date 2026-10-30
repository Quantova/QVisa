// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');

function freshKey() {
  return Q.generateKey();
}

function grantVisa(key, subject) {
  return Q.grant({ key, visaType: 'tourist', visaNo: 'V 1234567', subject: Q.keyId(subject), entries: 'multiple', validUntil: '2027-01-01T00:00:00.000Z', authorityLabel: 'Consulate General' });
}

test('a granted visa is a well formed signed record of the authority', () => {
  const authority = freshKey();
  const holder = freshKey();
  const visa = grantVisa(authority, holder);
  assert.strictEqual(visa.format, 'qvisa/1');
  assert.strictEqual(visa.type, 'grant');
  assert.strictEqual(visa.algorithm, 'ML-DSA-65');
  assert.strictEqual(visa.signer.id, Q.keyId(authority));
  assert.strictEqual(visa.statement.authorityKeyId, Q.keyId(authority));
  assert.strictEqual(visa.statement.subjectKeyId, Q.keyId(holder));
  assert.match(visa.statement.visaId, /^[0-9a-f]{32}$/);
  assert.strictEqual(Buffer.from(visa.signer.publicKey, 'base64').length, Q.PUBLIC_KEY_BYTES);
  assert.strictEqual(Buffer.from(visa.signature, 'base64').length, Q.SIGNATURE_BYTES);
});

test('the extend, enter and exit records chain to the same visa', () => {
  const authority = freshKey();
  const holder = freshKey();
  const officer = freshKey();
  const visa = grantVisa(authority, holder);
  const ext = Q.extend({ key: authority, visa, validUntil: '2028-01-01T00:00:00.000Z' });
  const ent = Q.enter({ key: officer, record: visa, post: 'LHR Terminal 5' });
  const ex = Q.exit({ key: officer, record: ent, post: 'LGW' });
  assert.strictEqual(ext.statement.visaId, visa.statement.visaId);
  assert.strictEqual(ext.statement.grantRef, Q.recordRef(visa));
  assert.strictEqual(ent.statement.priorRef, Q.recordRef(visa));
  assert.strictEqual(ex.statement.priorRef, Q.recordRef(ent));
});

test('invalid inputs are refused before anything is signed', () => {
  const key = freshKey();
  const holder = freshKey();
  const base = { key, visaType: 'tourist', visaNo: 'V1', subject: Q.keyId(holder), entries: 'single', validUntil: '2027-01-01T00:00:00.000Z' };
  assert.throws(() => Q.grant(Object.assign({}, base, { visaType: 'holiday' })), /visaType must be one of/);
  assert.throws(() => Q.grant(Object.assign({}, base, { entries: 'five' })), /entries must be one of/);
  assert.throws(() => Q.grant(Object.assign({}, base, { visaNo: '' })), /visaNo is 1 to/);
  assert.throws(() => Q.grant(Object.assign({}, base, { subject: 'nothex' })), /subject is a/);
  assert.throws(() => Q.grant(Object.assign({}, base, { unknownField: 1 })), /is not an option of grant/);
});

test('a signing key must be a well formed 32 byte seed', () => {
  const holder = freshKey();
  assert.throws(() => grantVisa(new Uint8Array(16), holder), /32 byte Uint8Array seed/);
  assert.throws(() => grantVisa(new Uint8Array(32), holder), /too few different byte values/);
});

test('a well formed record verifies and a type mismatch is invalid', async () => {
  const authority = freshKey();
  const holder = freshKey();
  const visa = grantVisa(authority, holder);
  const ok = await Q.verify(visa, { type: 'grant', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(ok.status, 'valid');
  assert.strictEqual(ok.type, 'grant');
  assert.strictEqual(ok.visaId, visa.statement.visaId);
  const wrongType = await Q.verify(visa, { type: 'enter', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(wrongType.status, 'invalid');
  const wrongSigner = await Q.verify(visa, { type: 'grant', network: 'testnet', requireAnchor: false, strict: false, signerKeyId: Q.keyId(freshKey()) });
  assert.strictEqual(wrongSigner.status, 'invalid');
});

test('a tampered statement no longer verifies', async () => {
  const authority = freshKey();
  const holder = freshKey();
  const visa = grantVisa(authority, holder);
  const forged = JSON.parse(JSON.stringify(visa));
  forged.statement.entries = 'single';
  const r = await Q.verify(forged, { type: 'grant', network: 'testnet', requireAnchor: false, strict: false });
  assert.strictEqual(r.status, 'invalid');
  assert.ok(r.checks.some((c) => c.name === 'signature' && !c.ok));
});

test('the prior link binds an entry to the visa it refers to', async () => {
  const authority = freshKey();
  const holder = freshKey();
  const officer = freshKey();
  const visa = grantVisa(authority, holder);
  const ent = Q.enter({ key: officer, record: visa, post: 'LHR Terminal 5' });
  const good = await Q.verify(ent, { type: 'enter', network: 'testnet', requireAnchor: false, strict: false, prior: visa });
  assert.ok(good.checks.some((c) => c.name === 'prior' && c.ok));
  const otherVisa = grantVisa(authority, holder);
  const bad = await Q.verify(ent, { type: 'enter', network: 'testnet', requireAnchor: false, strict: false, prior: otherVisa });
  assert.strictEqual(bad.status, 'invalid');
  assert.ok(bad.checks.some((c) => c.name === 'prior' && !c.ok));
});

test('subjectRef is deterministic for the same secret and reference and differs otherwise', () => {
  const secret = new Uint8Array(32);
  globalThis.crypto.getRandomValues(secret);
  const a = Q.subjectRef(secret, 'V 1234567');
  const b = Q.subjectRef(secret, 'V 1234567');
  const c = Q.subjectRef(secret, 'V 1234568');
  assert.strictEqual(a, b);
  assert.notStrictEqual(a, c);
  assert.match(a, /^[0-9a-f]{64}$/);
});

test('the kind and constants are the ones pinned for the visa line', () => {
  assert.strictEqual(Q.KIND, 1503);
  assert.strictEqual(Q.FORMAT, 'qvisa/1');
  assert.deepStrictEqual([...Q.TYPES], ['grant', 'extend', 'enter', 'exit', 'revoke']);
  assert.deepStrictEqual([...Q.VISATYPES], ['tourist', 'business', 'student', 'work', 'transit', 'diplomatic']);
  assert.deepStrictEqual([...Q.ENTRIES], ['single', 'double', 'multiple']);
});
