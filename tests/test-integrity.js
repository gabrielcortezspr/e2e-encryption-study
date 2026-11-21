#!/usr/bin/env node
/**
 * Tests for the client security layers: Ed25519 + TOFU + ECDH + HKDF + AEAD envelope
 * Usage: node tests/test-integrity.js   (or: npm test, from the repo root)
 *
 * Uses a temporary directory for keys, so client/.keys is left untouched.
 */

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const tmpKeys = fs.mkdtempSync(path.join(os.tmpdir(), 'e2e-study-keys-'));
process.env.KEYS_DIR = tmpKeys;

const tofu = require('../client/crypto/ed25519-tofu');
const ECDHManual = require('../client/crypto/ecdh-manual');
const { hkdf, deriveSessionKeys } = require('../client/crypto/hkdf');
const { encryptMessage, decryptMessage } = require('../client/crypto/envelope');

// Silence module logs (they log the expected errors)
const realLog = console.log;
const realError = console.error;
const quiet = (fn) => {
    console.log = () => {};
    console.error = () => {};
    try { return fn(); } finally { console.log = realLog; console.error = realError; }
};

let passed = 0;
function test(name, fn) {
    try {
        fn();
        passed++;
        realLog(`  ✓ ${name}`);
    } catch (err) {
        realError(`  ✗ ${name}\n    ${err.stack}`);
        process.exitCode = 1;
    }
}

realLog('🧪 Integrity tests - Ed25519 + TOFU + ECDH + HKDF + AEAD envelope\n');

// --- Ed25519 identities and ephemeral ECDH for Alice and Bob --------------
const alice = { ecdh: new ECDHManual() };
const bob = { ecdh: new ECDHManual() };
alice.ecdh.generateKeyPair();
bob.ecdh.generateKeyPair();

const signAs = (user, ecdh) => {
    tofu.setUsername(user);
    return quiet(() => tofu.signECDHPublicKey(ecdh.publicKey.toString('hex')));
};
const aliceSigned = signAs('Alice', alice.ecdh);
const bobSigned = signAs('Bob', bob.ecdh);

test('Alice and Bob have different Ed25519 identities', () => {
    assert.notStrictEqual(aliceSigned.ed25519Pub, bobSigned.ed25519Pub);
});

test('Private key file is created with mode 600', () => {
    const mode = fs.statSync(tofu.getKeypairFile('Alice')).mode & 0o777;
    if (process.platform !== 'win32') assert.strictEqual(mode, 0o600);
});

// --- TOFU ------------------------------------------------------------------
test("Alice verifies Bob's signature and pins his fingerprint (first contact)", () => {
    tofu.setUsername('Alice');
    quiet(() => tofu.verifyAndPinPeer('Bob', bobSigned.ed25519Pub, bobSigned.ecdhPub, bobSigned.signature));
    const pins = JSON.parse(fs.readFileSync(tofu.getTofuStore('Alice'), 'utf8'));
    assert.ok(pins.Bob && pins.Bob.fingerprint);
});

test('Reconnecting with the same identity is accepted', () => {
    tofu.setUsername('Alice');
    quiet(() => tofu.verifyAndPinPeer('Bob', bobSigned.ed25519Pub, bobSigned.ecdhPub, bobSigned.signature));
});

test('A swapped ECDH key (MITM) is rejected by the signature check', () => {
    const mallory = new ECDHManual();
    mallory.generateKeyPair();
    tofu.setUsername('Alice');
    assert.throws(
        () => quiet(() => tofu.verifyAndPinPeer('Bob', bobSigned.ed25519Pub, mallory.publicKey.toString('hex'), bobSigned.signature)),
        /Invalid signature/
    );
});

test('A different Ed25519 identity for "Bob" triggers the TOFU alert', () => {
    const fakeBob = signAs('Mallory', bob.ecdh); // valid signature, but a different identity
    tofu.setUsername('Alice');
    assert.throws(
        () => quiet(() => tofu.verifyAndPinPeer('Bob', fakeBob.ed25519Pub, fakeBob.ecdhPub, fakeBob.signature)),
        /TOFU: identity of Bob changed/
    );
});

// --- ECDH + HKDF -----------------------------------------------------------
const sharedA = alice.ecdh.computeSharedSecret(bob.ecdh.publicKey);
const sharedB = bob.ecdh.computeSharedSecret(alice.ecdh.publicKey);
const context = ['Alice', 'Bob'].sort().join(':');
const keyA = deriveSessionKeys(sharedA, context).encKey;
const keyB = deriveSessionKeys(sharedB, context).encKey;

test('ECDH: both sides compute the same secret', () => {
    assert.ok(sharedA.equals(sharedB));
});

test('HKDF: both sides derive the same 16-byte key', () => {
    assert.strictEqual(keyA.length, 16);
    assert.ok(keyA.equals(keyB));
});

test('HKDF: a different context yields a different key', () => {
    assert.ok(!deriveSessionKeys(sharedA, 'Alice:Carol').encKey.equals(keyA));
});

test('HKDF: RFC 5869 test vector 1', () => {
    const ikm = Buffer.alloc(22, 0x0b);
    const salt = Buffer.from('000102030405060708090a0b0c', 'hex');
    const info = Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex');
    const okm = hkdf(ikm, info, 42, salt).toString('hex');
    assert.strictEqual(okm, '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
});

// --- Envelope AEAD ---------------------------------------------------------
const plaintext = 'Integrity test: message protected by AES-128-GCM!';
const envelope = encryptMessage(plaintext, keyA, 'Alice', 'Bob', false);

test('Tampering with the ciphertext is detected (GCM tag)', () => {
    const flipped = (parseInt(envelope.ct[0], 16) ^ 1).toString(16) + envelope.ct.slice(1);
    assert.throws(() => quiet(() => decryptMessage({ ...envelope, ct: flipped }, keyB, 'Alice')),
        /authenticate/);
});

test('Tampering with metadata (AAD) is detected (GCM tag)', () => {
    assert.throws(() => quiet(() => decryptMessage({ ...envelope, to: 'Carol' }, keyB, 'Alice')),
        /authenticate/);
});

test('A forged envelope does not "burn" the nonce of the real message', () => {
    // Both failures above reused the nonce; the real message must still open
    const decrypted = decryptMessage(envelope, keyB, 'Alice');
    assert.strictEqual(decrypted, plaintext);
});

test('Replaying the same envelope is rejected', () => {
    assert.throws(() => quiet(() => decryptMessage(envelope, keyB, 'Alice')), /Repeated nonce/);
});

test('An unexpected sender is rejected', () => {
    const env = encryptMessage('oi', keyA, 'Alice', 'Bob');
    assert.throws(() => quiet(() => decryptMessage(env, keyB, 'Carol')), /Unexpected sender/);
});

test('A timestamp outside the 5-minute window is rejected', () => {
    const env = encryptMessage('oi', keyA, 'Alice', 'Bob');
    const old = { ...env, ts: Date.now() - 10 * 60 * 1000 };
    assert.throws(() => quiet(() => decryptMessage(old, keyB, 'Alice')), /acceptance window/);
});

test('The wrong key does not decrypt', () => {
    const env = encryptMessage('oi', keyA, 'Alice', 'Bob');
    assert.throws(() => quiet(() => decryptMessage(env, crypto.randomBytes(16), 'Alice')), /authenticate/);
});

fs.rmSync(tmpKeys, { recursive: true, force: true });

if (process.exitCode) {
    realError('\n❌ Some tests failed');
} else {
    realLog(`\n✅ ${passed} tests passed`);
}
