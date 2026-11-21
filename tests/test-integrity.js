#!/usr/bin/env node
/**
 * Teste das camadas de segurança do cliente: Ed25519 + TOFU + ECDH + HKDF + Envelope AEAD
 * Uso: node tests/test-integrity.js   (ou: npm test, na raiz)
 *
 * Usa um diretório temporário para as chaves, sem tocar em client/.keys.
 */

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const tmpKeys = fs.mkdtempSync(path.join(os.tmpdir(), 'e2e-chat-keys-'));
process.env.KEYS_DIR = tmpKeys;

const tofu = require('../client/crypto/ed25519-tofu');
const ECDHManual = require('../client/crypto/ecdh-manual');
const { hkdf, deriveSessionKeys } = require('../client/crypto/hkdf');
const { encryptMessage, decryptMessage } = require('../client/crypto/envelope');

// Silenciar logs dos módulos (os erros esperados são logados por eles)
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

realLog('🧪 Teste de Integridade - Ed25519 + TOFU + ECDH + HKDF + Envelope AEAD\n');

// --- Identidades Ed25519 e ECDH efêmero de Alice e Bob ---------------------
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

test('Alice e Bob têm identidades Ed25519 diferentes', () => {
    assert.notStrictEqual(aliceSigned.ed25519Pub, bobSigned.ed25519Pub);
});

test('Arquivo de chave privada é criado com permissão 600', () => {
    const mode = fs.statSync(tofu.getKeypairFile('Alice')).mode & 0o777;
    if (process.platform !== 'win32') assert.strictEqual(mode, 0o600);
});

// --- TOFU ------------------------------------------------------------------
test('Alice verifica a assinatura de Bob e pina o fingerprint (1º contato)', () => {
    tofu.setUsername('Alice');
    quiet(() => tofu.verifyAndPinPeer('Bob', bobSigned.ed25519Pub, bobSigned.ecdhPub, bobSigned.signature));
    const pins = JSON.parse(fs.readFileSync(tofu.getTofuStore('Alice'), 'utf8'));
    assert.ok(pins.Bob && pins.Bob.fingerprint);
});

test('Reconexão com a mesma identidade é aceita', () => {
    tofu.setUsername('Alice');
    quiet(() => tofu.verifyAndPinPeer('Bob', bobSigned.ed25519Pub, bobSigned.ecdhPub, bobSigned.signature));
});

test('Chave ECDH substituída (MITM) é rejeitada pela assinatura', () => {
    const mallory = new ECDHManual();
    mallory.generateKeyPair();
    tofu.setUsername('Alice');
    assert.throws(
        () => quiet(() => tofu.verifyAndPinPeer('Bob', bobSigned.ed25519Pub, mallory.publicKey.toString('hex'), bobSigned.signature)),
        /Assinatura inválida/
    );
});

test('Identidade Ed25519 diferente para "Bob" dispara alerta TOFU', () => {
    const fakeBob = signAs('Mallory', bob.ecdh); // assinatura válida, mas outra identidade
    tofu.setUsername('Alice');
    assert.throws(
        () => quiet(() => tofu.verifyAndPinPeer('Bob', fakeBob.ed25519Pub, fakeBob.ecdhPub, fakeBob.signature)),
        /TOFU: Identidade de Bob mudou/
    );
});

// --- ECDH + HKDF -----------------------------------------------------------
const sharedA = alice.ecdh.computeSharedSecret(bob.ecdh.publicKey);
const sharedB = bob.ecdh.computeSharedSecret(alice.ecdh.publicKey);
const context = ['Alice', 'Bob'].sort().join(':');
const keyA = deriveSessionKeys(sharedA, context).encKey;
const keyB = deriveSessionKeys(sharedB, context).encKey;

test('ECDH: os dois lados calculam o mesmo segredo', () => {
    assert.ok(sharedA.equals(sharedB));
});

test('HKDF: os dois lados derivam a mesma chave de 16 bytes', () => {
    assert.strictEqual(keyA.length, 16);
    assert.ok(keyA.equals(keyB));
});

test('HKDF: contexto diferente gera chave diferente', () => {
    assert.ok(!deriveSessionKeys(sharedA, 'Alice:Carol').encKey.equals(keyA));
});

test('HKDF: vetor de teste 1 da RFC 5869', () => {
    const ikm = Buffer.alloc(22, 0x0b);
    const salt = Buffer.from('000102030405060708090a0b0c', 'hex');
    const info = Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex');
    const okm = hkdf(ikm, info, 42, salt).toString('hex');
    assert.strictEqual(okm, '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
});

// --- Envelope AEAD ---------------------------------------------------------
const plaintext = 'Teste de integridade: mensagem protegida por AES-128-GCM!';
const envelope = encryptMessage(plaintext, keyA, 'Alice', 'Bob', false);

test('Adulterar o ciphertext é detectado (tag GCM)', () => {
    const flipped = (parseInt(envelope.ct[0], 16) ^ 1).toString(16) + envelope.ct.slice(1);
    assert.throws(() => quiet(() => decryptMessage({ ...envelope, ct: flipped }, keyB, 'Alice')),
        /authenticate/);
});

test('Adulterar metadados (AAD) é detectado (tag GCM)', () => {
    assert.throws(() => quiet(() => decryptMessage({ ...envelope, to: 'Carol' }, keyB, 'Alice')),
        /authenticate/);
});

test('Envelope forjado não "queima" o nonce da mensagem legítima', () => {
    // As duas falhas acima reutilizaram o nonce; a mensagem real ainda deve abrir
    const decrypted = decryptMessage(envelope, keyB, 'Alice');
    assert.strictEqual(decrypted, plaintext);
});

test('Replay do mesmo envelope é rejeitado', () => {
    assert.throws(() => quiet(() => decryptMessage(envelope, keyB, 'Alice')), /Nonce repetido/);
});

test('Remetente inesperado é rejeitado', () => {
    const env = encryptMessage('oi', keyA, 'Alice', 'Bob');
    assert.throws(() => quiet(() => decryptMessage(env, keyB, 'Carol')), /Sender inesperado/);
});

test('Timestamp fora da janela de 5 minutos é rejeitado', () => {
    const env = encryptMessage('oi', keyA, 'Alice', 'Bob');
    const old = { ...env, ts: Date.now() - 10 * 60 * 1000 };
    assert.throws(() => quiet(() => decryptMessage(old, keyB, 'Alice')), /janela/);
});

test('Chave errada não descriptografa', () => {
    const env = encryptMessage('oi', keyA, 'Alice', 'Bob');
    assert.throws(() => quiet(() => decryptMessage(env, crypto.randomBytes(16), 'Alice')));
});

fs.rmSync(tmpKeys, { recursive: true, force: true });

if (process.exitCode) {
    realError('\n❌ Há testes falhando');
} else {
    realLog(`\n✅ ${passed} testes passaram`);
}
