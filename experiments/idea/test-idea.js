#!/usr/bin/env node
/**
 * Testes do IDEA educativo (experiments/idea/idea.js)
 * Uso: node experiments/idea/test-idea.js
 */

const assert = require('assert');
const crypto = require('crypto');
const idea = require('./idea');

// Vetor de teste do artigo original de Lai & Massey (também usado em libs como Crypto++)
const KEY = Buffer.from('00010002000300040005000600070008', 'hex');
const PLAIN = Buffer.from('0000000100020003', 'hex');
const CIPHER = '11fbed2b01986de5';

const enc = idea.expandKey(KEY);
const dec = idea.invertSubkeys(enc);

const ct = idea.encryptBlock(PLAIN, enc);
assert.strictEqual(ct.toString('hex'), CIPHER, 'bloco cifrado não bate com o vetor oficial');
console.log('✓ Vetor de teste oficial:', ct.toString('hex'));

const pt = idea.decryptBlock(ct, dec);
assert.strictEqual(pt.toString('hex'), PLAIN.toString('hex'), 'decriptação do vetor falhou');
console.log('✓ Decriptação do vetor de teste');

for (let i = 0; i < 200; i++) {
    const key = crypto.randomBytes(16);
    const msg = crypto.randomBytes(1 + (i % 40)).toString('base64');
    assert.strictEqual(idea.decryptIdea(idea.encryptIdea(msg, key), key), msg);
}
console.log('✓ Ida e volta com 200 chaves/mensagens aleatórias');

console.log('\n✅ IDEA OK');
