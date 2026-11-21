#!/usr/bin/env node
/**
 * Tests for the educational IDEA (experiments/idea/idea.js)
 * Usage: node experiments/idea/test-idea.js
 */

const assert = require('assert');
const crypto = require('crypto');
const idea = require('./idea');

// Test vector from Lai & Massey's original paper (also used by libraries such as Crypto++)
const KEY = Buffer.from('00010002000300040005000600070008', 'hex');
const PLAIN = Buffer.from('0000000100020003', 'hex');
const CIPHER = '11fbed2b01986de5';

const enc = idea.expandKey(KEY);
const dec = idea.invertSubkeys(enc);

const ct = idea.encryptBlock(PLAIN, enc);
assert.strictEqual(ct.toString('hex'), CIPHER, 'ciphertext does not match the official vector');
console.log('✓ Official test vector:', ct.toString('hex'));

const pt = idea.decryptBlock(ct, dec);
assert.strictEqual(pt.toString('hex'), PLAIN.toString('hex'), 'decrypting the vector failed');
console.log('✓ Test vector decrypts back');

for (let i = 0; i < 200; i++) {
    const key = crypto.randomBytes(16);
    const msg = crypto.randomBytes(1 + (i % 40)).toString('base64');
    assert.strictEqual(idea.decryptIdea(idea.encryptIdea(msg, key), key), msg);
}
console.log('✓ Round trip with 200 random keys/messages');

console.log('\n✅ IDEA OK');
