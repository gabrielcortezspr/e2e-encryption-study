#!/usr/bin/env node
/**
 * Manually decrypts a v1 envelope (AES-128-GCM)
 *
 * Usage:
 *   node tools/decrypt-envelope.js <key_hex> '<envelope_json>'
 *   node tools/decrypt-envelope.js <key_hex> envelope.json
 *
 * The key (32 hex characters) is shown by the client with /keys or in --debug
 * mode, which also prints the full envelope JSON for every message sent.
 *
 * Unlike the client, this tool does NOT enforce the timestamp window or the
 * replay cache: it is meant for studying old messages. The GCM tag is still
 * verified.
 */

const crypto = require('crypto');
const fs = require('fs');
const { buildAAD } = require('../client/crypto/envelope');

function usage() {
    console.log("Usage: node tools/decrypt-envelope.js <key_hex> <envelope_json | file.json>");
    process.exit(1);
}

const [keyHex, envelopeArg] = process.argv.slice(2);
if (!keyHex || !envelopeArg) usage();

try {
    if (!/^[0-9a-fA-F]{32}$/.test(keyHex.trim())) {
        throw new Error('The key must be exactly 32 hexadecimal characters (16 bytes)');
    }
    const key = Buffer.from(keyHex.trim(), 'hex');

    const raw = fs.existsSync(envelopeArg) ? fs.readFileSync(envelopeArg, 'utf8') : envelopeArg;
    const env = JSON.parse(raw);

    for (const field of ['v', 'ts', 'from', 'to', 'nonce', 'ct', 'tag']) {
        if (env[field] === undefined) throw new Error(`Envelope is missing the "${field}" field`);
    }

    const nonce = Buffer.from(env.nonce, 'hex');
    const decipher = crypto.createDecipheriv('aes-128-gcm', key, nonce);
    decipher.setAAD(buildAAD(env.v, env.ts, env.from, env.to, nonce));
    decipher.setAuthTag(Buffer.from(env.tag, 'hex'));

    const plaintext = Buffer.concat([
        decipher.update(Buffer.from(env.ct, 'hex')),
        decipher.final()
    ]).toString('utf8');

    console.log(`From:    ${env.from}`);
    console.log(`To:      ${env.to}${env.isGroup ? ' (group)' : ''}`);
    console.log(`Sent at: ${new Date(env.ts).toISOString()}`);
    console.log('✓ GCM tag is valid');
    console.log(`Message: "${plaintext}"`);
} catch (error) {
    const msg = /authenticate/.test(error.message)
        ? 'Invalid GCM tag: wrong key or tampered envelope'
        : error.message;
    console.error('❌ Error:', msg);
    process.exit(1);
}
