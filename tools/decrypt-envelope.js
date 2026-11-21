#!/usr/bin/env node
/**
 * Descriptografa manualmente um envelope v1 (AES-128-GCM)
 *
 * Uso:
 *   node tools/decrypt-envelope.js <chave_hex> '<envelope_json>'
 *   node tools/decrypt-envelope.js <chave_hex> envelope.json
 *
 * A chave (32 caracteres hex) aparece no cliente com /keys ou no modo --debug.
 * O envelope tem o formato { v, ts, from, to, isGroup, nonce, ct, tag }.
 *
 * Diferente do cliente, esta ferramenta NÃO aplica a janela de timestamp nem o
 * cache anti-replay: ela serve para estudar mensagens antigas. A tag GCM
 * continua sendo verificada.
 */

const crypto = require('crypto');
const fs = require('fs');

function usage() {
    console.log('Uso: node tools/decrypt-envelope.js <chave_hex> <envelope_json | arquivo.json>');
    process.exit(1);
}

const [keyHex, envelopeArg] = process.argv.slice(2);
if (!keyHex || !envelopeArg) usage();

try {
    if (!/^[0-9a-fA-F]{32}$/.test(keyHex.trim())) {
        throw new Error('A chave deve ter exatamente 32 caracteres hexadecimais (16 bytes)');
    }
    const key = Buffer.from(keyHex.trim(), 'hex');

    const raw = fs.existsSync(envelopeArg) ? fs.readFileSync(envelopeArg, 'utf8') : envelopeArg;
    const env = JSON.parse(raw);

    for (const field of ['v', 'ts', 'from', 'to', 'nonce', 'ct', 'tag']) {
        if (env[field] === undefined) throw new Error(`Envelope sem o campo "${field}"`);
    }

    // Mesma AAD usada em client/crypto/envelope.js
    const aad = Buffer.concat([
        Buffer.from([env.v]),
        Buffer.from(env.ts.toString()),
        Buffer.from(env.from),
        Buffer.from(env.to),
        Buffer.from(env.nonce, 'hex')
    ]);

    const decipher = crypto.createDecipheriv('aes-128-gcm', key, Buffer.from(env.nonce, 'hex'));
    decipher.setAAD(aad);
    decipher.setAuthTag(Buffer.from(env.tag, 'hex'));

    const plaintext = Buffer.concat([
        decipher.update(Buffer.from(env.ct, 'hex')),
        decipher.final()
    ]).toString('utf8');

    console.log(`De:      ${env.from}`);
    console.log(`Para:    ${env.to}${env.isGroup ? ' (grupo)' : ''}`);
    console.log(`Enviado: ${new Date(env.ts).toISOString()}`);
    console.log('✓ Tag GCM válida');
    console.log(`Mensagem: "${plaintext}"`);
} catch (error) {
    const msg = /authenticate/.test(error.message)
        ? 'Tag GCM inválida: chave errada ou envelope adulterado'
        : error.message;
    console.error('❌ Erro:', msg);
    process.exit(1);
}
