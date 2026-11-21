/**
 * Implementação de criptografia com envelope v1 usando AES-128-GCM (AEAD)
 * Envelope inclui: versão, timestamp, sender, recipient, nonce, ciphertext, tag
 * Integridade garantida por GCM auth tag + AAD (metadados)
 * SERVIDOR: apenas fornece funções auxiliares (não cifra/decifra, apenas relay)
 */

const crypto = require('crypto');

const ENVELOPE_VERSION = 1;
const TIMESTAMP_WINDOW_MS = 5 * 60 * 1000; // 5 minutos

/**
 * Cria envelope v1 criptografado com AES-128-GCM
 * @param {string} message - Mensagem plaintext
 * @param {Buffer} key - Chave de cifra (16 bytes)
 * @param {string} sender - Identificador do remetente
 * @param {string} recipient - Identificador do destinatário (ou groupId)
 * @param {boolean} isGroup - Se é mensagem de grupo
 * @returns {Object} - Envelope {v, ts, from, to, isGroup, nonce, ct, tag}
 */
function encryptMessage(message, key, sender, recipient, isGroup = false) {
    try {
        if (!Buffer.isBuffer(key) || key.length !== 16) {
            throw new Error('Chave deve ser Buffer de 16 bytes (128 bits)');
        }
        if (!sender || !recipient) {
            throw new Error('Sender e recipient são obrigatórios');
        }

        const nonce = crypto.randomBytes(12); // 96 bits (recomendado para GCM)
        const timestamp = Date.now();
        
        // AAD (Additional Authenticated Data): metadados protegidos mas não cifrados
        const aad = Buffer.concat([
            Buffer.from([ENVELOPE_VERSION]),
            Buffer.from(timestamp.toString()),
            Buffer.from(sender),
            Buffer.from(recipient),
            nonce
        ]);

        const cipher = crypto.createCipheriv('aes-128-gcm', key, nonce);
        cipher.setAAD(aad);
        
        const encrypted = Buffer.concat([
            cipher.update(message, 'utf8'),
            cipher.final()
        ]);
        
        const tag = cipher.getAuthTag();

        return {
            v: ENVELOPE_VERSION,
            ts: timestamp,
            from: sender,
            to: recipient,
            isGroup: isGroup || false,
            nonce: nonce.toString('hex'),
            ct: encrypted.toString('hex'),
            tag: tag.toString('hex')
        };
    } catch (error) {
        console.error('Erro ao criar envelope criptografado:', error.message);
        throw error;
    }
}

/**
 * Valida e descriptografa envelope v1
 * @param {Object} envelope - Envelope recebido
 * @param {Buffer} key - Chave de cifra (16 bytes)
 * @param {string} expectedSender - Sender esperado (opcional, validação adicional)
 * @returns {string} - Mensagem plaintext
 * @throws {Error} - Se validação/integridade falhar
 */
function decryptMessage(envelope, key, expectedSender = null) {
    try {
        if (!Buffer.isBuffer(key) || key.length !== 16) {
            throw new Error('Chave deve ser Buffer de 16 bytes (128 bits)');
        }
        
        // Validar estrutura
        const { v, ts, from, to, nonce, ct, tag } = envelope;
        if (!v || !ts || !from || !to || !nonce || !ct || !tag) {
            throw new Error('Envelope incompleto ou inválido');
        }
        
        // Validar versão
        if (v !== ENVELOPE_VERSION) {
            throw new Error(`Versão de envelope não suportada: ${v}`);
        }
        
        // Validar timestamp (janela de aceitação)
        const now = Date.now();
        if (Math.abs(now - ts) > TIMESTAMP_WINDOW_MS) {
            throw new Error('Timestamp fora da janela de aceitação (possível replay antigo)');
        }
        
        // Validar sender (se fornecido)
        if (expectedSender && from !== expectedSender) {
            throw new Error(`Sender inesperado: esperado ${expectedSender}, recebido ${from}`);
        }
        
        // Recriar AAD
        const aad = Buffer.concat([
            Buffer.from([v]),
            Buffer.from(ts.toString()),
            Buffer.from(from),
            Buffer.from(to),
            Buffer.from(nonce, 'hex')
        ]);

        const decipher = crypto.createDecipheriv('aes-128-gcm', key, Buffer.from(nonce, 'hex'));
        decipher.setAAD(aad);
        decipher.setAuthTag(Buffer.from(tag, 'hex'));
        
        const decrypted = Buffer.concat([
            decipher.update(Buffer.from(ct, 'hex')),
            decipher.final()
        ]).toString('utf8');
        
        return decrypted;
    } catch (error) {
        console.error('Erro ao validar/descriptografar envelope:', error.message);
        throw error;
    }
}

module.exports = {
    encryptMessage,
    decryptMessage
};


