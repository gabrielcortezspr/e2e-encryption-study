const crypto = require('crypto');

/**
 * HKDF-SHA256 (RFC 5869)
 * Deriva chaves criptográficas a partir de um segredo compartilhado
 * @param {Buffer} ikm - Input Keying Material (shared secret)
 * @param {Buffer|string} info - Context/application-specific info
 * @param {number} length - Comprimento da chave derivada em bytes
 * @param {Buffer|null} salt - Salt opcional (16 bytes recomendado)
 * @returns {Buffer} - Chave derivada
 */
function hkdf(ikm, info, length = 16, salt = null) {
    if (!Buffer.isBuffer(ikm)) {
        throw new Error('IKM deve ser Buffer');
    }
    
    // Usa salt padrão se não fornecido (RFC 5869 recomenda)
    const actualSalt = salt || Buffer.alloc(32, 0);
    
    // Extract: PRK = HMAC-SHA256(salt, IKM)
    const prk = crypto.createHmac('sha256', actualSalt).update(ikm).digest();
    
    // Expand: gerar blocos T(1), T(2), ... até ter bytes suficientes
    const infoBuffer = Buffer.isBuffer(info) ? info : Buffer.from(info, 'utf8');
    const blocks = [];
    let prev = Buffer.alloc(0);
    const iterations = Math.ceil(length / 32); // SHA256 = 32 bytes
    
    for (let i = 1; i <= iterations; i++) {
        prev = crypto.createHmac('sha256', prk)
            .update(prev)
            .update(infoBuffer)
            .update(Buffer.from([i]))
            .digest();
        blocks.push(prev);
    }
    
    return Buffer.concat(blocks).subarray(0, length);
}

/**
 * Deriva chaves de sessão a partir do segredo compartilhado ECDH
 * @param {Buffer} sharedSecret - Segredo ECDH
 * @param {string} context - Contexto (ex: 'peer1:peer2')
 * @param {boolean} debugMode - Se true, exibe logs detalhados
 * @returns {{encKey: Buffer, authKey: Buffer}} - Chaves de cifra (16 bytes) e autenticação (32 bytes)
 */
function deriveSessionKeys(sharedSecret, context = 'IDEA-MSG-V1', debugMode = false) {
    if (debugMode) {
        console.log('🔑 [HKDF] Derivando chaves de sessão...');
        console.log('   📥 IKM (shared secret):', sharedSecret.toString('hex').substring(0, 32) + '...');
        console.log('   📝 Info/Context:', context);
        console.log('   📏 Comprimento solicitado: 48 bytes');
    }
    
    // Derivar 48 bytes: 16 para AES-128 + 32 para possível HMAC/extensão futura
    const okm = hkdf(sharedSecret, context, 48);
    
    const encKey = okm.subarray(0, 16);   // AES-128-GCM
    const authKey = okm.subarray(16, 48); // Reservado
    
    if (debugMode) {
        console.log('   ✓ Derivação HKDF-SHA256 completa');
        console.log('   🔐 encKey (16 bytes):', encKey.toString('hex'));
        console.log('   🔐 authKey (32 bytes):', authKey.toString('hex').substring(0, 32) + '...');
        console.log('   💡 encKey será usada para AES-128-GCM');
    }
    
    return {
        encKey,
        authKey
    };
}

module.exports = {
    hkdf,
    deriveSessionKeys
};
