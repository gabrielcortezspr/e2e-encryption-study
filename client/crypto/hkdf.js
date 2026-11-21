const crypto = require('crypto');

/**
 * HKDF-SHA256 (RFC 5869)
 * Derives cryptographic keys from a shared secret
 * @param {Buffer} ikm - Input Keying Material (shared secret)
 * @param {Buffer|string} info - Context/application-specific info
 * @param {number} length - Length of the derived key in bytes
 * @param {Buffer|null} salt - Optional salt (defaults to 32 zero bytes, as in the RFC)
 * @returns {Buffer} - Derived key
 */
function hkdf(ikm, info, length = 16, salt = null) {
    if (!Buffer.isBuffer(ikm)) {
        throw new Error('IKM must be a Buffer');
    }

    const actualSalt = salt || Buffer.alloc(32, 0);

    // Extract: PRK = HMAC-SHA256(salt, IKM)
    const prk = crypto.createHmac('sha256', actualSalt).update(ikm).digest();

    // Expand: T(1), T(2), ... until there are enough bytes
    const infoBuffer = Buffer.isBuffer(info) ? info : Buffer.from(info, 'utf8');
    const blocks = [];
    let prev = Buffer.alloc(0);
    const iterations = Math.ceil(length / 32); // SHA-256 = 32 bytes

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
 * Derives session keys from the ECDH shared secret
 * @param {Buffer} sharedSecret - ECDH secret
 * @param {string} context - Context (e.g. 'alice:bob', sorted)
 * @param {boolean} debugMode - If true, prints detailed logs
 * @returns {{encKey: Buffer, authKey: Buffer}} - Encryption key (16 bytes) and reserved key (32 bytes)
 */
function deriveSessionKeys(sharedSecret, context = 'E2E-MSG-V1', debugMode = false) {
    if (debugMode) {
        console.log('│ ► Deriving session key...');
        console.log(`│   Context: ${context}`);
    }

    // 48 bytes: 16 for the AES-128-GCM key + 32 reserved (authKey, currently unused)
    const okm = hkdf(sharedSecret, context, 48);

    const encKey = okm.subarray(0, 16);   // AES-128-GCM
    const authKey = okm.subarray(16, 48); // Reserved

    if (debugMode) {
        console.log(`│ ✓ Session key derived (${encKey.length} bytes)`);
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
