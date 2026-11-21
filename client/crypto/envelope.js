/**
 * Envelope v1: authenticated encryption (AEAD) with AES-128-GCM
 *
 * Envelope: { v, ts, from, to, isGroup, nonce, ct, tag }
 * - Confidentiality: AES-128-GCM with a random 96-bit nonce
 * - Integrity/authenticity: the GCM tag covers the ciphertext and, via AAD,
 *   the metadata (v, ts, from, to, nonce)
 * - Anti-replay: timestamp window (5 min) + cache of already accepted nonces
 */

const crypto = require('crypto');

const ENVELOPE_VERSION = 1;
const TIMESTAMP_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const nonceCache = new Map(); // Simple in-memory replay cache (per process)

/**
 * Builds the AAD (Additional Authenticated Data): authenticated, not encrypted
 */
function buildAAD(v, ts, from, to, nonce) {
    return Buffer.concat([
        Buffer.from([v]),
        Buffer.from(ts.toString()),
        Buffer.from(from),
        Buffer.from(to),
        nonce
    ]);
}

/**
 * Creates an encrypted v1 envelope with AES-128-GCM
 * @param {string} message - Plaintext message
 * @param {Buffer} key - Encryption key (16 bytes)
 * @param {string} sender - Sender identifier
 * @param {string} recipient - Recipient identifier (or group name)
 * @param {boolean} isGroup - Whether this is a group message
 * @param {boolean} debugMode - If true, prints detailed logs
 * @returns {Object} - Envelope {v, ts, from, to, isGroup, nonce, ct, tag}
 */
function encryptMessage(message, key, sender, recipient, isGroup = false, debugMode = false) {
    try {
        if (!Buffer.isBuffer(key) || key.length !== 16) {
            throw new Error('Key must be a 16-byte Buffer (128 bits)');
        }
        if (!sender || !recipient) {
            throw new Error('Sender and recipient are required');
        }

        const nonce = crypto.randomBytes(12); // 96 bits
        const timestamp = Date.now();
        const aad = buildAAD(ENVELOPE_VERSION, timestamp, sender, recipient, nonce);

        const cipher = crypto.createCipheriv('aes-128-gcm', key, nonce);
        cipher.setAAD(aad);

        const encrypted = Buffer.concat([
            cipher.update(message, 'utf8'),
            cipher.final()
        ]);

        const tag = cipher.getAuthTag();

        if (debugMode) {
            console.log('│ ✓ Message encrypted (AES-128-GCM)');
            console.log(`│   Authentication tag: ${tag.toString('hex').substring(0, 16)}...`);
        }

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
        console.error('❌ Error creating encrypted envelope:', error.message);
        throw error;
    }
}

/**
 * Validates and decrypts a v1 envelope
 * @param {Object} envelope - Received envelope
 * @param {Buffer} key - Encryption key (16 bytes)
 * @param {string} expectedSender - Expected sender (optional extra check)
 * @param {boolean} debugMode - If true, prints detailed logs
 * @returns {string} - Plaintext message
 * @throws {Error} - If any validation or integrity check fails
 */
function decryptMessage(envelope, key, expectedSender = null, debugMode = false) {
    try {
        if (!Buffer.isBuffer(key) || key.length !== 16) {
            throw new Error('Key must be a 16-byte Buffer (128 bits)');
        }

        if (debugMode) {
            console.log('│ ► Validating received envelope...');
        }

        // Structure
        const { v, ts, from, to, nonce, ct, tag } = envelope;
        if (!v || !ts || !from || !to || !nonce || !ct || !tag) {
            throw new Error('Incomplete or invalid envelope');
        }

        // Version
        if (v !== ENVELOPE_VERSION) {
            throw new Error(`Unsupported envelope version: ${v}`);
        }

        // Timestamp (acceptance window)
        const timeDiff = Math.abs(Date.now() - ts);
        if (timeDiff > TIMESTAMP_WINDOW_MS) {
            throw new Error('Timestamp outside the acceptance window (possible old replay)');
        }

        if (debugMode) {
            console.log(`│ ✓ Timestamp valid (${Math.floor(timeDiff / 1000)}s difference)`);
        }

        // Sender (if provided)
        if (expectedSender && from !== expectedSender) {
            throw new Error(`Unexpected sender: expected ${expectedSender}, got ${from}`);
        }

        // Replay detection (nonce already seen in this process)
        const nonceKey = `${from}:${nonce}`;
        if (nonceCache.has(nonceKey)) {
            throw new Error('Repeated nonce detected (possible replay attack)');
        }

        if (debugMode) {
            console.log('│ ✓ Nonce is unique (anti-replay)');
        }

        const nonceBuf = Buffer.from(nonce, 'hex');
        const decipher = crypto.createDecipheriv('aes-128-gcm', key, nonceBuf);
        decipher.setAAD(buildAAD(v, ts, from, to, nonceBuf));
        decipher.setAuthTag(Buffer.from(tag, 'hex'));

        const decrypted = Buffer.concat([
            decipher.update(Buffer.from(ct, 'hex')),
            decipher.final()
        ]).toString('utf8');

        // Only remember the nonce after the tag is verified, so a forged
        // envelope cannot "burn" the nonce of a legitimate message.
        rememberNonce(nonceKey, ts);

        if (debugMode) {
            console.log('│ ✓ Authentication tag verified');
            console.log('│ ✓ Message decrypted (AES-128-GCM)');
        }

        return decrypted;
    } catch (error) {
        console.error('❌ Error validating/decrypting envelope:', error.message);
        throw error;
    }
}

/**
 * Stores an accepted nonce, keeping the cache bounded
 */
function rememberNonce(nonceKey, ts) {
    nonceCache.set(nonceKey, ts);

    if (nonceCache.size > 10000) {
        const entries = Array.from(nonceCache.entries());
        entries.sort((a, b) => a[1] - b[1]);
        for (let i = 0; i < 5000; i++) {
            nonceCache.delete(entries[i][0]);
        }
    }
}

module.exports = {
    encryptMessage,
    decryptMessage,
    buildAAD,
    ENVELOPE_VERSION
};
