/**
 * Persistent Ed25519 identity + TOFU (Trust On First Use)
 *
 * - Each user has a long-term Ed25519 key pair stored on disk
 * - The ephemeral ECDH public key is signed with the Ed25519 key
 * - On first contact with a peer, the SHA-256 fingerprint of their Ed25519
 *   key is "pinned"; if it changes later, the connection is rejected
 *   (possible MITM)
 *
 * Files (git-ignored), per user, in client/.keys/ (or $KEYS_DIR):
 *   ed25519_keypair_<user>.json  - key pair (contains the PRIVATE key)
 *   pinned_keys_<user>.json      - TOFU fingerprints of known peers
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEYS_DIR = process.env.KEYS_DIR || path.join(__dirname, '..', '.keys');

let currentUsername = null;

function requireUsername(username) {
    const name = username || currentUsername;
    if (!name) {
        throw new Error('Username not set. Call setUsername() first.');
    }
    return name;
}

function ensureKeysDir() {
    if (!fs.existsSync(KEYS_DIR)) {
        fs.mkdirSync(KEYS_DIR, { recursive: true, mode: 0o700 });
    }
}

function fingerprintOf(ed25519PubHex) {
    return crypto.createHash('sha256').update(ed25519PubHex, 'hex').digest('hex');
}

/**
 * Path of the file holding the user's Ed25519 key pair
 */
function getKeypairFile(username) {
    return path.join(KEYS_DIR, `ed25519_keypair_${requireUsername(username)}.json`);
}

/**
 * Path of the file holding the user's TOFU pins
 */
function getTofuStore(username) {
    return path.join(KEYS_DIR, `pinned_keys_${requireUsername(username)}.json`);
}

/**
 * Sets the username used to name the key files
 * @param {string} username
 */
function setUsername(username) {
    currentUsername = username;
}

/**
 * Loads or generates the persistent Ed25519 key pair
 * @param {boolean} debugMode - If true, prints detailed logs
 * @returns {{publicKey: string, privateKey: string}} - DER keys (SPKI/PKCS#8), hex-encoded
 */
function ensureEd25519KeyPair(debugMode = false) {
    const KEYPAIR_FILE = getKeypairFile();
    try {
        if (fs.existsSync(KEYPAIR_FILE)) {
            const stored = JSON.parse(fs.readFileSync(KEYPAIR_FILE, 'utf8'));
            if (debugMode) {
                console.log('│ ✓ Identity key loaded');
                console.log(`│   ID: ${fingerprintOf(stored.publicKey).substring(0, 16)}...`);
            }
            return stored;
        }
    } catch (err) {
        console.warn('⚠️  Could not load existing identity key, generating a new one...', err.message);
    }

    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');

    const keypair = {
        publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
        privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex')
    };

    if (debugMode) {
        console.log('│ ✓ New identity key generated');
        console.log(`│   ID: ${fingerprintOf(keypair.publicKey).substring(0, 16)}...`);
    }

    // Persist (owner-only permissions: it contains the private key)
    try {
        ensureKeysDir();
        fs.writeFileSync(KEYPAIR_FILE, JSON.stringify(keypair, null, 2), { mode: 0o600 });
        console.log('✓ Ed25519 key pair generated and saved to', KEYPAIR_FILE);
    } catch (err) {
        console.error('❌ Error saving Ed25519 key:', err.message);
    }

    return keypair;
}

/**
 * Signs the ECDH public key with the Ed25519 private key
 * @param {string} ecdhPublicKeyHex - ECDH public key (hex)
 * @param {boolean} debugMode - If true, prints detailed logs
 * @returns {{ed25519Pub: string, ecdhPub: string, signature: string}}
 */
function signECDHPublicKey(ecdhPublicKeyHex, debugMode = false) {
    const keypair = ensureEd25519KeyPair(debugMode);

    if (debugMode) {
        console.log('│ ✓ Signing exchange key...');
    }

    const privateKey = crypto.createPrivateKey({
        key: Buffer.from(keypair.privateKey, 'hex'),
        format: 'der',
        type: 'pkcs8'
    });

    const signature = crypto.sign(null, Buffer.from(ecdhPublicKeyHex, 'hex'), privateKey);

    if (debugMode) {
        console.log(`│   Signature: ${signature.toString('hex').substring(0, 16)}...`);
    }

    return {
        ed25519Pub: keypair.publicKey,
        ecdhPub: ecdhPublicKeyHex,
        signature: signature.toString('hex')
    };
}

/**
 * Loads stored TOFU pins
 * @returns {Object} - Map peerId -> {fingerprint, ed25519PubHex, firstSeen}
 */
function loadPins() {
    const TOFU_STORE = getTofuStore();
    if (!fs.existsSync(TOFU_STORE)) {
        return {};
    }
    try {
        return JSON.parse(fs.readFileSync(TOFU_STORE, 'utf8'));
    } catch (err) {
        console.warn('Error reading TOFU pins:', err.message);
        return {};
    }
}

/**
 * Saves TOFU pins
 * @param {Object} pins
 */
function savePins(pins) {
    const TOFU_STORE = getTofuStore();
    try {
        ensureKeysDir();
        fs.writeFileSync(TOFU_STORE, JSON.stringify(pins, null, 2));
    } catch (err) {
        console.error('Error saving TOFU pins:', err.message);
    }
}

/**
 * Verifies the signature and applies TOFU (Trust On First Use)
 * @param {string} peerId - Peer identifier
 * @param {string} ed25519PubHex - Peer's Ed25519 public key (hex)
 * @param {string} ecdhPubHex - Peer's ECDH public key (hex)
 * @param {string} signatureHex - Signature over the ECDH key (hex)
 * @param {boolean} debugMode - If true, prints detailed logs
 * @throws {Error} - If the signature is invalid or the pin changed (possible MITM)
 */
function verifyAndPinPeer(peerId, ed25519PubHex, ecdhPubHex, signatureHex, debugMode = false) {
    if (debugMode) {
        console.log(`│ ► Verifying identity of ${peerId}...`);
    }

    // Signature
    const publicKey = crypto.createPublicKey({
        key: Buffer.from(ed25519PubHex, 'hex'),
        format: 'der',
        type: 'spki'
    });

    const isValid = crypto.verify(
        null,
        Buffer.from(ecdhPubHex, 'hex'),
        publicKey,
        Buffer.from(signatureHex, 'hex')
    );
    if (!isValid) {
        throw new Error(`❌ Invalid signature for peer ${peerId}`);
    }

    if (debugMode) {
        console.log('│ ✓ Digital signature verified');
    }

    // TOFU: check the pin
    const pins = loadPins();
    const fingerprint = fingerprintOf(ed25519PubHex);

    if (!pins[peerId]) {
        // First contact: pin it
        pins[peerId] = {
            fingerprint,
            ed25519PubHex,
            firstSeen: new Date().toISOString()
        };
        savePins(pins);

        console.log('┌─────────────────────────────────────────────────────────────┐');
        console.log(`│ 🔔 FIRST CONNECTION WITH ${peerId.padEnd(34)} │`);
        console.log('├─────────────────────────────────────────────────────────────┤');
        console.log('│ Trust On First Use (TOFU) - identity recorded               │');
        console.log(`│ Fingerprint: ${fingerprint.substring(0, 32)}...`.padEnd(62) + '│');
        console.log('│ This identity will be checked on future contacts.           │');
        console.log('│ If it changes, a security alert will be raised.             │');
        console.log('└─────────────────────────────────────────────────────────────┘');

        if (debugMode) {
            console.log(`│   Full fingerprint: ${fingerprint}`);
        }
    } else {
        if (pins[peerId].fingerprint !== fingerprint) {
            console.log('┌─────────────────────────────────────────────────────────────┐');
            console.log('│ ⚠️  SECURITY ALERT - IDENTITY CHANGED                        │');
            console.log('├─────────────────────────────────────────────────────────────┤');
            console.log(`│ User: ${peerId.padEnd(53)} │`);
            console.log('│ Expected fingerprint (stored):                              │');
            console.log(`│   ${pins[peerId].fingerprint.substring(0, 32)}...`.padEnd(62) + '│');
            console.log('│ Received fingerprint (new):                                 │');
            console.log(`│   ${fingerprint.substring(0, 32)}...`.padEnd(62) + '│');
            console.log('│ Possible causes:                                            │');
            console.log('│   • Man-in-the-Middle (MITM) attack                         │');
            console.log('│   • The peer reinstalled / deleted their ed25519_keypair    │');
            console.log('│ ❌ CONNECTION REJECTED                                      │');
            console.log('│ (if the change is legitimate, use /delete @user)            │');
            console.log('└─────────────────────────────────────────────────────────────┘');

            throw new Error(
                `TOFU: identity of ${peerId} changed! ` +
                `Expected: ${pins[peerId].fingerprint.substring(0, 16)}... ` +
                `Received: ${fingerprint.substring(0, 16)}...`
            );
        }

        if (debugMode) {
            console.log('│ ✓ Identity confirmed (valid TOFU pin)');
        } else {
            console.log(`✓ Identity of ${peerId} confirmed`);
        }
    }
}

/**
 * Returns the local Ed25519 public key
 * @returns {string} - Public key (hex)
 */
function getLocalEd25519PublicKey() {
    return ensureEd25519KeyPair().publicKey;
}

module.exports = {
    KEYS_DIR,
    getKeypairFile,
    getTofuStore,
    setUsername,
    ensureEd25519KeyPair,
    signECDHPublicKey,
    verifyAndPinPeer,
    getLocalEd25519PublicKey
};
