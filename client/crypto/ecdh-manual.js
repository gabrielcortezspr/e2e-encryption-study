/**
 * ECDH (Elliptic Curve Diffie-Hellman) with educational logs
 * Curve: secp256k1 (the same one Bitcoin uses)
 *
 * Thin wrapper around crypto.createECDH that exposes each step (private key,
 * public key, shared secret). The raw shared secret is NOT used as a key:
 * it goes through HKDF (see hkdf.js) before becoming an AES key.
 */

const crypto = require('crypto');

class ECDHManual {
    constructor(debug = false) {
        this.debug = debug;
        this.curve = 'secp256k1';
        this.privateKey = null;
        this.publicKey = null;
    }

    /**
     * Generates a key pair (private + public)
     */
    generateKeyPair() {
        if (this.debug) {
            console.log('=== ECDH - Key Generation ===');
        }

        // Random 32-byte private key
        this.privateKey = crypto.randomBytes(32);

        if (this.debug) {
            console.log('1. Private key generated:', this.privateKey.toString('hex'));
        }

        // Derive the public key from the private key
        const ecdh = crypto.createECDH(this.curve);
        ecdh.setPrivateKey(this.privateKey);
        this.publicKey = ecdh.getPublicKey();

        if (this.debug) {
            console.log('2. Public key computed:', this.publicKey.toString('hex'));
            console.log('3. Public key size:', this.publicKey.length, 'bytes');
        }

        return {
            privateKey: this.privateKey,
            publicKey: this.publicKey
        };
    }

    /**
     * Computes the shared secret from the other party's public key
     */
    computeSharedSecret(otherPublicKey) {
        if (this.debug) {
            console.log('=== ECDH - Shared Secret ===');
            console.log('1. Received public key:', otherPublicKey.toString('hex'));
        }

        if (!this.privateKey) {
            throw new Error('Private key not generated. Call generateKeyPair() first.');
        }

        const ecdh = crypto.createECDH(this.curve);
        ecdh.setPrivateKey(this.privateKey);

        const sharedSecret = ecdh.computeSecret(otherPublicKey);

        if (this.debug) {
            console.log('2. Shared secret computed:', sharedSecret.toString('hex'));
            console.log('3. Shared secret size:', sharedSecret.length, 'bytes');
        }

        return sharedSecret;
    }

    /**
     * Returns key information for debugging
     */
    getKeyInfo() {
        return {
            hasPrivateKey: !!this.privateKey,
            hasPublicKey: !!this.publicKey,
            privateKeyHex: this.privateKey ? this.privateKey.toString('hex') : null,
            publicKeyHex: this.publicKey ? this.publicKey.toString('hex') : null,
            curve: this.curve
        };
    }
}

module.exports = ECDHManual;
