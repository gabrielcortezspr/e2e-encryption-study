/**
 * ECDH (Elliptic Curve Diffie-Hellman) com logs educativos
 * Curva: secp256k1 (mesma do Bitcoin)
 *
 * Wrapper sobre crypto.createECDH que expõe cada etapa (chave privada,
 * chave pública, segredo compartilhado). O segredo bruto NÃO é usado como
 * chave: ele passa pelo HKDF (ver hkdf.js) antes de virar chave AES.
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
     * Gera par de chaves (privada + pública)
     */
    generateKeyPair() {
        if (this.debug) {
            console.log('=== ECDH Manual - Geracao de Chaves ===');
        }

        // Gerar chave privada aleatória (32 bytes)
        this.privateKey = crypto.randomBytes(32);
        
        if (this.debug) {
            console.log('1. Chave privada gerada:', this.privateKey.toString('hex'));
        }

        // Criar instância ECDH para calcular chave pública
        const ecdh = crypto.createECDH(this.curve);
        ecdh.setPrivateKey(this.privateKey);
        this.publicKey = ecdh.getPublicKey();

        if (this.debug) {
            console.log('2. Chave publica calculada:', this.publicKey.toString('hex'));
            console.log('3. Tamanho da chave publica:', this.publicKey.length, 'bytes');
        }

        return {
            privateKey: this.privateKey,
            publicKey: this.publicKey
        };
    }

    /**
     * Calcula chave compartilhada usando chave pública do outro participante
     */
    computeSharedSecret(otherPublicKey) {
        if (this.debug) {
            console.log('=== ECDH Manual - Calculo da Chave Compartilhada ===');
            console.log('1. Chave publica recebida:', otherPublicKey.toString('hex'));
        }

        if (!this.privateKey) {
            throw new Error('Chave privada não foi gerada. Execute generateKeyPair() primeiro.');
        }

        // Criar instância ECDH para calcular chave compartilhada
        const ecdh = crypto.createECDH(this.curve);
        ecdh.setPrivateKey(this.privateKey);
        
        const sharedSecret = ecdh.computeSecret(otherPublicKey);

        if (this.debug) {
            console.log('2. Chave compartilhada calculada:', sharedSecret.toString('hex'));
            console.log('3. Tamanho da chave compartilhada:', sharedSecret.length, 'bytes');
        }

        return sharedSecret;
    }

    /**
     * Retorna informações das chaves para debug
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

