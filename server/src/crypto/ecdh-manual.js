/**
 * Implementação Manual do ECDH (Elliptic Curve Diffie-Hellman)
 * Versão educativa que mostra cada etapa do processo
 * Curva: secp256k1 (mesma do Bitcoin)
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
     * Deriva chave final para uso no IDEA (128 bits)
     */
    deriveIDEAKey(sharedSecret) {
        if (this.debug) {
            console.log('=== ECDH Manual - Derivacao da Chave IDEA ===');
            console.log('1. Chave compartilhada (entrada):', sharedSecret.toString('hex'));
        }

        // Usar SHA-256 para derivar chave de 128 bits
        const hash = crypto.createHash('sha256').update(sharedSecret).digest();
        const ideaKey = hash.slice(0, 16); // Primeiros 16 bytes (128 bits)

        if (this.debug) {
            console.log('2. Hash SHA-256:', hash.toString('hex'));
            console.log('3. Chave IDEA (128 bits):', ideaKey.toString('hex'));
        }

        return ideaKey;
    }

    /**
     * Processo completo: gera chaves e calcula chave compartilhada
     */
    performKeyExchange(otherPublicKey) {
        if (this.debug) {
            console.log('=== ECDH Manual - Troca de Chaves Completa ===');
        }

        // Se não temos chaves, gerar
        if (!this.privateKey || !this.publicKey) {
            this.generateKeyPair();
        }

        // Calcular chave compartilhada
        const sharedSecret = this.computeSharedSecret(otherPublicKey);
        
        // Derivar chave para IDEA
        const ideaKey = this.deriveIDEAKey(sharedSecret);

        if (this.debug) {
            console.log('Troca de chaves ECDH concluida com sucesso!');
        }

        return {
            publicKey: this.publicKey,
            sharedSecret: sharedSecret,
            ideaKey: ideaKey
        };
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

