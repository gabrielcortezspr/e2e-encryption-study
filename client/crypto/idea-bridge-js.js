

const simpleCrypto = require('./simple-crypto');

class IDEABridgeJS {
    constructor() {
        this.isAvailable = true;
    }

    /**
     * Verifica se o bridge está disponível
     */
    async checkAvailability() {
        return {
            success: true,
            message: 'Bridge JavaScript IDEA disponível',
            type: 'javascript'
        };
    }

    /**
     * Criptografa mensagem usando IDEA
     */
    async encryptMessage(message, key) {
        try {
            if (!Buffer.isBuffer(key)) {
                throw new Error('Chave deve ser um Buffer');
            }

            if (key.length !== 16) {
                throw new Error('Chave deve ter 16 bytes (128 bits)');
            }

            const ciphertext = simpleCrypto.encryptMessage(message, key);
            return ciphertext;
        } catch (error) {
            console.error('Erro ao criptografar mensagem (JS):', error.message);
            throw error;
        }
    }

    /**
     * Descriptografa mensagem usando IDEA
     */
    async decryptMessage(ciphertext, key) {
        try {
            if (!Buffer.isBuffer(key)) {
                throw new Error('Chave deve ser um Buffer');
            }

            if (key.length !== 16) {
                throw new Error('Chave deve ter 16 bytes (128 bits)');
            }

            const message = simpleCrypto.decryptMessage(ciphertext, key);
            return message;
        } catch (error) {
            console.error('Erro ao descriptografar mensagem (JS):', error.message);
            throw error;
        }
    }

    /**
     * Testa a funcionalidade do bridge
     */
    async testConnection() {
        try {
            // Teste simples
            const testKey = Buffer.alloc(16, 0x13);
            const testMessage = 'Teste';
            
            console.log('🔍 Testando bridge JavaScript...');
            console.log('   Chave:', testKey.toString('hex'));
            console.log('   Mensagem:', testMessage);
            
            const encrypted = await this.encryptMessage(testMessage, testKey);
            console.log('   Criptografado:', encrypted.substring(0, 32) + '...');
            
            const decrypted = await this.decryptMessage(encrypted, testKey);
            console.log('   Descriptografado:', decrypted);
            
            if (decrypted === testMessage) {
                return {
                    success: true,
                    message: 'Bridge JavaScript IDEA funcionando corretamente',
                    data: {
                        testMessage,
                        encrypted: encrypted.substring(0, 20) + '...',
                        decrypted
                    }
                };
            } else {
                throw new Error(`Teste falhou: esperado "${testMessage}", obtido "${decrypted}"`);
            }
        } catch (error) {
            console.error('❌ Erro no teste:', error.message);
            return {
                success: false,
                message: 'Falha no teste do bridge JavaScript',
                error: error.message
            };
        }
    }

    /**
     * Retorna informações sobre o bridge
     */
    getInfo() {
        return {
            type: 'javascript',
            name: 'IDEA Bridge JavaScript',
            version: '1.0.0',
            description: 'Implementação nativa do algoritmo IDEA em JavaScript',
            features: [
                'Criptografia IDEA completa',
                'Modo ECB com padding PKCS#7',
                'Chaves de 128 bits',
                'Sem dependências externas'
            ]
        };
    }
}

module.exports = IDEABridgeJS;

