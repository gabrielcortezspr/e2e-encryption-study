#!/usr/bin/env node
/**
 * Utilitário para descriptografar mensagens manualmente
 * Uso: node utils/decrypt.js <chave_hex> <texto_criptografado_hex>
 */

const crypto = require('crypto');

/**
 * Descriptografa uma mensagem usando AES-128-ECB
 * Mesma implementação usada no servidor
 */
function decryptMessage(encryptedHex, keyHex) {
    try {
        // Validar comprimento da chave
        if (keyHex.length !== 32) {
            throw new Error(`Chave deve ter exatamente 32 caracteres hex (recebido: ${keyHex.length}). Chave: ${keyHex}`);
        }

        // Validar comprimento do texto criptografado (deve ser par para hex)
        if (encryptedHex.length % 2 !== 0) {
            // Se faltar apenas um caractere, tentar automaticamente
            if (encryptedHex.length === 31 || encryptedHex.length === 33) {
                throw new Error(`TEXT_INCOMPLETE:${encryptedHex}`);
            }
            
            let errorMsg = `Texto criptografado deve ter comprimento par em hex (recebido: ${encryptedHex.length} caracteres, esperado: numero par).\n`;
            errorMsg += `Texto recebido: ${encryptedHex}\n`;
            errorMsg += `\nDica: Verifique se copiou o texto completo. O texto criptografado pode ter sido cortado.`;
            throw new Error(errorMsg);
        }

        // Converter chave de hex para Buffer
        const key = Buffer.from(keyHex, 'hex');
        
        if (key.length !== 16) {
            throw new Error(`Chave deve ter exatamente 16 bytes após conversão (recebido: ${key.length} bytes)`);
        }

        // Validar se o texto criptografado é válido em hex
        if (!/^[0-9a-fA-F]+$/.test(encryptedHex)) {
            throw new Error('Texto criptografado contém caracteres inválidos. Deve conter apenas caracteres hexadecimais (0-9, a-f, A-F)');
        }

        // Descriptografar usando AES-128-ECB (simulado com CBC e IV zero)
        // Node.js não suporta ECB diretamente, então usamos CBC com IV zero
        const iv = Buffer.alloc(16, 0); // IV zero para simular ECB
        const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
        decipher.setAutoPadding(true); // Padding automático
        let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    } catch (error) {
        throw new Error(`Erro ao descriptografar: ${error.message}`);
    }
}

// Verificar argumentos
if (process.argv.length < 4) {
    console.log('Utilitario de Descriptografia');
    console.log('');
    console.log('Uso:');
    console.log('  node utils/decrypt.js <chave_hex> <texto_criptografado_hex>');
    console.log('');
    console.log('Exemplo:');
    console.log('  node utils/decrypt.js a1b2c3d4e5f6789012345678901234 14f7d0259a5c4414130b1bc537c0b3f6');
    console.log('');
    console.log('Dica: Use o modo debug para ver a chave e o texto criptografado');
    process.exit(1);
}

const keyHex = process.argv[2];
const encryptedHex = process.argv[3];

try {
    console.log('Descriptografando mensagem...');
    console.log(`   Chave (${keyHex.length} chars): ${keyHex}`);
    console.log(`   Texto criptografado (${encryptedHex.length} chars): ${encryptedHex}`);
    console.log('');
    
    // Validar argumentos antes de tentar descriptografar
    if (!keyHex || !encryptedHex) {
        throw new Error('Chave e texto criptografado sao obrigatorios');
    }

    // Remover espaços em branco se houver
    const cleanKeyHex = keyHex.trim();
    let cleanEncryptedHex = encryptedHex.trim();
    
    // Tentar descriptografar
    try {
        const decrypted = decryptMessage(cleanEncryptedHex, cleanKeyHex);
        console.log('Mensagem descriptografada:');
        console.log(`   "${decrypted}"`);
    } catch (decryptError) {
        // Se o erro indicar texto incompleto, tentar automaticamente
        if (decryptError.message.includes('TEXT_INCOMPLETE:')) {
            const incompleteText = decryptError.message.split('TEXT_INCOMPLETE:')[1];
            console.log('Texto criptografado parece estar incompleto (comprimento impar).');
            console.log('Tentando automaticamente adicionar caracteres faltantes...\n');
            
            // Tentar adicionar cada caractere hex possível
            const hexChars = '0123456789abcdef';
            let found = false;
            
            for (const char of hexChars) {
                try {
                    const testHex = incompleteText + char;
                    const testKey = Buffer.from(cleanKeyHex, 'hex');
                    const iv = Buffer.alloc(16, 0); // IV zero para simular ECB
                    const decipher = crypto.createDecipheriv('aes-128-cbc', testKey, iv);
                    decipher.setAutoPadding(true); // Padding automático
                    let testDecrypted = decipher.update(testHex, 'hex', 'utf8');
                    testDecrypted += decipher.final('utf8');
                    
                    // Se conseguiu descriptografar, mostrar resultado
                    console.log(`Texto corrigido automaticamente (adicionado '${char}' no final)`);
                    console.log(`   Texto completo: ${testHex}`);
                    console.log(`   Mensagem descriptografada: "${testDecrypted}"`);
                    found = true;
                    break;
                } catch (e) {
                    // Continuar tentando
                }
            }
            
            if (!found) {
                throw new Error(`Nao foi possivel corrigir automaticamente o texto. Verifique se copiou o texto completo.\nTexto recebido: ${incompleteText}`);
            }
        } else {
            throw decryptError;
        }
    }
    
} catch (error) {
    console.error('Erro:', error.message);
    console.log('');
    console.log('Dicas:');
    console.log('   - Verifique se copiou a chave completa (32 caracteres hex)');
    console.log('   - Verifique se copiou o texto criptografado completo');
    console.log('   - O texto criptografado deve ter comprimento par (numero par de caracteres)');
    console.log('   - Certifique-se de nao ter espacos ou caracteres extras');
    console.log('   - No modo debug, certifique-se de copiar o texto criptografado completo');
    process.exit(1);
}

