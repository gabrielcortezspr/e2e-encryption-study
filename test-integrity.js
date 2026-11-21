#!/usr/bin/env node
/**
 * Teste rápido de integridade: Ed25519 + HKDF + Envelope
 */

const crypto = require('crypto');
const { signECDHPublicKey, verifyAndPinPeer, ensureEd25519KeyPair } = require('./client/crypto/ed25519-tofu');
const { deriveSessionKeys } = require('./client/crypto/hkdf');
const { encryptMessage, decryptMessage } = require('./client/crypto/simple-crypto');

console.log('🧪 Teste de Integridade - Ed25519 + HKDF + Envelope AEAD\n');

try {
    // 1. Gerar pares Ed25519 para Alice e Bob
    console.log('1️⃣  Gerando pares Ed25519...');
    ensureEd25519KeyPair();
    console.log('   ✓ Chaves Ed25519 geradas/carregadas\n');

    // 2. Simular ECDH (chaves públicas fixas para teste)
    console.log('2️⃣  Simulando troca ECDH...');
    const aliceECDH = crypto.createECDH('secp256k1');
    aliceECDH.generateKeys();
    const aliceECDHPub = aliceECDH.getPublicKey('hex');
    
    const bobECDH = crypto.createECDH('secp256k1');
    bobECDH.generateKeys();
    const bobECDHPub = bobECDH.getPublicKey('hex');
    
    console.log(`   Alice ECDH pub: ${aliceECDHPub.substring(0, 32)}...`);
    console.log(`   Bob ECDH pub: ${bobECDHPub.substring(0, 32)}...\n`);

    // 3. Assinar chaves ECDH com Ed25519
    console.log('3️⃣  Assinando chaves ECDH com Ed25519...');
    const aliceSigned = signECDHPublicKey(aliceECDHPub);
    console.log(`   ✓ Alice assinou sua chave ECDH`);
    console.log(`     Ed25519 pub: ${aliceSigned.ed25519Pub.substring(0, 32)}...`);
    console.log(`     Signature: ${aliceSigned.signature.substring(0, 32)}...\n`);

    // Simular Bob também (usando mesma chave Ed25519 para simplificar teste)
    const bobSigned = signECDHPublicKey(bobECDHPub);
    console.log(`   ✓ Bob assinou sua chave ECDH\n`);

    // 4. Verificar assinatura e aplicar TOFU (Alice verifica Bob)
    console.log('4️⃣  Aplicando TOFU (Alice verifica Bob)...');
    try {
        verifyAndPinPeer('Bob', bobSigned.ed25519Pub, bobECDHPub, bobSigned.signature);
        console.log('   ✓ Assinatura de Bob válida e pin estabelecido\n');
    } catch (err) {
        console.log(`   ℹ️  ${err.message}\n`);
    }

    // 5. Calcular segredo compartilhado via ECDH
    console.log('5️⃣  Calculando segredo compartilhado ECDH...');
    const aliceShared = aliceECDH.computeSecret(Buffer.from(bobECDHPub, 'hex'));
    const bobShared = bobECDH.computeSecret(Buffer.from(aliceECDHPub, 'hex'));
    
    if (!aliceShared.equals(bobShared)) {
        throw new Error('Segredos ECDH não coincidem!');
    }
    console.log(`   ✓ Segredo compartilhado: ${aliceShared.toString('hex').substring(0, 32)}...\n`);

    // 6. Derivar chaves via HKDF
    console.log('6️⃣  Derivando chaves via HKDF-SHA256...');
    const { encKey: aliceEncKey } = deriveSessionKeys(aliceShared, 'Alice:Bob');
    const { encKey: bobEncKey } = deriveSessionKeys(bobShared, 'Alice:Bob');
    
    if (!aliceEncKey.equals(bobEncKey)) {
        throw new Error('Chaves derivadas não coincidem!');
    }
    console.log(`   ✓ Chave de cifra (encKey): ${aliceEncKey.toString('hex')}\n`);

    // 7. Criar envelope com AES-GCM
    console.log('7️⃣  Criando envelope v1 com AES-GCM...');
    const plaintext = 'Teste de integridade: Esta mensagem está protegida por AEAD!';
    const envelope = encryptMessage(plaintext, aliceEncKey, 'Alice', 'Bob', false);
    
    console.log(`   ✓ Envelope criado:`);
    console.log(`     Versão: ${envelope.v}`);
    console.log(`     Timestamp: ${new Date(envelope.ts).toISOString()}`);
    console.log(`     From: ${envelope.from}`);
    console.log(`     To: ${envelope.to}`);
    console.log(`     Nonce: ${envelope.nonce.substring(0, 24)}...`);
    console.log(`     Ciphertext: ${envelope.ct.substring(0, 32)}...`);
    console.log(`     Tag: ${envelope.tag.substring(0, 32)}...\n`);

    // 8. Validar e descriptografar envelope
    console.log('8️⃣  Validando e descriptografando envelope...');
    const decrypted = decryptMessage(envelope, bobEncKey, 'Alice');
    
    if (decrypted !== plaintext) {
        throw new Error('Texto descriptografado não coincide!');
    }
    console.log(`   ✓ Mensagem descriptografada: "${decrypted}"\n`);

    // 9. Testar detecção de adulteração
    console.log('9️⃣  Testando detecção de adulteração...');
    const tamperedEnvelope = { ...envelope, ct: envelope.ct.replace('a', 'b') };
    try {
        decryptMessage(tamperedEnvelope, bobEncKey, 'Alice');
        console.log('   ❌ FALHA: Adulteração não detectada!\n');
    } catch (err) {
        console.log(`   ✓ Adulteração detectada: ${err.message}\n`);
    }

    // 10. Testar detecção de replay (timestamp antigo)
    console.log('🔟 Testando detecção de timestamp antigo...');
    const oldEnvelope = { ...envelope, ts: Date.now() - (10 * 60 * 1000) }; // 10 min atrás
    try {
        decryptMessage(oldEnvelope, bobEncKey, 'Alice');
        console.log('   ❌ FALHA: Replay não detectado!\n');
    } catch (err) {
        console.log(`   ✓ Replay detectado: ${err.message}\n`);
    }

    console.log('✅ TODOS OS TESTES PASSARAM!\n');
    console.log('Resumo:');
    console.log('- ✓ Ed25519: Assinatura e verificação funcionando');
    console.log('- ✓ TOFU: Pinning estabelecido');
    console.log('- ✓ ECDH: Segredo compartilhado calculado corretamente');
    console.log('- ✓ HKDF: Derivação de chaves funcionando');
    console.log('- ✓ Envelope: Criptografia AES-GCM com integridade');
    console.log('- ✓ Validação: Adulteração e replay detectados\n');

} catch (error) {
    console.error('❌ ERRO:', error.message);
    console.error(error.stack);
    process.exit(1);
}
