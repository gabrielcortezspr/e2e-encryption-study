/**
 * Identidade Ed25519 persistente + TOFU (Trust On First Use)
 *
 * - Cada usuário tem um par Ed25519 de longo prazo, salvo em disco
 * - A chave pública ECDH efêmera é assinada com a chave Ed25519
 * - No primeiro contato com um peer, o fingerprint (SHA-256) da chave Ed25519
 *   dele é "pinado"; se mudar depois, a conexão é rejeitada (possível MITM)
 *
 * Arquivos (fora do git), por usuário, em client/.keys/ (ou $KEYS_DIR):
 *   ed25519_keypair_<user>.json  - par de chaves (contém a chave PRIVADA)
 *   pinned_keys_<user>.json      - fingerprints TOFU dos peers conhecidos
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEYS_DIR = process.env.KEYS_DIR || path.join(__dirname, '..', '.keys');

let currentUsername = null;

function requireUsername(username) {
    const name = username || currentUsername;
    if (!name) {
        throw new Error('Username não configurado. Chame setUsername() primeiro.');
    }
    return name;
}

function ensureKeysDir() {
    if (!fs.existsSync(KEYS_DIR)) {
        fs.mkdirSync(KEYS_DIR, { recursive: true, mode: 0o700 });
    }
}

/**
 * Caminho do arquivo com o par Ed25519 do usuário
 */
function getKeypairFile(username) {
    return path.join(KEYS_DIR, `ed25519_keypair_${requireUsername(username)}.json`);
}

/**
 * Caminho do arquivo com os pins TOFU do usuário
 */
function getTofuStore(username) {
    return path.join(KEYS_DIR, `pinned_keys_${requireUsername(username)}.json`);
}

/**
 * Configura o username para os arquivos de chave
 * @param {string} username - Nome do usuário
 */
function setUsername(username) {
    currentUsername = username;
}

/**
 * Carrega ou gera par de chaves Ed25519 persistente
 * @param {boolean} debugMode - Se true, exibe logs detalhados
 * @returns {{publicKey: string, privateKey: string}} - Chaves em DER (SPKI/PKCS#8) codificadas em hex
 */
function ensureEd25519KeyPair(debugMode = false) {
    const KEYPAIR_FILE = getKeypairFile();
    try {
        if (fs.existsSync(KEYPAIR_FILE)) {
            const stored = JSON.parse(fs.readFileSync(KEYPAIR_FILE, 'utf8'));
            if (debugMode) {
                const fingerprint = crypto.createHash('sha256').update(stored.publicKey, 'hex').digest('hex');
                console.log('│ ✓ Chave de autenticação carregada');
                console.log(`│   ID: ${fingerprint.substring(0, 16)}...`);
            }
            return stored;
        }
    } catch (err) {
        console.warn('⚠️  Erro ao carregar chave de autenticação existente, gerando nova...', err.message);
    }
    
    // Gerar novo par
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    
    const keypair = {
        publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
        privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex')
    };
    
    if (debugMode) {
        const fingerprint = crypto.createHash('sha256').update(keypair.publicKey, 'hex').digest('hex');
        console.log('│ ✓ Nova chave de autenticação gerada');
        console.log(`│   ID: ${fingerprint.substring(0, 16)}...`);
    }
    
    // Persistir (somente o dono pode ler: contém a chave privada)
    try {
        ensureKeysDir();
        fs.writeFileSync(KEYPAIR_FILE, JSON.stringify(keypair, null, 2), { mode: 0o600 });
        console.log('✓ Par Ed25519 gerado e persistido em', KEYPAIR_FILE);
    } catch (err) {
        console.error('❌ Erro ao salvar chave Ed25519:', err.message);
    }
    
    return keypair;
}

/**
 * Assina a chave pública ECDH com a chave privada Ed25519
 * @param {string} ecdhPublicKeyHex - Chave pública ECDH em hex
 * @param {boolean} debugMode - Se true, exibe logs detalhados
 * @returns {{ed25519Pub: string, ecdhPub: string, signature: string}}
 */
function signECDHPublicKey(ecdhPublicKeyHex, debugMode = false) {
    const keypair = ensureEd25519KeyPair(debugMode);
    
    if (debugMode) {
        console.log('│ ✓ Assinando chave de troca...');
    }
    
    const privateKey = crypto.createPrivateKey({
        key: Buffer.from(keypair.privateKey, 'hex'),
        format: 'der',
        type: 'pkcs8'
    });
    
    const ecdhBytes = Buffer.from(ecdhPublicKeyHex, 'hex');
    const signature = crypto.sign(null, ecdhBytes, privateKey);
    
    if (debugMode) {
        console.log(`│   Assinatura: ${signature.toString('hex').substring(0, 16)}...`);
    }
    
    return {
        ed25519Pub: keypair.publicKey,
        ecdhPub: ecdhPublicKeyHex,
        signature: signature.toString('hex')
    };
}

/**
 * Carrega pins TOFU armazenados
 * @returns {Object} - Mapa peerId -> {fingerprint, ed25519PubHex, firstSeen}
 */
function loadPins() {
    const TOFU_STORE = getTofuStore();
    if (!fs.existsSync(TOFU_STORE)) {
        return {};
    }
    try {
        return JSON.parse(fs.readFileSync(TOFU_STORE, 'utf8'));
    } catch (err) {
        console.warn('Erro ao ler pins TOFU:', err.message);
        return {};
    }
}

/**
 * Salva pins TOFU
 * @param {Object} pins - Mapa de pins
 */
function savePins(pins) {
    const TOFU_STORE = getTofuStore();
    try {
        ensureKeysDir();
        fs.writeFileSync(TOFU_STORE, JSON.stringify(pins, null, 2));
    } catch (err) {
        console.error('Erro ao salvar pins TOFU:', err.message);
    }
}

/**
 * Verifica assinatura e aplica TOFU (Trust On First Use)
 * @param {string} peerId - Identificador do peer
 * @param {string} ed25519PubHex - Chave pública Ed25519 do peer (hex)
 * @param {string} ecdhPubHex - Chave pública ECDH do peer (hex)
 * @param {string} signatureHex - Assinatura da chave ECDH (hex)
 * @param {boolean} debugMode - Se true, exibe logs detalhados
 * @throws {Error} - Se assinatura inválida ou pin mudou (possível MITM)
 */
function verifyAndPinPeer(peerId, ed25519PubHex, ecdhPubHex, signatureHex, debugMode = false) {
    if (debugMode) {
        console.log(`│ ► Verificando identidade de ${peerId}...`);
    }
    
    // Verificar assinatura
    const publicKey = crypto.createPublicKey({
        key: Buffer.from(ed25519PubHex, 'hex'),
        format: 'der',
        type: 'spki'
    });
    
    const ecdhBytes = Buffer.from(ecdhPubHex, 'hex');
    const signature = Buffer.from(signatureHex, 'hex');
    
    const isValid = crypto.verify(null, ecdhBytes, publicKey, signature);
    if (!isValid) {
        throw new Error(`❌ Assinatura inválida para peer ${peerId}`);
    }
    
    if (debugMode) {
        console.log('│ ✓ Assinatura digital verificada');
    }
    
    // TOFU: verificar pin
    const pins = loadPins();
    const fingerprint = crypto.createHash('sha256').update(ed25519PubHex, 'hex').digest('hex');
    
    if (!pins[peerId]) {
        // Primeiro contato: pin
        pins[peerId] = {
            fingerprint,
            ed25519PubHex,
            firstSeen: new Date().toISOString()
        };
        savePins(pins);
        
        // Alerta visual para primeira conexão (TOFU)
        console.log('┌─────────────────────────────────────────────────────────────┐');
        console.log('│         🔔 PRIMEIRA CONEXÃO COM', peerId.padEnd(27), '│');
        console.log('├─────────────────────────────────────────────────────────────┤');
        console.log('│                                                             │');
        console.log('│ Trust On First Use (TOFU) - Identidade registrada          │');
        console.log('│                                                             │');
        console.log(`│ Fingerprint: ${fingerprint.substring(0, 32)}... │`);
        console.log('│                                                             │');
        console.log('│ Esta identidade será verificada em futuros contatos.       │');
        console.log('│ Se mudar, será emitido um alerta de segurança.             │');
        console.log('│                                                             │');
        console.log('└─────────────────────────────────────────────────────────────┘');
        
        if (debugMode) {
            console.log(`│   Fingerprint completo: ${fingerprint}`);
        }
    } else {
        // Verificar se pin mudou
        if (pins[peerId].fingerprint !== fingerprint) {
            // Alerta visual detalhado
            console.log('┌─────────────────────────────────────────────────────────────┐');
            console.log('│         ⚠️  ALERTA DE SEGURANÇA - IDENTIDADE MUDOU         │');
            console.log('├─────────────────────────────────────────────────────────────┤');
            console.log('│                                                             │');
            console.log(`│ Usuário: ${peerId.padEnd(52)} │`);
            console.log('│                                                             │');
            console.log('│ Fingerprint Esperado (armazenado):                          │');
            console.log(`│   ${pins[peerId].fingerprint.substring(0, 32)}...            │`);
            console.log('│                                                             │');
            console.log('│ Fingerprint Recebido (novo):                                │');
            console.log(`│   ${fingerprint.substring(0, 32)}...            │`);
            console.log('│                                                             │');
            console.log('│ Possíveis causas:                                           │');
            console.log(`│   • Ataque Man-in-the-Middle (MITM)                         │`);
            console.log(`│   • ${peerId} reinstalou o sistema                          │`);
            console.log(`│   • ${peerId} deletou arquivo ed25519_keypair               │`);
            console.log('│                                                             │');
            console.log('│ ❌ CONEXÃO REJEITADA POR SEGURANÇA                          │');
            console.log('│                                                             │');
            console.log('└─────────────────────────────────────────────────────────────┘');
            
            throw new Error(
                `TOFU: Identidade de ${peerId} mudou! ` +
                `Esperado: ${pins[peerId].fingerprint.substring(0, 16)}... ` +
                `Recebido: ${fingerprint.substring(0, 16)}...`
            );
        }
        
        if (debugMode) {
            console.log('│ ✓ Identidade confirmada (pin TOFU válido)');
        } else {
            console.log(`✓ Identidade de ${peerId} confirmada`);
        }
    }
}

/**
 * Obtém chave pública Ed25519 local
 * @returns {string} - Chave pública em hex
 */
function getLocalEd25519PublicKey() {
    const keypair = ensureEd25519KeyPair();
    return keypair.publicKey;
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
