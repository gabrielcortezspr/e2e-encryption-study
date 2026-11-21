/**
 * Cliente WebSocket para comunicação com o servidor
 * End-to-End Encryption: Chaves privadas ficam apenas no cliente
 * Integridade: Ed25519 assinatura + TOFU pinning + HKDF + envelope AEAD
 */

const io = require('socket.io-client');
const EventEmitter = require('events');
const ECDHManual = require('../crypto/ecdh-manual');
const IDEABridgeJS = require('../crypto/idea-bridge-js');
const { setUsername, signECDHPublicKey, verifyAndPinPeer, ensureEd25519KeyPair } = require('../crypto/ed25519-tofu');
const { deriveSessionKeys } = require('../crypto/hkdf');

class WebSocketClient extends EventEmitter {
    constructor(serverUrl, username, debugMode = false) {
        super();
        this.serverUrl = serverUrl;
        this.username = username;
        this.socket = null;
        this.isConnected = false;
        this.publicKey = null;
        this.ecdh = null; // Instância ECDH do cliente
        this.ideaBridge = new IDEABridgeJS(); // Bridge IDEA para criptografia
        this.sharedKeys = new Map(); // Chaves compartilhadas (calculadas no cliente)
        this.groupKeys = new Map(); // Chaves de grupo
        this.debugMode = debugMode;
        this.processedKeys = new Set(); // Controlar chaves publicas ja processadas (evitar loops)
        
        // Configurar username para arquivos Ed25519 específicos
        setUsername(username);
    }

    /**
     * Conecta ao servidor
     * Gera chaves ECDH no cliente (chave privada fica apenas no cliente)
     * Assina chave ECDH com Ed25519 para autenticação
     */
    async connect() {
        return new Promise((resolve, reject) => {
            try {
                if (this.debugMode) {
                    console.log('\n╔═══════════════════════════════════════════════════════════════╗');
                    console.log('║              🔐 PILARES DE SEGURANÇA - CONEXÃO               ║');
                    console.log('╚═══════════════════════════════════════════════════════════════╝');
                    console.log('\n┌─── PILAR: INTEGRIDADE ───────────────────────────────────────┐');
                }
                
                // Garantir par Ed25519 persistente (TOFU)
                ensureEd25519KeyPair(this.debugMode);
                
                // GERAR CHAVES ECDH NO CLIENTE (end-to-end encryption)
                if (this.debugMode) {
                    console.log('└──────────────────────────────────────────────────────────────┘');
                    console.log('\n┌─── PILAR: CONFIDENCIALIDADE ────────────────────────────────┐');
                }
                this.ecdh = new ECDHManual(false); // Não mostrar debug do ECDH aqui
                const keyPair = this.ecdh.generateKeyPair();
                this.publicKey = keyPair.publicKey.toString('hex');
                if (this.debugMode) {
                    console.log('│ ✓ Chaves ECDH geradas (privada mantida localmente)');
                }
                // privateKey fica apenas no cliente, nunca é enviado

                // Assinar chave pública ECDH com Ed25519
                if (this.debugMode) {
                    console.log('└──────────────────────────────────────────────────────────────┘');
                    console.log('\n┌─── PILAR: INTEGRIDADE (Autenticação de Chave) ──────────────┐');
                }
                const signedKey = signECDHPublicKey(this.publicKey, this.debugMode);
                if (this.debugMode) {
                    console.log('└──────────────────────────────────────────────────────────────┘\n');
                }

                // Conectar ao servidor
                this.socket = io(this.serverUrl, {
                    transports: ['websocket'],
                    timeout: 10000
                });

                // Evento de conexão
                this.socket.on('connect', () => {
                    if (!this.debugMode) {
                        console.log('✓ Conectado ao servidor WebSocket');
                    }
                    this.isConnected = true;
                    
                    // Enviar chave pública ECDH assinada + chave pública Ed25519
                    this.socket.emit('user_connect', {
                        username: this.username,
                        publicKey: this.publicKey, // Chave pública ECDH
                        ed25519Pub: signedKey.ed25519Pub, // Chave pública Ed25519
                        signature: signedKey.signature // Assinatura da chave ECDH
                    });
                });

                // Evento de desconexão
                this.socket.on('disconnect', () => {
                    console.log('Desconectado do servidor');
                    this.isConnected = false;
                });

                // Evento de erro
                this.socket.on('connect_error', (error) => {
                    console.error('Erro de conexao:', error.message);
                    reject(error);
                });

                // Configurar event handlers
                this.setupEventHandlers();

                // Resolver quando usuário for conectado
                this.socket.on('user_connected', (data) => {
                    // Servidor confirma que recebeu a chave pública
                    this.emit('user_connected', data);
                    resolve(data);
                });

            } catch (error) {
                reject(error);
            }
        });
    }

    /**
     * Configura event handlers
     */
    setupEventHandlers() {
        // Eventos do servidor
        this.socket.on('user_connected', (data) => {
            this.emit('user_connected', data);
        });

        this.socket.on('chat_started', (data) => {
            this.emit('chat_started', data);
        });

        this.socket.on('exchange_public_key', (data) => {
            // CALCULAR CHAVE COMPARTILHADA NO CLIENTE
            this.handleExchangePublicKey(data);
            this.emit('exchange_public_key', data);
        });

        this.socket.on('key_exchanged', (data) => {
            // Evento de confirmação (chave já foi calculada no handleExchangePublicKey)
            this.emit('key_exchanged', data);
        });

        this.socket.on('chat_ready', (data) => {
            this.emit('chat_ready', data);
        });

        this.socket.on('message_received', (data) => {
            // Descriptografar mensagem NO CLIENTE
            this.handleReceivedMessage(data);
        });

        this.socket.on('message_sent', (data) => {
            this.emit('message_sent', data);
        });

        this.socket.on('group_joined', (data) => {
            this.emit('group_joined', data);
        });

        this.socket.on('member_joined_group', (data) => {
            this.emit('member_joined_group', data);
        });

        this.socket.on('group_left', (data) => {
            // ✅ Limpar nossas chaves de grupo quando SAÍMOS
            if (data.groupName && data.clearGroupKey) {
                this.clearGroupKeys(data.groupName);
                if (this.debugMode) {
                    console.log(`🧹 Chaves do grupo ${data.groupName} limpas (você saiu)`);
                }
            }
            this.emit('group_left', data);
        });

        this.socket.on('member_left_group', (data) => {
            // ✅ Outro membro saiu: limpar chaves DAQUELE membro para permitir re-entrada
            if (data.groupName && data.leftMember) {
                this.clearMemberKeysFromGroup(data.groupName, data.leftMember);
                if (this.debugMode) {
                    console.log(`👋 ${data.leftMember} saiu do grupo ${data.groupName}`);
                    console.log(`   🧹 Chaves de ${data.leftMember} removidas do cache`);
                    console.log(`   Aguardando servidor solicitar regeneração da chave de grupo...`);
                }
            }
            this.emit('member_left_group', data);
        });

        this.socket.on('clear_group_key', (data) => {
            // ✅ Limpar chave quando você é o único membro restante
            if (data.groupName) {
                this.clearGroupKeys(data.groupName);
                if (this.debugMode) {
                    console.log(`🧹 Chave do grupo ${data.groupName} limpa: ${data.reason}`);
                }
            }
            this.emit('clear_group_key', data);
        });

        this.socket.on('users_list', (data) => {
            this.emit('users_list', data);
        });

        this.socket.on('groups_list', (data) => {
            this.emit('groups_list', data);
        });

        this.socket.on('chat_left', (data) => {
            this.emit('chat_left', data);
        });

        this.socket.on('user_joined', (data) => {
            this.emit('user_joined', data);
        });

        this.socket.on('user_left', (data) => {
            this.emit('user_left', data);
        });

        this.socket.on('error', (data) => {
            this.emit('error', data);
        });

        this.socket.on('group_key_distributed', (data) => {
            this.emit('group_key_distributed', data);
        });

        this.socket.on('generate_group_key', (data) => {
            // Gerar chave de grupo localmente (end-to-end) - metodo antigo (deprecated)
            this.generateGroupKey(data);
            this.emit('generate_group_key', data);
        });

        this.socket.on('generate_and_distribute_group_key', (data) => {
            // Gerar e distribuir chave de grupo (apenas para criador do grupo)
            this.generateAndDistributeGroupKey(data);
            this.emit('generate_and_distribute_group_key', data);
        });

        this.socket.on('group_key_received', (data) => {
            // Receber chave de grupo criptografada
            this.handleGroupKeyReceived(data);
            this.emit('group_key_received', data);
        });

        this.socket.on('group_message_received', (data) => {
            // Descriptografar mensagem de grupo NO CLIENTE
            this.handleReceivedGroupMessage(data);
        });
    }

    /**
     * Processa mensagem recebida (privada)
     * Valida e descriptografa envelope v1 NO CLIENTE (end-to-end)
     */
    async handleReceivedMessage(data) {
        const { from, envelope } = data;

        try {
            // Buscar chave compartilhada NO CLIENTE
            const sharedKey = this.sharedKeys.get(from);

            if (!sharedKey) {
                console.error(`Chave compartilhada nao encontrada para ${from}`);
                this.emit('error', {
                    message: `Chave compartilhada não encontrada para ${from}`,
                    type: 'NoSharedKey'
                });
                return;
            }

            // VALIDAR E DESCRIPTOGRAFAR ENVELOPE NO CLIENTE
            if (this.debugMode) {
                console.log(`\n┌─── PILAR: INTEGRIDADE (Validação) + CONFIDENCIALIDADE (Decifra) ───┐`);
            }
            const { decryptMessage } = require('../crypto/simple-crypto');
            const decrypted = decryptMessage(envelope, sharedKey, from, this.debugMode);
            if (this.debugMode) {
                console.log('└──────────────────────────────────────────────────────────────┘\n');
            }

            // Emitir evento com mensagem descriptografada
            this.emit('message_received', {
                from: from,
                message: decrypted, // Mensagem descriptografada
                envelope: envelope, // Mantém envelope para debug
                timestamp: envelope.ts || new Date().toISOString()
            });

        } catch (error) {
            console.error('Erro ao validar/descriptografar mensagem:', error.message);
            this.emit('error', {
                message: `Erro ao descriptografar mensagem de ${from}`,
                details: error.message,
                type: 'DecryptionError'
            });
        }
    }

    /**
     * Processa mensagem de grupo recebida
     * Valida e descriptografa envelope v1 NO CLIENTE (end-to-end)
     */
    async handleReceivedGroupMessage(data) {
        const { from, groupName, envelope } = data;

        try {
            // Buscar chave de grupo NO CLIENTE
            const groupKey = this.groupKeys.get(groupName);

            if (!groupKey) {
                console.error(`Chave de grupo nao encontrada para ${groupName}`);
                this.emit('error', {
                    message: `Chave de grupo não encontrada para ${groupName}`,
                    type: 'NoGroupKey'
                });
                return;
            }

            // VALIDAR E DESCRIPTOGRAFAR ENVELOPE NO CLIENTE
            if (this.debugMode) {
                console.log(`\n┌─── PILAR: INTEGRIDADE (Validação) + CONFIDENCIALIDADE (Decifra) ───┐`);
            }
            const { decryptMessage } = require('../crypto/simple-crypto');
            const decrypted = decryptMessage(envelope, groupKey, from, this.debugMode);
            if (this.debugMode) {
                console.log('└──────────────────────────────────────────────────────────────┘\n');
            }

            // Emitir evento com mensagem descriptografada
            this.emit('group_message_received', {
                from: from,
                groupName: groupName,
                message: decrypted, // Mensagem descriptografada
                envelope: envelope, // Mantém envelope para debug
                timestamp: envelope.ts || new Date().toISOString()
            });

        } catch (error) {
            console.error('Erro ao validar/descriptografar mensagem de grupo:', error.message);
            this.emit('error', {
                message: `Erro ao descriptografar mensagem de grupo de ${from}`,
                details: error.message,
                type: 'GroupDecryptionError'
            });
        }
    }

    /**
     * Inicia chat com usuário
     */
    startChat(targetUser) {
        if (!this.isConnected) {
            throw new Error('Não conectado ao servidor');
        }

        this.socket.emit('start_chat', {
            targetUser: targetUser
        });
    }

    /**
     * Processa troca de chave pública recebida do servidor
     * Verifica assinatura Ed25519 (TOFU), calcula chave compartilhada NO CLIENTE (end-to-end)
     * Deriva chaves via HKDF
     * EVITA LOOPS: Nao reenvia a chave publica (servidor ja fez o roteamento inicial)
     */
    handleExchangePublicKey(data) {
        const { targetUser, publicKey, ed25519Pub, signature, isGroup, groupName } = data;

        if (!this.ecdh) {
            console.error('ECDH nao inicializado');
            return;
        }

        if (!publicKey) {
            console.error('Chave publica nao fornecida');
            return;
        }

        // Verificar campos de autenticação
        if (!ed25519Pub || !signature) {
            console.error(`⚠️  Peer ${targetUser} não enviou assinatura Ed25519. Conexão rejeitada.`);
            this.emit('error', {
                message: `Peer ${targetUser} não enviou credenciais de autenticação`,
                type: 'MissingAuthentication'
            });
            return;
        }

        // VERIFICAR SE JA PROCESSAMOS ESTA CHAVE (evitar loops)
        // Para grupos, incluir groupName no keyId para permitir re-processamento após saída/entrada
        const keyId = groupName 
            ? `${groupName}:${targetUser}:${publicKey.substring(0, 16)}`
            : `${targetUser}:${publicKey.substring(0, 16)}`;
        
        if (this.processedKeys.has(keyId)) {
            if (this.debugMode) {
                console.log(`Chave publica de ${targetUser} ja foi processada, ignorando...`);
            }
            return; // Já processamos esta chave, evitar loop
        }
        this.processedKeys.add(keyId);

        try {
            if (this.debugMode) {
                console.log('\n╔═══════════════════════════════════════════════════════════════╗');
                console.log(`║         🔐 PILARES DE SEGURANÇA - Troca com ${targetUser.padEnd(14)}║`);
                console.log('╚═══════════════════════════════════════════════════════════════╝');
                console.log('\n┌─── PILAR: INTEGRIDADE (Verificação de Identidade) ──────────┐');
            }
            
            // Verificar assinatura Ed25519 e aplicar TOFU pinning
            verifyAndPinPeer(targetUser, ed25519Pub, publicKey, signature, this.debugMode);

            if (this.debugMode) {
                console.log('└──────────────────────────────────────────────────────────────┘');
                console.log('\n┌─── PILAR: CONFIDENCIALIDADE (Estabelecimento de Chave) ─────┐');
            }

            // Converter chave publica de hex para Buffer
            const publicKeyBuffer = Buffer.from(publicKey, 'hex');

            // CALCULAR CHAVE COMPARTILHADA NO CLIENTE
            const sharedSecret = this.ecdh.computeSharedSecret(publicKeyBuffer);
            if (this.debugMode) {
                console.log('│ ✓ Shared secret ECDH computado');
            }
            
            // Derivar chaves via HKDF (contexto único por par)
            const context = [this.username, targetUser].sort().join(':');
            const { encKey } = deriveSessionKeys(sharedSecret, context, this.debugMode);
            
            if (this.debugMode) {
                console.log('└──────────────────────────────────────────────────────────────┘');
            }
            
            // Compatibilidade: manter ideaKey para bridge legado (temporário)
            const ideaKey = encKey;

            // ARMAZENAR CHAVE COMPARTILHADA NO CLIENTE
            if (isGroup && groupName) {
                // Para grupos, armazenar com chave única incluindo grupo
                // Armazenar em ambas as ordens para facilitar busca
                this.sharedKeys.set(`${groupName}:${targetUser}`, ideaKey);
                // Também armazenar com nosso username para busca reversa
                // (o outro cliente vai usar nosso username como chave)
            } else {
                this.sharedKeys.set(targetUser, ideaKey);
            }

            // REMOVIDO: Nao reenviar chave publica de volta
            // O servidor ja fez o roteamento inicial no handleStartChat
            // Reenviar criaria um loop infinito!

            if (!this.debugMode) {
                console.log(`✓ Chave de sessão estabelecida com ${targetUser}`);
            }

        } catch (error) {
            console.error('Erro ao calcular chave compartilhada:', error.message);
            // Remover da lista de processadas em caso de erro
            this.processedKeys.delete(keyId);
        }
    }

    /**
     * Troca chave pública com outro usuário
     * (Mantido para compatibilidade, mas agora a lógica principal está em handleExchangePublicKey)
     */
    exchangePublicKey(targetUser, publicKey, options = {}) {
        // Esta função agora apenas notifica o servidor
        // O cálculo da chave compartilhada é feito em handleExchangePublicKey
        if (!this.isConnected) {
            throw new Error('Não conectado ao servidor');
        }

        const { isGroup = false, groupName = null } = options;

        this.socket.emit('exchange_public_key', {
            targetUser: targetUser,
            publicKey: publicKey || this.publicKey,
            isGroup: isGroup,
            groupName: groupName
        });
    }

    /**
     * Armazena chave de grupo
     */
    storeGroupKey(groupName, groupKey) {
        this.groupKeys.set(groupName, Buffer.from(groupKey, 'hex'));
    }

    /**
     * Gera chave de grupo localmente a partir das chaves compartilhadas
     * End-to-End: Chave de grupo é calculada no cliente
     * 
     * IMPORTANTE: Cada cliente só tem as chaves compartilhadas que ele calculou.
     * Por exemplo, se o grupo tem [João, Jose, Aline]:
     * - João tem: chaves com Jose e Aline
     * - Jose tem: chaves com João e Aline
     * - Aline tem: chaves com João e Jose
     * 
     * Para gerar a mesma chave de grupo, todos devem usar TODAS as chaves compartilhadas
     * do grupo. Como cada cliente só tem suas próprias chaves, precisamos de uma abordagem diferente.
     * 
     * SOLUÇÃO: Usar apenas as chaves que este cliente tem (com os outros membros).
     * A chave de grupo será o XOR de todas as chaves compartilhadas que este cliente calculou.
     * 
     * NOTA: Isso funciona porque cada par de usuários tem a MESMA chave compartilhada (ECDH),
     * então quando fazemos XOR, a ordem não importa e todos chegam à mesma chave final.
     */
    generateGroupKey(data) {
        const { groupName, members, expectedPairs } = data;

        if (!groupName || !members) {
            console.error('Dados insuficientes para gerar chave de grupo');
            return;
        }

        try {
            // Coletar TODAS as chaves compartilhadas que este cliente tem com outros membros do grupo
            const sharedKeys = [];
            const ourUsername = this.username;
            
            // Percorrer todos os membros do grupo
            for (const member of members) {
                // Pular nós mesmos
                if (member === ourUsername) {
                    continue;
                }
                
                // Buscar chave compartilhada com este membro
                // A chave está armazenada como `${groupName}:${member}`
                const keyId = `${groupName}:${member}`;
                let sharedKey = this.sharedKeys.get(keyId);
                
                // Fallback: tentar sem o prefixo do grupo
                if (!sharedKey) {
                    sharedKey = this.sharedKeys.get(member);
                }
                
                if (sharedKey) {
                    sharedKeys.push(sharedKey);
                    if (this.debugMode) {
                        console.log(`   Chave compartilhada encontrada com ${member}: ${sharedKey.toString('hex').substring(0, 16)}...`);
                    }
                } else {
                    if (this.debugMode) {
                        console.log(`   Chave compartilhada NAO encontrada com ${member}`);
                        console.log(`      Tentando: ${keyId}, ${member}`);
                        console.log(`      Chaves disponíveis: ${Array.from(this.sharedKeys.keys()).filter(k => k.includes(groupName) || k === member).join(', ')}`);
                    }
                }
            }

            // Verificar se temos chaves suficientes
            // Cada cliente deve ter (numero de membros - 1) chaves compartilhadas
            const expectedKeysForThisClient = members.length - 1;
            
            if (sharedKeys.length === 0) {
                console.error(`Nenhuma chave compartilhada encontrada para o grupo ${groupName}`);
                console.error(`   Esperado: ${expectedKeysForThisClient} chaves (uma para cada outro membro)`);
                return;
            }

            if (sharedKeys.length < expectedKeysForThisClient) {
                console.warn(`Chaves compartilhadas incompletas para o grupo ${groupName}`);
                console.warn(`   Encontradas: ${sharedKeys.length}, Esperadas: ${expectedKeysForThisClient}`);
                console.warn(`   A chave de grupo pode não funcionar corretamente!`);
            }

            if (this.debugMode) {
                console.log(`Gerando chave de grupo ${groupName}:`);
                console.log(`   Nossas chaves compartilhadas: ${sharedKeys.length} / ${expectedKeysForThisClient}`);
                console.log(`   Total de pares no grupo: ${expectedPairs}`);
            }

            // Gerar chave de grupo usando XOR de todas as chaves compartilhadas que temos
            // IMPORTANTE: Ordenar as chaves por nome do membro para garantir consistencia
            // Mas como estamos usando apenas nossas chaves (n-1 chaves), todos terao o mesmo conjunto
            const groupKey = Buffer.alloc(16); // 128 bits para IDEA
            
            sharedKeys.forEach(key => {
                if (key && key.length === 16) {
                    for (let i = 0; i < 16; i++) {
                        groupKey[i] ^= key[i];
                    }
                }
            });

            // Armazenar chave de grupo
            this.groupKeys.set(groupName, groupKey);

            if (this.debugMode) {
                console.log(`Chave de grupo ${groupName} gerada: ${groupKey.toString('hex')}`);
                console.log(`   Usando ${sharedKeys.length} chaves compartilhadas`);
            } else {
                console.log(`Chave de grupo ${groupName} gerada com sucesso!`);
            }

        } catch (error) {
            console.error(`Erro ao gerar chave de grupo ${groupName}:`, error.message);
        }
    }

    /**
     * Gera e distribui chave de grupo (apenas para criador do grupo)
     * End-to-End: Criador gera chave aleatoria e distribui criptografada
     */
    async generateAndDistributeGroupKey(data) {
        const { groupName, members } = data;

        if (!groupName || !members) {
            console.error('Dados insuficientes para gerar chave de grupo');
            return;
        }

        try {
            if (this.debugMode) {
                console.log('\n╔═══════════════════════════════════════════════════════════════╗');
                console.log(`║      🔐 CRIAÇÃO DE GRUPO: ${groupName.padEnd(35)}║`);
                console.log('╚═══════════════════════════════════════════════════════════════╝');
                console.log('\n┌─── PILAR: CONFIDENCIALIDADE ─────────────────────────────────┐');
            }
            
            // Gerar chave de grupo aleatoria (128 bits)
            const crypto = require('crypto');
            const groupKey = crypto.randomBytes(16);
            
            if (this.debugMode) {
                console.log('│ ► Gerando chave de grupo IDEA-128...');
                console.log(`│ ✓ Chave gerada: ${groupKey.toString('hex').substring(0, 16)}...`);
                console.log('│');
                console.log('│ ► Distribuindo chave para membros...');
            } else {
                console.log(`Gerando chave de grupo ${groupName}...`);
            }

            // Criptografar chave de grupo para cada membro usando suas chaves compartilhadas
            const encryptedKeys = [];
            
            for (const member of members) {
                if (member === this.username) {
                    // Para nós mesmos, armazenar a chave diretamente
                    this.groupKeys.set(groupName, groupKey);
                    continue;
                }

                // Buscar chave compartilhada com este membro
                const sharedKeyId = `${groupName}:${member}`;
                let sharedKey = this.sharedKeys.get(sharedKeyId);
                
                if (!sharedKey) {
                    sharedKey = this.sharedKeys.get(member);
                }

                if (!sharedKey) {
                    console.error(`Chave compartilhada nao encontrada com ${member}`);
                    continue;
                }

                // Criptografar chave de grupo usando a chave compartilhada com envelope
                const { encryptMessage } = require('../crypto/simple-crypto');
                const envelope = encryptMessage(
                    groupKey.toString('hex'),
                    sharedKey,
                    this.username,
                    member,
                    false,
                    false // Sem debug para não poluir
                );

                encryptedKeys.push({
                    member: member,
                    encryptedKey: envelope
                });

                if (this.debugMode) {
                    console.log(`│ ✓ Chave criptografada para ${member}`);
                }
            }

            // Armazenar chave de grupo para nós mesmos
            this.groupKeys.set(groupName, groupKey);

            if (this.debugMode) {
                console.log('└──────────────────────────────────────────────────────────────┘');
                console.log('\n┌─── PILAR: INTEGRIDADE ───────────────────────────────────────┐');
                console.log('│ ✓ Cada envelope contém tag de autenticação');
                console.log('│ ✓ Proteção contra replay e adulteração');
                console.log('└──────────────────────────────────────────────────────────────┘\n');
            }

            // Enviar chaves criptografadas para o servidor distribuir
            this.socket.emit('distribute_group_key', {
                groupName: groupName,
                encryptedKeys: encryptedKeys
            });

            if (this.debugMode) {
                console.log(`✓ Grupo '${groupName}' criado com ${encryptedKeys.length + 1} membros\n`);
            } else {
                console.log(`Chave de grupo ${groupName} gerada e distribuida para ${encryptedKeys.length} membros`);
            }

        } catch (error) {
            console.error(`Erro ao gerar e distribuir chave de grupo ${groupName}:`, error.message);
        }
    }

    /**
     * Processa chave de grupo recebida (criptografada)
     * End-to-End: Descriptografa chave de grupo usando chave compartilhada
     */
    async handleGroupKeyReceived(data) {
        const { groupName, encryptedKey, from } = data;

        try {
            if (this.debugMode) {
                console.log('\n╔═══════════════════════════════════════════════════════════════╗');
                console.log(`║      📥 RECEBENDO CHAVE DE GRUPO: ${groupName.padEnd(27)}║`);
                console.log('╚═══════════════════════════════════════════════════════════════╝');
                console.log('\n┌─── PILAR: INTEGRIDADE + CONFIDENCIALIDADE ───────────────────┐');
            }
            
            // Buscar chave compartilhada com o criador do grupo
            const sharedKeyId = `${groupName}:${from}`;
            let sharedKey = this.sharedKeys.get(sharedKeyId);
            
            if (!sharedKey) {
                sharedKey = this.sharedKeys.get(from);
            }

            if (!sharedKey) {
                console.error(`Chave compartilhada nao encontrada com ${from} para descriptografar chave de grupo`);
                return;
            }

            if (this.debugMode) {
                console.log(`│ ► Descriptografando chave recebida de ${from}...`);
            }

            // Descriptografar chave de grupo do envelope
            const { decryptMessage } = require('../crypto/simple-crypto');
            const groupKeyHex = decryptMessage(encryptedKey, sharedKey, from, this.debugMode);
            const groupKey = Buffer.from(groupKeyHex, 'hex');

            // Armazenar chave de grupo
            this.groupKeys.set(groupName, groupKey);

            if (this.debugMode) {
                console.log('└──────────────────────────────────────────────────────────────┘');
                console.log(`\n✓ Chave de grupo '${groupName}' recebida com sucesso!\n`);
            } else {
                console.log(`Chave de grupo ${groupName} recebida e descriptografada com sucesso!`);
            }

        } catch (error) {
            console.error(`Erro ao descriptografar chave de grupo ${groupName}:`, error.message);
        }
    }

    /**
     * Envia mensagem
     * Criptografa a mensagem NO CLIENTE usando envelope v1 antes de enviar (end-to-end)
     */
    async sendMessage(data) {
        if (!this.isConnected) {
            throw new Error('Não conectado ao servidor');
        }

        const { message, targetUser, isGroup } = data;

        // Buscar chave NO CLIENTE
        const key = isGroup 
            ? this.groupKeys.get(targetUser)
            : this.sharedKeys.get(targetUser);

        if (!key) {
            throw new Error(`Chave nao encontrada para ${isGroup ? 'grupo' : 'usuario'} ${targetUser}`);
        }

        try {
            // CRIPTOGRAFAR NO CLIENTE com envelope v1
            if (this.debugMode) {
                console.log('\n┌─── PILAR: CONFIDENCIALIDADE (Cifra) + INTEGRIDADE (Tag) ────────┐');
            }
            const { encryptMessage } = require('../crypto/simple-crypto');
            const envelope = encryptMessage(message, key, this.username, targetUser, isGroup, this.debugMode);
            if (this.debugMode) {
                console.log('└──────────────────────────────────────────────────────────────┘\n');
            }

            // Enviar envelope JA CRIPTOGRAFADO
            this.socket.emit('send_message', {
                envelope: envelope, // Envelope com integridade
                targetUser: targetUser,
                isGroup: isGroup || false
            });

            // Emitir evento local para confirmação
            this.emit('message_sent', {
                message: message,
                envelope: envelope,
                target: targetUser,
                isGroup: isGroup || false
            });

        } catch (error) {
            console.error('Erro ao criptografar mensagem:', error.message);
            throw error;
        }
    }

    /**
     * Entra em grupo
     */
    joinGroup(groupName) {
        if (!this.isConnected) {
            throw new Error('Não conectado ao servidor');
        }

        this.socket.emit('join_group', {
            groupName: groupName
        });
    }

    /**
     * Sai do grupo
     */
    leaveGroup(groupName) {
        if (!this.isConnected) {
            throw new Error('Não conectado ao servidor');
        }

        this.socket.emit('leave_group', {
            groupName: groupName
        });
    }

    /**
     * Sai do chat atual
     */
    leaveChat() {
        if (!this.isConnected) {
            throw new Error('Não conectado ao servidor');
        }

        this.socket.emit('leave_chat');
        
        // Limpar chaves processadas ao sair do chat (permite re-entrar)
        // Manter as chaves compartilhadas para poder retomar a conversa
    }
    
    /**
     * Limpa chaves processadas para um usuário específico
     * Útil quando precisar reprocessar uma chave
     */
    clearProcessedKey(targetUser) {
        // Remover todas as chaves processadas que começam com o nome do usuário
        const keysToRemove = [];
        this.processedKeys.forEach(keyId => {
            if (keyId.startsWith(`${targetUser}:`)) {
                keysToRemove.push(keyId);
            }
        });
        keysToRemove.forEach(keyId => this.processedKeys.delete(keyId));
    }

    /**
     * Limpa todas as chaves relacionadas a um grupo
     * Usado quando alguém sai do grupo ou quando o secret share é recriado
     */
    clearGroupKeys(groupName) {
        // Limpar chave de grupo
        this.groupKeys.delete(groupName);

        // Limpar chaves compartilhadas relacionadas ao grupo
        const keysToRemove = [];
        this.sharedKeys.forEach((key, keyId) => {
            if (keyId.startsWith(`${groupName}:`)) {
                keysToRemove.push(keyId);
            }
        });
        keysToRemove.forEach(keyId => this.sharedKeys.delete(keyId));

        // Limpar chaves processadas relacionadas ao grupo
        const processedKeysToRemove = [];
        this.processedKeys.forEach(keyId => {
            if (keyId.includes(groupName)) {
                processedKeysToRemove.push(keyId);
            }
        });
        processedKeysToRemove.forEach(keyId => this.processedKeys.delete(keyId));

        if (this.debugMode) {
            console.log(`Chaves do grupo ${groupName} foram limpas`);
        }
    }

    /**
     * Limpa chaves de um membro específico que saiu do grupo
     * Para permitir que ele possa entrar novamente como "novo"
     */
    clearMemberKeysFromGroup(groupName, memberName) {
        // Limpar chave compartilhada com aquele membro
        const groupKeyId = `${groupName}:${memberName}`;
        const directKeyId = memberName;
        
        this.sharedKeys.delete(groupKeyId);
        this.sharedKeys.delete(directKeyId);

        // Limpar TODAS as chaves processadas relacionadas àquele membro no grupo
        // Formato: groupName:memberName:publicKeyPrefix
        const processedToRemove = [];
        this.processedKeys.forEach(keyId => {
            if (keyId.startsWith(`${groupName}:${memberName}:`)) {
                processedToRemove.push(keyId);
            }
        });
        processedToRemove.forEach(keyId => this.processedKeys.delete(keyId));

        if (this.debugMode) {
            console.log(`🧹 Chaves de ${memberName} removidas do cache do grupo ${groupName}`);
            console.log(`   Removidas ${processedToRemove.length} entradas de processedKeys`);
        }
    }

    /**
     * Lista usuários online
     */
    listUsers() {
        if (!this.isConnected) {
            throw new Error('Não conectado ao servidor');
        }

        this.socket.emit('list_users');
    }

    /**
     * Lista grupos
     */
    listGroups() {
        if (!this.isConnected) {
            throw new Error('Não conectado ao servidor');
        }

        this.socket.emit('list_groups');
    }

    /**
     * Desconecta do servidor
     */
    disconnect() {
        if (this.socket) {
            this.socket.disconnect();
            this.isConnected = false;
        }
    }

    /**
     * Retorna status da conexão
     */
    getStatus() {
        return {
            isConnected: this.isConnected,
            username: this.username,
            hasPublicKey: !!this.publicKey,
            sharedKeysCount: this.sharedKeys.size
        };
    }

    /**
     * Retorna informações das chaves (incluindo chave privada)
     * ATENCAO: Chave privada é informacao sensivel!
     */
    getKeyInfo() {
        if (!this.ecdh) {
            return {
                error: 'ECDH não inicializado',
                hasPrivateKey: false,
                hasPublicKey: false
            };
        }

        const keyInfo = this.ecdh.getKeyInfo();
        
        return {
            hasPrivateKey: keyInfo.hasPrivateKey,
            hasPublicKey: keyInfo.hasPublicKey,
            privateKeyHex: keyInfo.privateKeyHex,
            publicKeyHex: keyInfo.publicKeyHex || this.publicKey,
            curve: keyInfo.curve,
            sharedKeysCount: this.sharedKeys.size,
            groupKeysCount: this.groupKeys.size
        };
    }

    /**
     * Limpa toda a sessão atual (chaves efêmeras e estado)
     * Usado pelo comando /newprofile
     */
    clearSession() {
        // Limpar chaves ECDH efêmeras
        this.publicKey = null;
        this.ecdh = null;
        
        // Limpar chaves derivadas
        this.sharedKeys.clear();
        this.groupKeys.clear();
        this.processedKeys.clear();
        
        console.log('   ✓ Chaves ECDH efêmeras limpas');
        console.log('   ✓ Chaves derivadas (HKDF) limpas');
        console.log('   ✓ Cache de processamento limpo');
    }
}

module.exports = WebSocketClient;

