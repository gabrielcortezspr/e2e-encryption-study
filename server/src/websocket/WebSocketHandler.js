/**
 * Gerenciador de WebSocket para o sistema de mensagens
 * End-to-End Encryption: Servidor apenas roteia chaves públicas e envelopes cifrados
 *
 * Eventos recebidos do cliente:
 *   user_connect, start_chat, send_message, join_group, leave_group,
 *   distribute_group_key, leave_chat, list_users, list_groups, disconnect
 *
 * Eventos enviados ao cliente:
 *   user_connected, user_joined, user_left, chat_started, chat_ready, chat_left,
 *   exchange_public_key, message_sent, message_received, group_message_received,
 *   group_joined, group_left, member_joined_group, member_left_group,
 *   generate_and_distribute_group_key, group_key_received, clear_group_key,
 *   users_list, groups_list, error
 */

const crypto = require('crypto');
const User = require('../models/User');
const Group = require('../models/Group');

class WebSocketHandler {
    constructor(io) {
        this.io = io;
        this.users = new Map(); // username -> User
        this.groups = new Map(); // groupName -> Group
        
        this.setupEventHandlers();
    }

    /**
     * Configura os event handlers do WebSocket
     */
    setupEventHandlers() {
        this.io.on('connection', (socket) => {
            console.log(`Cliente conectado: ${socket.id}`);

            // Evento: Usuário se conecta
            socket.on('user_connect', (data) => {
                this.handleUserConnect(socket, data);
            });

            // Evento: Iniciar chat 1:1
            socket.on('start_chat', (data) => {
                this.handleStartChat(socket, data);
            });

            // Evento: Enviar mensagem
            socket.on('send_message', (data) => {
                this.handleSendMessage(socket, data);
            });

            // Evento: Criar/entrar em grupo
            socket.on('join_group', (data) => {
                this.handleJoinGroup(socket, data);
            });

            // Evento: Sair do grupo
            socket.on('leave_group', (data) => {
                this.handleLeaveGroup(socket, data);
            });

            // Evento: Distribuir chave de grupo criptografada
            socket.on('distribute_group_key', (data) => {
                this.handleDistributeGroupKey(socket, data);
            });

            // Evento: Sair do chat
            socket.on('leave_chat', () => {
                this.handleLeaveChat(socket);
            });

            // Evento: Listar usuários
            socket.on('list_users', () => {
                this.handleListUsers(socket);
            });

            // Evento: Listar grupos
            socket.on('list_groups', () => {
                this.handleListGroups(socket);
            });

            // Evento: Desconexão
            socket.on('disconnect', () => {
                this.handleDisconnect(socket);
            });
        });
    }

    /**
     * Manipula conexão de usuário
     * ✅ End-to-End: Cliente envia sua chave pública (chave privada fica no cliente)
     * ✅ Integridade: Armazena também chave Ed25519 e assinatura para relay
     */
    async handleUserConnect(socket, data) {
        try {
            const { username, publicKey, ed25519Pub, signature } = data;
            
            if (!username) {
                socket.emit('error', { message: 'Username é obrigatório' });
                return;
            }

            if (!publicKey) {
                socket.emit('error', { message: 'Chave pública ECDH é obrigatória' });
                return;
            }

            if (!ed25519Pub || !signature) {
                socket.emit('error', { message: 'Credenciais de autenticação (Ed25519) são obrigatórias' });
                return;
            }

            if (this.users.has(username)) {
                socket.emit('error', { message: 'Username já está em uso' });
                return;
            }

            // ✅ Criar usuário e armazenar chaves públicas + assinatura
            const user = new User(username, socket.id);
            user.setPublicKey(publicKey, ed25519Pub, signature);
            // ❌ NÃO gerar chaves no servidor
            // ❌ NÃO armazenar chaves privadas

            // Armazenar usuário
            this.users.set(username, user);
            socket.username = username;

            // Calcular fingerprint Ed25519 para mostrar identidade única
            const ed25519Fingerprint = crypto.createHash('sha256').update(ed25519Pub, 'hex').digest('hex');
            
            console.log(`Usuario conectado: ${username}`);
            console.log(`   Chave ECDH (efêmera): ${publicKey.substring(0, 16)}...`);
            console.log(`   Identidade Ed25519: ${ed25519Fingerprint.substring(0, 32)}...`);

            // Resposta para o cliente
            socket.emit('user_connected', {
                success: true,
                username: username,
                message: 'Conectado com sucesso!'
            });

            // Notificar outros usuários
            socket.broadcast.emit('user_joined', {
                username: username,
                message: `${username} entrou no sistema`
            });

        } catch (error) {
            console.error('Erro ao conectar usuário:', error);
            socket.emit('error', { message: 'Erro interno do servidor' });
        }
    }

    /**
     * Manipula início de chat 1:1
     */
    async handleStartChat(socket, data) {
        try {
            const { targetUser } = data;
            const username = socket.username;

            if (!username || !targetUser) {
                socket.emit('error', { message: 'Dados inválidos' });
                return;
            }

            if (!this.users.has(targetUser)) {
                socket.emit('error', { message: 'Usuário não encontrado' });
                return;
            }

            if (username === targetUser) {
                socket.emit('error', { message: 'Não é possível conversar consigo mesmo' });
                return;
            }

            const user = this.users.get(username);
            const target = this.users.get(targetUser);

            // Definir chat ativo
            user.setCurrentChat('private', targetUser);
            target.setCurrentChat('private', username);

            console.log(`Chat iniciado: ${username} <-> ${targetUser}`);

            // Verificar credenciais Ed25519 de ambos usuários
            if (!user.ed25519PublicKey || !user.signature) {
                console.error(`❌ Usuário ${username} não tem credenciais Ed25519 completas`);
                socket.emit('error', { message: 'Credenciais de autenticação incompletas' });
                return;
            }
            
            if (!target.ed25519PublicKey || !target.signature) {
                console.error(`❌ Usuário ${targetUser} não tem credenciais Ed25519 completas`);
                socket.emit('error', { message: `Usuário ${targetUser} sem credenciais de autenticação` });
                return;
            }
            
            // Rotear chaves publicas + credenciais Ed25519 entre os usuarios (UMA VEZ)
            console.log(`Rotendo troca de chaves ECDH + Ed25519: ${username} <-> ${targetUser}`);
            
            // Enviar chave publica de Bob para Alice (com Ed25519 + assinatura)
            socket.emit('exchange_public_key', {
                targetUser: targetUser,
                publicKey: target.publicKey, // Chave publica ECDH de Bob
                ed25519Pub: target.ed25519PublicKey, // Chave publica Ed25519 de Bob
                signature: target.signature, // Assinatura de Bob
                isGroup: false
            });

            // Enviar chave publica de Alice para Bob (com Ed25519 + assinatura)
            this.io.to(target.socketId).emit('exchange_public_key', {
                targetUser: username,
                publicKey: user.publicKey, // Chave publica ECDH de Alice
                ed25519Pub: user.ed25519PublicKey, // Chave publica Ed25519 de Alice
                signature: user.signature, // Assinatura de Alice
                isGroup: false
            });

            // Notificar ambos os usuários
            socket.emit('chat_started', {
                success: true,
                targetUser: targetUser,
                message: `Chat iniciado com ${targetUser}. Troca de chaves em andamento...`
            });

            this.io.to(target.socketId).emit('chat_started', {
                success: true,
                targetUser: username,
                message: `${username} iniciou um chat com você. Troca de chaves em andamento...`
            });

            // Aguardar um pouco e entao notificar que o chat esta pronto
            // (ambos os clientes ja calcularam suas chaves compartilhadas)
            setTimeout(() => {
                socket.emit('chat_ready', {
                    targetUser: targetUser,
                    message: `Chat seguro estabelecido com ${targetUser}!`
                });

                this.io.to(target.socketId).emit('chat_ready', {
                    targetUser: username,
                    message: `Chat seguro estabelecido com ${username}!`
                });
            }, 500); // Aguardar 500ms para garantir que os clientes processaram as chaves

        } catch (error) {
            console.error('Erro ao iniciar chat:', error);
            socket.emit('error', { message: 'Erro interno do servidor' });
        }
    }

    /**
     * Manipula envio de mensagem
     * End-to-End: Envelope já vem do cliente com integridade, apenas rotear
     */
    async handleSendMessage(socket, data) {
        try {
            const { envelope, targetUser, isGroup } = data;
            const username = socket.username;

            if (!username || !envelope || !targetUser) {
                socket.emit('error', { message: 'Dados inválidos' });
                return;
            }

            const user = this.users.get(username);

            if (!user) {
                socket.emit('error', { message: 'Usuário não encontrado' });
                return;
            }

            // Envelope já vem com integridade do cliente
            if (isGroup) {
                await this.handleGroupMessage(user, envelope, targetUser);
            } else {
                await this.handlePrivateMessage(user, envelope, targetUser);
            }

        } catch (error) {
            console.error('Erro ao enviar mensagem:', error);
            socket.emit('error', { 
                message: 'Erro ao enviar mensagem',
                details: error.message,
                type: error.name || 'UnknownError'
            });
        }
    }

    /**
     * Manipula mensagem privada
     * End-to-End: Envelope já vem com integridade, apenas rotear (não descriptografar)
     */
    async handlePrivateMessage(user, envelope, targetUser) {
        const target = this.users.get(targetUser);

        console.log(`Roteando envelope privado:`);
        console.log(`   De: ${user.username}`);
        console.log(`   Para: ${targetUser}`);
        console.log(`   Envelope v${envelope.v} ts:${envelope.ts}`);

        if (!target) {
            this.io.to(user.socketId).emit('error', { 
                message: 'Usuário de destino não encontrado',
                details: `Usuário ${targetUser} não está online`,
                type: 'TargetNotFound'
            });
            return;
        }

        try {
            // Apenas rotear envelope (não descriptografar)
            // Notificar remetente que mensagem foi enviada
            this.io.to(user.socketId).emit('message_sent', {
                success: true,
                envelope: envelope,
                target: targetUser,
                isGroup: false
            });

            // Enviar envelope para destinatario (ele valida e descriptografa no cliente)
            this.io.to(target.socketId).emit('message_received', {
                from: user.username,
                envelope: envelope, // Envelope completo com integridade
                timestamp: envelope.ts
            });

            console.log(`Envelope roteado: ${user.username} -> ${targetUser}`);

        } catch (error) {
            console.error('Erro ao rotear mensagem:', error);
            this.io.to(user.socketId).emit('error', { 
                message: 'Erro ao rotear mensagem',
                details: error.message,
                type: error.name || 'RoutingError',
                targetUser: targetUser
            });
        }
    }

    /**
     * Manipula mensagem de grupo
     * End-to-End: Envelope já vem com integridade, apenas rotear (não descriptografar)
     */
    async handleGroupMessage(user, envelope, groupName) {
        const group = this.groups.get(groupName);

        console.log(`Roteando envelope de grupo:`);
        console.log(`   De: ${user.username}`);
        console.log(`   Grupo: ${groupName}`);
        console.log(`   Envelope v${envelope.v} ts:${envelope.ts}`);

        if (!group) {
            this.io.to(user.socketId).emit('error', { 
                message: 'Grupo não encontrado',
                details: `Grupo ${groupName} não existe`,
                type: 'GroupNotFound'
            });
            return;
        }

        if (!group.isMember(user.username)) {
            this.io.to(user.socketId).emit('error', { 
                message: 'Você não é membro deste grupo',
                details: `Usuário ${user.username} não é membro do grupo ${groupName}`,
                type: 'NotGroupMember'
            });
            return;
        }

        try {
            // Apenas rotear envelope (não descriptografar)
            // Enviar envelope para todos os membros do grupo
            group.members.forEach(memberName => {
                const member = this.users.get(memberName);
                if (member && member.isOnline) {
                    this.io.to(member.socketId).emit('group_message_received', {
                        from: user.username,
                        groupName: groupName,
                        envelope: envelope, // Envelope completo com integridade
                        timestamp: envelope.ts
                    });
                }
            });

            // Confirmar envio para o remetente
            this.io.to(user.socketId).emit('message_sent', {
                success: true,
                envelope: envelope,
                target: groupName,
                isGroup: true
            });

            console.log(`Envelope de grupo roteado: ${user.username} -> ${groupName} (${group.members.size} membros)`);

        } catch (error) {
            console.error('Erro ao rotear mensagem de grupo:', error);
            this.io.to(user.socketId).emit('error', { 
                message: 'Erro ao rotear mensagem de grupo',
                details: error.message,
                type: error.name || 'GroupRoutingError',
                groupName: groupName
            });
        }
    }

    /**
     * Estabelece chaves ECDH entre todos os pares de membros do grupo
     * End-to-End: Apenas roteia chaves publicas (clientes calculam chaves compartilhadas)
     */
    async establishGroupKeys(group) {
        const members = Array.from(group.members);
        console.log(`Roteando chaves públicas + Ed25519 para grupo ${group.name} com ${members.length} membros`);

        // Para cada par de membros, rotear chaves públicas COM Ed25519
        for (let i = 0; i < members.length; i++) {
            for (let j = i + 1; j < members.length; j++) {
                const member1 = members[i];
                const member2 = members[j];
                
                const user1 = this.users.get(member1);
                const user2 = this.users.get(member2);

                if (user1 && user2 && user1.isOnline && user2.isOnline && user1.publicKey && user2.publicKey) {
                    // Verificar credenciais Ed25519
                    if (!user1.ed25519PublicKey || !user1.signature || !user2.ed25519PublicKey || !user2.signature) {
                        console.error(`❌ Credenciais Ed25519 incompletas: ${member1} ou ${member2}`);
                        continue;
                    }
                    
                    console.log(`🔑 Roteando chaves públicas + Ed25519 no grupo: ${member1} ↔ ${member2}`);
                    
                    // ✅ Rotear chaves públicas COM Ed25519 entre os dois membros
                    this.io.to(user1.socketId).emit('exchange_public_key', {
                        targetUser: member2,
                        publicKey: user2.publicKey,
                        ed25519Pub: user2.ed25519PublicKey,
                        signature: user2.signature,
                        isGroup: true,
                        groupName: group.name
                    });

                    this.io.to(user2.socketId).emit('exchange_public_key', {
                        targetUser: member1,
                        publicKey: user1.publicKey,
                        ed25519Pub: user1.ed25519PublicKey,
                        signature: user1.signature,
                        isGroup: true,
                        groupName: group.name
                    });
                }
            }
        }
    }

    /**
     * Notifica os clientes para gerarem a chave de grupo
     * ✅ End-to-End: O criador do grupo gera a chave e a distribui criptografada
     */
    notifyGroupKeyGeneration(groupName) {
        const group = this.groups.get(groupName);
        if (!group) return;

        const members = Array.from(group.members);
        const creator = group.creator;
        
        console.log(`🔔 Solicitando geração de chave de grupo: ${groupName} (${members.length} membros)`);
        console.log(`   Criador do grupo: ${creator}`);

        // ✅ O criador do grupo gera chave aleatória e distribui para todos
        const creatorUser = this.users.get(creator);
        if (creatorUser && creatorUser.isOnline) {
            this.io.to(creatorUser.socketId).emit('generate_and_distribute_group_key', {
                groupName: groupName,
                members: members,
                message: `Gere e distribua a chave de grupo para ${groupName}`
            });
        } else {
            console.error(`❌ Criador do grupo ${creator} não está online`);
        }
    }

    /**
     * Manipula distribuição de chave de grupo criptografada
     * ✅ End-to-End: Apenas roteia a chave criptografada (servidor não descriptografa)
     */
    async handleDistributeGroupKey(socket, data) {
        try {
            const { groupName, encryptedKeys } = data;
            const username = socket.username;
            
            const group = this.groups.get(groupName);
            if (!group) {
                socket.emit('error', { message: 'Grupo não encontrado' });
                return;
            }

            // Verificar se é o criador do grupo
            if (group.creator !== username) {
                socket.emit('error', { message: 'Apenas o criador do grupo pode distribuir a chave' });
                return;
            }

            if (!Array.isArray(encryptedKeys)) {
                socket.emit('error', { message: 'Dados inválidos' });
                return;
            }

            console.log(`🔐 Distribuindo chave de grupo ${groupName} para ${encryptedKeys.length} membros`);
            group.markKeyDistributed();

            // ✅ Rotear chave criptografada para cada membro
            encryptedKeys.forEach(({ member, encryptedKey }) => {
                const memberUser = this.users.get(member);
                if (memberUser && memberUser.isOnline) {
                    this.io.to(memberUser.socketId).emit('group_key_received', {
                        groupName: groupName,
                        encryptedKey: encryptedKey,
                        from: username,
                        message: `Chave de grupo ${groupName} recebida`
                    });
                }
            });

        } catch (error) {
            console.error('Erro ao distribuir chave de grupo:', error);
            socket.emit('error', { message: 'Erro ao distribuir chave de grupo' });
        }
    }

    /**
     * Inicia troca de chaves quando novo membro entra no grupo
     * End-to-End: Apenas roteia chaves publicas (clientes calculam chaves compartilhadas)
     */
    async initiateGroupKeyExchange(socket, groupName) {
        const group = this.groups.get(groupName);
        if (!group) return;

        const username = socket.username;
        const user = this.users.get(username);
        
        if (!user || !user.publicKey) {
            console.error(`❌ Usuário ${username} não tem chave pública`);
            return;
        }

        console.log(`🔄 Roteando chaves públicas + Ed25519 para novo membro ${username} no grupo ${groupName}`);

        // ✅ Rotear chaves públicas com todos os membros existentes
        const existingMembers = Array.from(group.members).filter(member => member !== username);
        
        for (const memberName of existingMembers) {
            const member = this.users.get(memberName);
            if (member && member.isOnline && member.publicKey) {
                // Verificar se membro tem credenciais Ed25519
                if (!member.ed25519PublicKey || !member.signature) {
                    console.error(`❌ Membro ${memberName} não tem credenciais Ed25519 completas`);
                    console.error(`   ed25519Pub: ${member.ed25519PublicKey ? 'OK' : 'MISSING'}`);
                    console.error(`   signature: ${member.signature ? 'OK' : 'MISSING'}`);
                    continue;
                }
                
                // Verificar se novo usuário tem credenciais Ed25519
                if (!user.ed25519PublicKey || !user.signature) {
                    console.error(`❌ Novo membro ${username} não tem credenciais Ed25519 completas`);
                    console.error(`   ed25519Pub: ${user.ed25519PublicKey ? 'OK' : 'MISSING'}`);
                    console.error(`   signature: ${user.signature ? 'OK' : 'MISSING'}`);
                    continue;
                }
                
                console.log(`🔑 Roteando chaves públicas + Ed25519: ${username} ↔ ${memberName}`);
                
                // ✅ Rotear chave pública do membro existente para o novo membro (com Ed25519)
                socket.emit('exchange_public_key', {
                    targetUser: memberName,
                    publicKey: member.publicKey, // Chave pública ECDH
                    ed25519Pub: member.ed25519PublicKey, // Chave pública Ed25519
                    signature: member.signature, // Assinatura
                    isGroup: true,
                    groupName: groupName
                });

                // ✅ Rotear chave pública do novo membro para o membro existente (com Ed25519)
                this.io.to(member.socketId).emit('exchange_public_key', {
                    targetUser: username,
                    publicKey: user.publicKey, // Chave pública ECDH
                    ed25519Pub: user.ed25519PublicKey, // Chave pública Ed25519
                    signature: user.signature, // Assinatura
                    isGroup: true,
                    groupName: groupName
                });
            }
        }
    }

    /**
     * Manipula entrada em grupo
     */
    async handleJoinGroup(socket, data) {
        try {
            const { groupName } = data;
            const username = socket.username;

            if (!username || !groupName) {
                socket.emit('error', { message: 'Dados inválidos' });
                return;
            }

            const user = this.users.get(username);

            if (!this.groups.has(groupName)) {
                // Criar novo grupo
                const group = new Group(groupName, username);
                this.groups.set(groupName, group);
                user.setCurrentChat('group', groupName);
                user.currentGroup = groupName;

                console.log(`👥 Grupo criado: ${groupName} por ${username}`);

                socket.emit('group_joined', {
                    success: true,
                    groupName: groupName,
                    isCreator: true,
                    message: `Grupo "${groupName}" criado com sucesso!`
                });
                
                // ✅ Não precisa estabelecer chaves ainda (grupo com apenas 1 membro)
            } else {
                // Entrar em grupo existente
                const group = this.groups.get(groupName);
                
                if (group.isMember(username)) {
                    socket.emit('error', { message: 'Você já é membro deste grupo' });
                    return;
                }

                group.addMember(username);
                user.setCurrentChat('group', groupName);
                user.currentGroup = groupName;

                console.log(`👥 Usuário ${username} entrou no grupo ${groupName}`);

                socket.emit('group_joined', {
                    success: true,
                    groupName: groupName,
                    isCreator: false,
                    members: Array.from(group.members),
                    message: `Você entrou no grupo "${groupName}"`
                });

                // Notificar outros membros
                group.members.forEach(memberName => {
                    if (memberName !== username) {
                        const member = this.users.get(memberName);
                        if (member) {
                            this.io.to(member.socketId).emit('member_joined_group', {
                                groupName: groupName,
                                newMember: username,
                                message: `${username} entrou no grupo`
                            });
                        }
                    }
                });

                // ✅ Iniciar troca de chaves para o novo membro (já inclui Ed25519)
                await this.initiateGroupKeyExchange(socket, groupName);
                
                // ✅ Quando novo membro entra, REGENERAR chave de grupo com todos os membros
                if (group.members.size >= 2) {
                    console.log(`🔄 Novo membro entrou: regenerando chave de grupo para ${groupName}`);
                    // Aguardar um pouco para garantir que trocas de chave foram processadas
                    setTimeout(() => {
                        this.notifyGroupKeyGeneration(groupName);
                    }, 1000);
                }
            }

        } catch (error) {
            console.error('Erro ao entrar em grupo:', error);
            socket.emit('error', { message: 'Erro interno do servidor' });
        }
    }

    /**
     * Manipula saída de grupo
     * Quando alguém sai, recria o secret share para os membros restantes
     */
    async handleLeaveGroup(socket, data) {
        try {
            const { groupName } = data;
            const username = socket.username;

            if (!username || !groupName) {
                socket.emit('error', { message: 'Dados inválidos' });
                return;
            }

            const group = this.groups.get(groupName);
            if (!group) {
                socket.emit('error', { message: 'Grupo não encontrado' });
                return;
            }

            if (!group.isMember(username)) {
                socket.emit('error', { message: 'Você não é membro deste grupo' });
                return;
            }

            const user = this.users.get(username);
            if (user) {
                // Limpar chat ativo se estava neste grupo
                if (user.currentGroup === groupName) {
                    user.clearCurrentChat();
                    user.currentGroup = null;
                }
            }

            // Remover membro (isso limpa todas as chaves relacionadas)
            const wasCreator = group.creator === username;
            group.removeMember(username);

            console.log(`👋 Usuário ${username} saiu do grupo ${groupName}`);

            // Notificar o usuário que saiu para LIMPAR suas chaves de grupo
            socket.emit('group_left', {
                success: true,
                groupName: groupName,
                clearGroupKey: true, // ✅ Sinaliza para limpar chave de grupo
                message: `Você saiu do grupo "${groupName}"`
            });

            // Notificar outros membros (sem limpar suas chaves ainda)
            group.members.forEach(memberName => {
                const member = this.users.get(memberName);
                if (member) {
                    this.io.to(member.socketId).emit('member_left_group', {
                        groupName: groupName,
                        leftMember: username,
                        message: `${username} saiu do grupo`,
                        wasCreator: wasCreator
                    });
                }
            });

            // Se o grupo ainda tem 2+ membros, REGENERAR chave de grupo
            if (group.members.size >= 2) {
                console.log(`🔄 Regenerando chave de grupo ${groupName} após saída de ${username}`);
                console.log(`   Membros restantes: ${Array.from(group.members).join(', ')}`);
                
                // ✅ NÃO limpar chaves! Apenas reestabelecer pares que faltam
                // As chaves pairwise existentes continuam válidas
                await this.establishGroupKeys(group);
                
                // Aguardar e solicitar regeneração da chave de grupo
                setTimeout(() => {
                    this.notifyGroupKeyGeneration(groupName);
                }, 1000);
            } else if (group.members.size === 1) {
                // Se restou apenas 1 membro, limpar chaves (não há mais secret share)
                const lastMember = Array.from(group.members)[0];
                const lastUser = this.users.get(lastMember);
                if (lastUser) {
                    this.io.to(lastUser.socketId).emit('clear_group_key', {
                        groupName: groupName,
                        reason: 'Você é o único membro restante'
                    });
                }
                group.invalidateKey();
                console.log(`ℹ️  Grupo ${groupName} agora tem apenas 1 membro, chaves limpas`);
            } else {
                // Grupo vazio, pode ser removido
                this.groups.delete(groupName);
                console.log(`🗑️  Grupo ${groupName} foi removido (sem membros)`);
            }

        } catch (error) {
            console.error('Erro ao sair do grupo:', error);
            socket.emit('error', { message: 'Erro interno do servidor' });
        }
    }

    /**
     * Manipula saída do chat
     */
    handleLeaveChat(socket) {
        const username = socket.username;
        if (!username) return;

        const user = this.users.get(username);
        if (user) {
            user.clearCurrentChat();
            user.currentGroup = null;
            
            socket.emit('chat_left', {
                success: true,
                message: 'Você saiu do chat'
            });

            console.log(`👋 Usuário ${username} saiu do chat`);
        }
    }

    /**
     * Lista usuários online
     */
    handleListUsers(socket) {
        const onlineUsers = Array.from(this.users.values())
            .filter(user => user.isOnline)
            .map(user => ({
                username: user.username,
                connectedAt: user.connectedAt,
                isInChat: user.isInChat()
            }));

        socket.emit('users_list', {
            users: onlineUsers,
            count: onlineUsers.length
        });
    }

    /**
     * Lista grupos
     */
    handleListGroups(socket) {
        const groupsList = Array.from(this.groups.values())
            .filter(group => group.isActive)
            .map(group => group.getInfo());

        socket.emit('groups_list', {
            groups: groupsList,
            count: groupsList.length
        });
    }

    /**
     * Manipula desconexão
     */
    async handleDisconnect(socket) {
        const username = socket.username;
        const user = username && this.users.get(username);

        // Ignora sockets que não completaram user_connect ou já foram substituídos
        if (!user || user.socketId !== socket.id) {
            return;
        }

        user.setOffline();

        // Sair de todos os grupos (dispara re-key para os membros restantes)
        for (const group of Array.from(this.groups.values())) {
            if (group.isMember(username)) {
                await this.handleLeaveGroup(socket, { groupName: group.name });
            }
        }

        // Remover o usuário: libera o username para reconexão.
        // A chave ECDH dele era efêmera, então uma reconexão gera chaves novas.
        this.users.delete(username);

        console.log(`👋 Usuário desconectado: ${username}`);

        // Notificar outros usuários
        socket.broadcast.emit('user_left', {
            username: username,
            message: `${username} saiu do sistema`
        });
    }
}

module.exports = WebSocketHandler;

