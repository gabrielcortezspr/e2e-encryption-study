/**
 * Manipulador de comandos CLI
 */

const chalk = require('chalk');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { getKeypairFile, getTofuStore } = require('../crypto/ed25519-tofu');

class CommandHandler {
    constructor(client) {
        this.client = client;
    }

    /**
     * Manipula comando do usuário
     */
    handleCommand(input) {
        const parts = input.split(' ');
        const command = parts[0].toLowerCase();
        const args = parts.slice(1);

        switch (command) {
            case '/help':
                this.showHelp();
                break;
            case '/users':
                this.listUsers();
                break;
            case '/chat':
                this.startChat(args);
                break;
            case '/group':
                this.joinGroup(args);
                break;
            case '/groups':
                this.listGroups();
                break;
            case '/leave':
                this.leaveChat();
                break;
            case '/status':
                this.showStatus();
                break;
            case '/keys':
                this.showKeys();
                break;
            case '/debug':
                this.toggleDebug();
                break;
            case '/newprofile':
                this.newProfile();
                break;
            case '/delete':
                this.deleteTofuPin(args);
                break;
            case '/quit':
            case '/exit':
                this.quit();
                break;
            default:
                console.log(chalk.red('❌ Comando não reconhecido. Use /help para ver comandos disponíveis.'));
                this.client.setPrompt();
        }
    }

    /**
     * Mostra ajuda
     */
    showHelp() {
        console.log(chalk.cyan('┌─────────────────────────────────────────┐'));
        console.log(chalk.cyan('│ Comandos disponíveis:                   │'));
        console.log(chalk.cyan('│                                         │'));
        console.log(chalk.cyan('│ /help          - Mostra esta ajuda      │'));
        console.log(chalk.cyan('│ /users         - Lista usuários online  │'));
        console.log(chalk.cyan('│ /chat <user>   - Inicia chat 1:1        │'));
        console.log(chalk.cyan('│ /group <nome>  - Cria/entra em grupo    │'));
        console.log(chalk.cyan('│ /groups        - Lista grupos           │'));
        console.log(chalk.cyan('│ /leave         - Sai do chat atual      │'));
        console.log(chalk.cyan('│ /status        - Status da conexão      │'));
        console.log(chalk.cyan('│ /keys          - Mostra suas chaves     │'));
        console.log(chalk.cyan('│ /debug         - Toggle modo debug      │'));
        console.log(chalk.cyan('│ /newprofile    - Simula reinstalação    │'));
        console.log(chalk.cyan('│ /delete @user  - Remove TOFU de usuário │'));
        console.log(chalk.cyan('│ /quit          - Sair do sistema        │'));
        console.log(chalk.cyan('└─────────────────────────────────────────┘'));
        console.log('');
        console.log(chalk.yellow('💡 Dicas:'));
        console.log('   - Para enviar mensagem, digite normalmente (sem /)');
        console.log('   - Use /chat <usuário> para conversar 1:1');
        console.log('   - Use /group <nome> para criar/entrar em grupos');
        console.log('   - Use /debug para ver detalhes da criptografia');
        console.log('');
        console.log(chalk.cyan('🔒 Segurança (TOFU):'));
        console.log('   - /newprofile: Simula reinstalação (gera nova identidade)');
        console.log('   - /delete @user: Remove TOFU (aceita nova identidade)');
        console.log('   - Útil quando alguém reinstala o sistema');
        this.client.setPrompt();
    }

    /**
     * Lista usuários online
     */
    listUsers() {
        this.client.wsClient.listUsers();
    }

    /**
     * Mostra lista de usuários
     */
    showUsersList(data) {
        console.log(chalk.blue('👥 Usuários online:'));
        
        if (data.users.length === 0) {
            console.log(chalk.gray('   Nenhum usuário online'));
        } else {
            data.users.forEach(user => {
                const status = user.isInChat ? chalk.yellow('(em chat)') : chalk.green('(disponível)');
                console.log(chalk.white(`   - ${user.username}`), status);
            });
        }
        
        console.log(chalk.blue(`Total: ${data.count} usuários`));
        this.client.setPrompt();
    }

    /**
     * Inicia chat 1:1
     */
    startChat(args) {
        if (args.length === 0) {
            console.log(chalk.red('❌ Use: /chat <usuário>'));
            this.client.setPrompt();
            return;
        }

        const targetUser = args[0];
        
        if (targetUser === this.client.username) {
            console.log(chalk.red('❌ Não é possível conversar consigo mesmo'));
            this.client.setPrompt();
            return;
        }

        console.log(chalk.yellow(`Iniciando chat com ${targetUser}...`));
        this.client.wsClient.startChat(targetUser);
    }

    /**
     * Entra em grupo
     */
    joinGroup(args) {
        if (args.length === 0) {
            console.log(chalk.red('❌ Use: /group <nome>'));
            this.client.setPrompt();
            return;
        }

        const groupName = args[0];
        console.log(chalk.yellow(`👥 Entrando no grupo "${groupName}"...`));
        this.client.wsClient.joinGroup(groupName);
    }

    /**
     * Lista grupos
     */
    listGroups() {
        this.client.wsClient.listGroups();
    }

    /**
     * Mostra lista de grupos
     */
    showGroupsList(data) {
        console.log(chalk.blue('👥 Grupos disponíveis:'));
        
        if (data.groups.length === 0) {
            console.log(chalk.gray('   Nenhum grupo disponível'));
        } else {
            data.groups.forEach(group => {
                const members = group.members.join(', ');
                const status = group.keysEstablished ? chalk.green('(seguro)') : chalk.yellow('(configurando)');
                console.log(chalk.white(`   - ${group.name}`), status);
                console.log(chalk.gray(`     Membros: ${members}`));
            });
        }
        
        console.log(chalk.blue(`Total: ${data.count} grupos`));
        this.client.setPrompt();
    }

    /**
     * Sai do chat atual (ou grupo)
     */
    leaveChat() {
        if (!this.client.currentChat) {
            console.log(chalk.yellow('⚠️  Você não está em nenhum chat'));
            this.client.setPrompt();
            return;
        }

        // Se estiver em um grupo, sair do grupo (isso recria o secret share)
        if (this.client.currentChat.type === 'group') {
            const groupName = this.client.currentChat.target;
            console.log(chalk.yellow(`👋 Saindo do grupo "${groupName}"...`));
            this.client.wsClient.leaveGroup(groupName);
            this.client.currentChat = null;
        } else {
            // Chat privado
            console.log(chalk.yellow('👋 Saindo do chat...'));
            this.client.wsClient.leaveChat();
            this.client.currentChat = null;
        }
    }

    /**
     * Mostra status da conexão
     */
    showStatus() {
        const status = this.client.wsClient.getStatus();
        
        console.log(chalk.blue('Status da Conexão:'));
        console.log(chalk.white(`   - Servidor: ${this.client.serverUrl}`), status.isConnected ? chalk.green('✅') : chalk.red('❌'));
        console.log(chalk.white(`   - Usuário: ${status.username}`));
        console.log(chalk.white(`   - Chaves ECDH: ${status.hasPublicKey ? '✅' : '❌'}`));
        console.log(chalk.white(`   - Chaves compartilhadas: ${status.sharedKeysCount}`));
        
        if (this.client.currentChat) {
            if (this.client.currentChat.type === 'private') {
                console.log(chalk.white(`   - Chat ativo: ${this.client.currentChat.target} (1:1)`));
            } else {
                console.log(chalk.white(`   - Chat ativo: ${this.client.currentChat.target} (grupo)`));
            }
        } else {
            console.log(chalk.white('   - Chat ativo: Nenhum'));
        }
        
        console.log(chalk.white(`   - Modo debug: ${this.client.debugMode ? 'Ativado' : 'Desativado'}`));
        this.client.setPrompt();
    }

    /**
     * Mostra informações das chaves (incluindo chave privada)
     */
    showKeys() {
        const keyInfo = this.client.wsClient.getKeyInfo();
        
        if (keyInfo.error) {
            console.log(chalk.red(`❌ ${keyInfo.error}`));
            this.client.setPrompt();
            return;
        }

        console.log(chalk.blue('🔑 Informações das Chaves:\n'));
        
        // ==================== PILAR: INTEGRIDADE ====================
        console.log(chalk.magenta('┌─────────────────────────────────────────────────────────────┐'));
        console.log(chalk.magenta('│              🛡️  PILAR: INTEGRIDADE                         │'));
        console.log(chalk.magenta('│         (Identidade Persistente - Ed25519)                  │'));
        console.log(chalk.magenta('└─────────────────────────────────────────────────────────────┘\n'));

        try {
            const ed25519KeypairFile = getKeypairFile(this.client.username);
            
            if (fs.existsSync(ed25519KeypairFile)) {
                const ed25519Data = JSON.parse(fs.readFileSync(ed25519KeypairFile, 'utf8'));
                
                // Validar dados
                if (!ed25519Data || !ed25519Data.publicKey || !ed25519Data.privateKey) {
                    throw new Error('Arquivo Ed25519 está corrompido ou incompleto');
                }
                
                // Calcular fingerprint
                const publicKeyBuffer = Buffer.from(ed25519Data.publicKey, 'hex');
                const fingerprint = crypto.createHash('sha256').update(publicKeyBuffer).digest('hex');

                console.log(chalk.cyan('ED25519 - Identidade de Longo Prazo:'));
                console.log(chalk.gray('─────────────────────────────────────────────────────────────'));
                console.log(chalk.gray(`📄 Arquivo: ${path.relative(process.cwd(), ed25519KeypairFile)}\n`));
                
                console.log(chalk.red('🔴 Chave Privada (NUNCA compartilhar):'));
                console.log(chalk.gray(`   ${ed25519Data.privateKey.substring(0, 64)}...`));
                console.log(chalk.gray(`   (${ed25519Data.privateKey.length} chars / ${ed25519Data.privateKey.length / 2} bytes)`));
                console.log(chalk.gray(`   Usada para: Assinar chaves ECDH efêmeras\n`));
                
                console.log(chalk.green('🔵 Chave Pública (Compartilhada livremente):'));
                console.log(chalk.gray(`   ${ed25519Data.publicKey.substring(0, 64)}...`));
                console.log(chalk.gray(`   (${ed25519Data.publicKey.length} chars / ${ed25519Data.publicKey.length / 2} bytes)`));
                console.log(chalk.gray(`   Usada para: Outros verificarem minhas assinaturas\n`));
                
                console.log(chalk.yellow('🔍 Fingerprint (Identidade única):'));
                console.log(chalk.white(`   ${fingerprint}`));
                console.log(chalk.gray(`   (SHA-256 da chave pública)`));
                console.log(chalk.gray(`   Usado para: TOFU - Detectar mudanças de identidade\n`));

                // TOFU Store - Identidades conhecidas
                console.log(chalk.gray('─────────────────────────────────────────────────────────────'));
                console.log(chalk.cyan('TOFU - Identidades Conhecidas (Trust On First Use):'));
                console.log(chalk.gray('─────────────────────────────────────────────────────────────'));
                const tofuFile = getTofuStore(this.client.username);
                console.log(chalk.gray(`📄 Arquivo: ${path.relative(process.cwd(), tofuFile)}\n`));

                if (fs.existsSync(tofuFile)) {
                    const pinnedKeys = JSON.parse(fs.readFileSync(tofuFile, 'utf8'));
                    const peerCount = Object.keys(pinnedKeys).length;
                    
                    if (peerCount > 0) {
                        console.log(chalk.white(`Total de identidades armazenadas: ${peerCount}\n`));
                        
                        Object.entries(pinnedKeys).forEach(([peerName, data]) => {
                            // Validar dados antes de processar
                            if (!data || !data.ed25519PubHex) {
                                console.log(chalk.red(`❌ Dados inválidos para ${peerName}\n`));
                                return;
                            }
                            
                            const peerPubKey = data.ed25519PubHex;
                            const storedFingerprint = data.fingerprint;
                            const pinnedDate = new Date(data.firstSeen).toLocaleString('pt-BR');
                            
                            console.log(chalk.white(`👤 ${peerName}:`));
                            console.log(chalk.gray(`   Chave Pública: ${peerPubKey.substring(0, 40)}...`));
                            console.log(chalk.yellow(`   Fingerprint: ${storedFingerprint}`));
                            console.log(chalk.gray(`   Primeira vez em: ${pinnedDate}`));
                            console.log(chalk.green(`   Status: ✓ Identidade conhecida e confiável\n`));
                        });
                    } else {
                        console.log(chalk.gray('Nenhuma identidade armazenada ainda.'));
                        console.log(chalk.gray('(Quando você falar com alguém pela primeira vez, será armazenado aqui)\n'));
                    }
                } else {
                    console.log(chalk.gray('Arquivo TOFU ainda não criado.'));
                    console.log(chalk.gray('(Será criado quando você falar com alguém pela primeira vez)\n'));
                }

            } else {
                console.log(chalk.yellow('❌ Arquivo Ed25519 não encontrado.'));
                console.log(chalk.gray('(Será criado ao conectar ao servidor)\n'));
            }

        } catch (error) {
            console.log(chalk.red('❌ Erro ao carregar informações Ed25519:'), error.message);
            console.log('');
        }

        // ==================== PILAR: CONFIDENCIALIDADE ====================
        console.log(chalk.magenta('┌─────────────────────────────────────────────────────────────┐'));
        console.log(chalk.magenta('│           🔐 PILAR: CONFIDENCIALIDADE                       │'));
        console.log(chalk.magenta('│           (Chaves de Sessão Efêmeras)                       │'));
        console.log(chalk.magenta('└─────────────────────────────────────────────────────────────┘\n'));

        console.log(chalk.cyan('ECDH - Chave de Sessão Efêmera:'));
        console.log(chalk.gray('─────────────────────────────────────────────────────────────'));
        console.log(chalk.yellow('⚠️  Chave gerada a CADA CONEXÃO (descartada ao desconectar)\n'));

        if (keyInfo.hasPrivateKey) {
            console.log(chalk.red('🔴 Chave Privada ECDH (In-Memory / RAM):'));
            console.log(chalk.gray(`   ${keyInfo.privateKeyHex}`));
            console.log(chalk.gray(`   (${keyInfo.privateKeyHex.length / 2} bytes)`));
            console.log(chalk.gray(`   Curva: secp256k1`));
            console.log(chalk.gray(`   Usada para: Computar shared secret via ECDH\n`));
        }

        if (keyInfo.hasPublicKey) {
            console.log(chalk.green('🔵 Chave Pública ECDH (Enviada para outros):'));
            console.log(chalk.gray(`   ${keyInfo.publicKeyHex}`));
            console.log(chalk.gray(`   (${keyInfo.publicKeyHex.length / 2} bytes)`));
            console.log(chalk.gray(`   Curva: secp256k1`));
            console.log(chalk.gray(`   Usada para: Outros computarem shared secret com você\n`));
        }

        if (!keyInfo.hasPrivateKey && !keyInfo.hasPublicKey) {
            console.log(chalk.yellow('❌ Chaves ECDH não geradas ainda (não conectado)\n'));
        }

        console.log(chalk.gray('─────────────────────────────────────────────────────────────'));
        console.log(chalk.cyan('Chaves Compartilhadas Derivadas (HKDF):'));
        console.log(chalk.gray('─────────────────────────────────────────────────────────────'));
        console.log(chalk.yellow('⚠️  Armazenadas em RAM (perdidas ao desconectar)'));
        console.log(chalk.yellow('⚠️  Derivadas via HKDF a partir do shared secret ECDH\n'));

        if (keyInfo.sharedKeysCount > 0) {
            console.log(chalk.white(`Total: ${keyInfo.sharedKeysCount} chave(s) ativa(s)\n`));
            
            this.client.wsClient.sharedKeys.forEach((key, peer) => {
                const isGroup = peer.includes(':');
                if (isGroup) {
                    const [groupName, peerName] = peer.split(':');
                    console.log(chalk.white(`👥 Grupo "${groupName}" com ${peerName}:`));
                } else {
                    console.log(chalk.white(`👤 Chat 1:1 com ${peer}:`));
                }
                console.log(chalk.gray(`   encKey (AES-128-GCM): ${key.toString('hex')}`));
                console.log(chalk.gray(`   (${key.length} bytes / ${key.length * 8} bits)`));
                console.log(chalk.gray(`   Derivada via: HKDF-SHA256(ECDH_shared_secret)\n`));
            });
        } else {
            console.log(chalk.gray('Nenhuma chave compartilhada estabelecida ainda.'));
            console.log(chalk.gray('(Use /chat <usuario> para iniciar troca de chaves)\n'));
        }

        console.log(chalk.gray('─────────────────────────────────────────────────────────────'));
        console.log(chalk.cyan('Chaves de Grupo:'));
        console.log(chalk.gray('─────────────────────────────────────────────────────────────'));
        console.log(chalk.yellow('⚠️  Armazenadas em RAM (perdidas ao desconectar)'));
        console.log(chalk.yellow('⚠️  Geradas pelo criador e distribuídas via envelope\n'));

        if (keyInfo.groupKeysCount > 0) {
            console.log(chalk.white(`Total: ${keyInfo.groupKeysCount} grupo(s) ativo(s)\n`));
            
            this.client.wsClient.groupKeys.forEach((key, groupName) => {
                console.log(chalk.white(`👥 Grupo "${groupName}":`));
                console.log(chalk.gray(`   Chave de Grupo (AES-128-GCM): ${key.toString('hex')}`));
                console.log(chalk.gray(`   (${key.length} bytes / ${key.length * 8} bits)`));
                console.log(chalk.gray(`   Tipo: Aleatória (gerada pelo criador)`));
                console.log(chalk.gray(`   Recebida: Via envelope criptografado com chave pairwise\n`));
            });
        } else {
            console.log(chalk.gray('Nenhuma chave de grupo estabelecida ainda.'));
            console.log(chalk.gray('(Use /group <nome> para criar/entrar em grupo)\n'));
        }
        
        this.client.setPrompt();
    }

    /**
     * Toggle modo debug
     */
    toggleDebug() {
        this.client.debugMode = !this.client.debugMode;
        console.log(chalk.blue(`Modo debug: ${this.client.debugMode ? 'Ativado' : 'Desativado'}`));
        this.client.setPrompt();
    }

    /**
     * Simula reinstalação da aplicação (gera novo perfil)
     */
    newProfile() {
        console.log(chalk.yellow('\n⚠️  ATENÇÃO: Você está prestes a DELETAR seu perfil atual!'));
        console.log(chalk.yellow('   Isso vai remover:'));
        console.log(chalk.gray('   • Sua identidade Ed25519 (chave de longo prazo)'));
        console.log(chalk.gray('   • Todas as identidades TOFU armazenadas'));
        console.log(chalk.gray('   • Todas as conexões ativas'));
        console.log('');
        console.log(chalk.red('   Esta ação é IRREVERSÍVEL!'));
        console.log(chalk.yellow('\n   Isso simula você desinstalar e reinstalar a aplicação.'));
        console.log(chalk.yellow('   Outros usuários receberão alerta TOFU ao falar com você.\n'));
        
        // Arquivos a deletar
        const ed25519File = getKeypairFile(this.client.username);
        const tofuFile = getTofuStore(this.client.username);
        
        let deleted = [];
        
        // Deletar Ed25519
        if (fs.existsSync(ed25519File)) {
            fs.unlinkSync(ed25519File);
            deleted.push('✓ Identidade Ed25519 deletada');
        }
        
        // Deletar TOFU store
        if (fs.existsSync(tofuFile)) {
            fs.unlinkSync(tofuFile);
            deleted.push('✓ Registro TOFU deletado');
        }
        
        // Limpar estado de sessão
        this.client.wsClient.clearSession();
        deleted.push('✓ Sessão atual limpa');
        
        console.log(chalk.green('\n🔄 Perfil resetado:'));
        deleted.forEach(msg => console.log(chalk.green(`   ${msg}`)));
        
        console.log(chalk.yellow('\n⚠️  Você precisa RECONECTAR para gerar novo perfil:'));
        console.log(chalk.cyan('   1. Use /quit para desconectar'));
        console.log(chalk.cyan('   2. Em um novo terminal, execute:'));
        console.log(chalk.white(`      node client/cli/main.js --username ${this.client.username}`));
        console.log(chalk.cyan('   3. Novo par Ed25519 será gerado automaticamente\n'));
        
        this.client.setPrompt();
    }

    /**
     * Deleta registro TOFU de um usuário específico
     */
    deleteTofuPin(args) {
        if (args.length === 0) {
            console.log(chalk.red('❌ Use: /delete @usuario'));
            console.log(chalk.gray('   Exemplo: /delete @Alice'));
            this.client.setPrompt();
            return;
        }
        
        // Remover @ se presente
        let targetUser = args[0];
        if (targetUser.startsWith('@')) {
            targetUser = targetUser.substring(1);
        }
        
        if (targetUser === this.client.username) {
            console.log(chalk.red('❌ Não é possível deletar seu próprio perfil'));
            console.log(chalk.yellow('   Use /newprofile para resetar seu perfil'));
            this.client.setPrompt();
            return;
        }
        
        const tofuFile = getTofuStore(this.client.username);
        
        if (!fs.existsSync(tofuFile)) {
            console.log(chalk.yellow(`⚠️  Você não tem nenhum registro TOFU ainda`));
            this.client.setPrompt();
            return;
        }
        
        try {
            const pins = JSON.parse(fs.readFileSync(tofuFile, 'utf8'));
            
            if (!pins[targetUser]) {
                console.log(chalk.yellow(`⚠️  Você não tem registro TOFU de ${targetUser}`));
                console.log(chalk.gray(`   Usuários registrados: ${Object.keys(pins).join(', ') || 'nenhum'}`));
                this.client.setPrompt();
                return;
            }
            
            const oldFingerprint = pins[targetUser].fingerprint;
            delete pins[targetUser];
            
            fs.writeFileSync(tofuFile, JSON.stringify(pins, null, 2));
            
            console.log(chalk.green(`\n✅ Registro TOFU de ${targetUser} deletado com sucesso!`));
            console.log(chalk.gray(`   Fingerprint removido: ${oldFingerprint.substring(0, 16)}...`));
            console.log(chalk.yellow(`\n⚠️  Próxima vez que falar com ${targetUser}:`));
            console.log(chalk.cyan(`   • Será tratado como PRIMEIRA CONEXÃO`));
            console.log(chalk.cyan(`   • Novo fingerprint será armazenado`));
            console.log(chalk.cyan(`   • Ideal se ${targetUser} usou /newprofile\n`));
            
        } catch (err) {
            console.log(chalk.red(`❌ Erro ao deletar registro TOFU: ${err.message}`));
        }
        
        this.client.setPrompt();
    }

    /**
     * Sai do sistema
     */
    quit() {
        console.log(chalk.yellow('👋 Saindo do sistema...'));
        this.client.disconnect();
    }
}

module.exports = CommandHandler;

