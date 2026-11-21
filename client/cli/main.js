#!/usr/bin/env node
/**
 * Cliente CLI Principal do Sistema de Mensagens Seguras
 */

// Carregar variáveis de ambiente
require('dotenv').config({ path: '../../config.env' });

const readline = require('readline');
const chalk = require('chalk');
const WebSocketClient = require('../shared/websocket-client');
const CommandHandler = require('./commands');
const MessageHandler = require('./message-handler');

class SecureMessageClient {
    constructor() {
        this.username = null;
        this.serverUrl = process.env.NODE_URL || 'http://localhost:6666';
        this.wsClient = null;
        this.commandHandler = null;
        this.messageHandler = null;
        this.isConnected = false;
        this.currentChat = null;
        this.debugMode = false;
        
        this.setupReadline();
        this.parseArguments();
    }

    /**
     * Configura interface readline
     */
    setupReadline() {
        this.rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout,
            prompt: ''
        });

        this.rl.on('line', (input) => {
            this.handleInput(input.trim());
        });

        this.rl.on('close', () => {
            this.disconnect();
        });
    }

    /**
     * Parse argumentos da linha de comando
     */
    parseArguments() {
        const args = process.argv.slice(2);
        
        for (let i = 0; i < args.length; i++) {
            switch (args[i]) {
                case '--username':
                case '-u':
                    this.username = args[i + 1];
                    i++;
                    break;
                case '--server':
                case '-s':
                    this.serverUrl = args[i + 1];
                    i++;
                    break;
                case '--debug':
                case '-d':
                    this.debugMode = true;
                    break;
                case '--help':
                case '-h':
                    this.showHelp();
                    process.exit(0);
                    break;
            }
        }

        if (!this.username) {
            console.log(chalk.red('❌ Username é obrigatório!'));
            console.log(chalk.yellow('💡 Use: node main.js --username SeuNome'));
            process.exit(1);
        }
    }

    /**
     * Mostra ajuda
     */
    showHelp() {
        console.log(chalk.cyan('Sistema de Mensagens Seguras - Cliente CLI'));
        console.log('');
        console.log(chalk.yellow('Uso:'));
        console.log('  node main.js --username <nome> [opções]');
        console.log('');
        console.log(chalk.yellow('Opções:'));
        console.log('  -u, --username <nome>  Nome do usuário (obrigatório)');
        console.log('  -s, --server <url>     URL do servidor (padrão: localhost:3000)');
        console.log('  -d, --debug           Ativar modo debug ECDH');
        console.log('  -h, --help            Mostrar esta ajuda');
        console.log('');
        console.log(chalk.yellow('Exemplos:'));
        console.log('  node main.js --username Alice');
        console.log('  node main.js --username Bob --debug');
        console.log('  node main.js --username Charlie --server http://192.168.1.100:3000');
    }

    /**
     * Inicia o cliente
     */
    async start() {
        try {
            this.showWelcome();
            await this.connect();
            this.showMainMenu();
            this.setPrompt();
        } catch (error) {
            console.error(chalk.red('❌ Erro ao iniciar cliente:'), error.message);
            process.exit(1);
        }
    }

    /**
     * Mostra tela de boas-vindas
     */
    showWelcome() {
        console.clear();
        console.log(chalk.green('Sistema de Mensagens Seguras - IDEA + ECDH'));
        console.log(chalk.blue('Usuário:'), chalk.white(this.username));
        console.log(chalk.blue('Servidor:'), chalk.white(this.serverUrl));
        console.log(chalk.blue('Debug:'), this.debugMode ? chalk.green('Ativado') : chalk.gray('Desativado'));
        console.log('');
    }

    /**
     * Conecta ao servidor
     */
    async connect() {
        try {
            console.log(chalk.yellow('🔌 Conectando ao servidor...'));
            
            this.wsClient = new WebSocketClient(this.serverUrl, this.username, this.debugMode);
            this.messageHandler = new MessageHandler(this);
            this.commandHandler = new CommandHandler(this);
            
            // Configurar event handlers
            this.setupEventHandlers();
            
            // Conectar
            await this.wsClient.connect();
            this.isConnected = true;
            
            console.log(chalk.green('✅ Conectado com sucesso!'));
            
        } catch (error) {
            console.error(chalk.red('❌ Erro ao conectar:'), error.message);
            throw error;
        }
    }

    /**
     * Configura event handlers do WebSocket
     */
    setupEventHandlers() {
        this.wsClient.on('user_connected', (data) => {
            console.log(chalk.green('✅'), data.message);
            this.setPrompt();
        });

        this.wsClient.on('chat_started', (data) => {
            console.log(chalk.blue('💬'), data.message);
            this.currentChat = { type: 'private', target: data.targetUser };
            this.setPrompt();
        });

        this.wsClient.on('exchange_public_key', (data) => {
            // ✅ handleExchangePublicKey no websocket-client.js já processa automaticamente
            // Apenas log informativo
            if (this.debugMode) {
                console.log(chalk.yellow(''), `Recebendo chave pública de ${data.targetUser}...`);
            }
        });

        this.wsClient.on('key_exchanged', (data) => {
            console.log(chalk.green('🔑'), data.message);
        });

        this.wsClient.on('chat_ready', (data) => {
            console.log(chalk.green(''), data.message);
            this.setPrompt();
        });

        this.wsClient.on('message_received', (data) => {
            this.messageHandler.handleReceivedMessage(data);
        });

        this.wsClient.on('message_sent', (data) => {
            this.messageHandler.handleSentMessage(data);
        });

        this.wsClient.on('group_joined', (data) => {
            console.log(chalk.blue('👥'), data.message);
            this.currentChat = { type: 'group', target: data.groupName };
            this.setPrompt();
        });

        this.wsClient.on('group_left', (data) => {
            console.log(chalk.yellow('👋'), data.message);
            if (this.currentChat && this.currentChat.target === data.groupName) {
                this.currentChat = null;
            }
            this.setPrompt();
        });

        this.wsClient.on('member_left_group', (data) => {
            console.log(chalk.yellow('👋'), data.message);
            if (data.wasCreator) {
                console.log(chalk.yellow('   ⚠️  O criador do grupo saiu. Novo criador será designado.'));
            }
            console.log(chalk.blue('   🔄 Recriando chaves do grupo...'));
            this.setPrompt();
        });

        this.wsClient.on('users_list', (data) => {
            this.commandHandler.showUsersList(data);
        });

        this.wsClient.on('groups_list', (data) => {
            this.commandHandler.showGroupsList(data);
        });

        this.wsClient.on('error', (data) => {
            console.log(chalk.red(''), data.message);
            if (data.details) {
                console.log(chalk.gray('   Detalhes:'), data.details);
            }
            if (data.type) {
                console.log(chalk.gray('   Tipo:'), data.type);
            }
            if (data.sharedKeyExists !== undefined) {
                console.log(chalk.gray('   Chave compartilhada existe:'), data.sharedKeyExists ? 'Sim' : 'Não');
            }
        });

        this.wsClient.on('user_joined', (data) => {
            console.log(chalk.green(''), data.message);
        });

        this.wsClient.on('user_left', (data) => {
            console.log(chalk.gray(''), data.message);
        });

        this.wsClient.on('group_key_distributed', (data) => {
            console.log(chalk.green(''), data.message);
            // Armazenar chave de grupo
            this.wsClient.storeGroupKey(data.groupName, data.groupKey);
            console.log(chalk.blue(`🔑 Chave de grupo ${data.groupName} armazenada!`));
        });

        this.wsClient.on('group_message_received', (data) => {
            this.messageHandler.handleGroupMessage(data);
        });
    }

    /**
     * Manipula entrada do usuário
     */
    handleInput(input) {
        if (!input) {
            this.setPrompt();
            return;
        }

        // Verificar se é comando
        if (input.startsWith('/')) {
            this.commandHandler.handleCommand(input);
        } else {
            // Enviar mensagem
            this.sendMessage(input);
        }
    }

    /**
     * Envia mensagem
     * ✅ Mensagem será criptografada no WebSocketClient antes de enviar (end-to-end)
     */
    async sendMessage(message) {
        if (!this.currentChat) {
            console.log(chalk.red('❌ Você não está em nenhum chat. Use /chat <usuário> ou /group <nome>'));
            this.setPrompt();
            return;
        }

        try {
            await this.wsClient.sendMessage({
                message: message,
                targetUser: this.currentChat.target,
                isGroup: this.currentChat.type === 'group'
            });
        } catch (error) {
            console.log(chalk.red('❌ Erro ao enviar mensagem:'), error.message);
            this.setPrompt();
        }
    }

    /**
     * Define prompt baseado no estado atual
     */
    setPrompt() {
        let prompt = '';
        
        if (this.currentChat) {
            if (this.currentChat.type === 'private') {
                prompt = chalk.cyan(`[${this.username} → ${this.currentChat.target}] `);
            } else {
                prompt = chalk.blue(`[Grupo: ${this.currentChat.target}] `);
            }
        } else {
            prompt = chalk.green(`${this.username}> `);
        }
        
        this.rl.setPrompt(prompt);
        this.rl.prompt();
    }

    /**
     * Mostra menu principal
     */
    showMainMenu() {
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
        console.log(chalk.cyan('│ /debug         - Toggle modo debug      │'));
        console.log(chalk.cyan('│ /quit          - Sair do sistema        │'));
        console.log(chalk.cyan('└─────────────────────────────────────────┘'));
        console.log('');
    }

    /**
     * Desconecta do servidor
     */
    disconnect() {
        if (this.wsClient) {
            this.wsClient.disconnect();
        }
        console.log(chalk.yellow('👋 Desconectado do servidor.'));
        process.exit(0);
    }
}

// Inicializar cliente
const client = new SecureMessageClient();
client.start();

