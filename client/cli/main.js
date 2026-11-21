#!/usr/bin/env node
/**
 * CLI client entry point
 * Usage: node client/cli/main.js --username Alice [--server URL] [--debug]
 */

const path = require('path');

// Load environment variables (path relative to this file, not to the cwd)
require('dotenv').config({ path: path.join(__dirname, '..', '..', 'config.env'), quiet: true });

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

        this.parseArguments();
        this.setupReadline();
    }

    /**
     * Sets up the readline interface
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
     * Parses command-line arguments
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
            console.log(chalk.red('❌ Username is required!'));
            console.log(chalk.yellow('💡 Use: node client/cli/main.js --username YourName'));
            process.exit(1);
        }
    }

    /**
     * Shows usage help
     */
    showHelp() {
        console.log(chalk.cyan('E2E Encryption Study - CLI client'));
        console.log('');
        console.log(chalk.yellow('Usage:'));
        console.log('  node client/cli/main.js --username <name> [options]');
        console.log('');
        console.log(chalk.yellow('Options:'));
        console.log('  -u, --username <name>  User name (required)');
        console.log('  -s, --server <url>     Server URL (default: NODE_URL or http://localhost:6666)');
        console.log('  -d, --debug            Show detailed cryptography logs');
        console.log('  -h, --help             Show this help');
        console.log('');
        console.log(chalk.yellow('Examples:'));
        console.log('  node client/cli/main.js --username Alice');
        console.log('  node client/cli/main.js --username Bob --debug');
        console.log('  node client/cli/main.js --username Charlie --server http://192.168.1.100:6666');
    }

    /**
     * Starts the client
     */
    async start() {
        try {
            this.showWelcome();
            await this.connect();
            this.showMainMenu();
            this.setPrompt();
        } catch (error) {
            console.error(chalk.red('❌ Error starting client:'), error.message);
            process.exit(1);
        }
    }

    /**
     * Welcome screen
     */
    showWelcome() {
        console.clear();
        console.log(chalk.green('E2E Encryption Study - ECDH + Ed25519 + AES-GCM'));
        console.log(chalk.blue('User:'), chalk.white(this.username));
        console.log(chalk.blue('Server:'), chalk.white(this.serverUrl));
        console.log(chalk.blue('Debug:'), this.debugMode ? chalk.green('On') : chalk.gray('Off'));
        console.log('');
    }

    /**
     * Connects to the server
     */
    async connect() {
        try {
            console.log(chalk.yellow('🔌 Connecting to server...'));

            this.wsClient = new WebSocketClient(this.serverUrl, this.username, this.debugMode);
            this.messageHandler = new MessageHandler(this);
            this.commandHandler = new CommandHandler(this);

            this.setupEventHandlers();

            await this.wsClient.connect();
            this.isConnected = true;

        } catch (error) {
            console.error(chalk.red('❌ Error connecting:'), error.message);
            throw error;
        }
    }

    /**
     * Wires WebSocket client events to the UI
     */
    setupEventHandlers() {
        this.wsClient.on('user_connected', (data) => {
            console.log(chalk.green('✅'), data.message);
        });

        this.wsClient.on('chat_started', (data) => {
            console.log(chalk.blue('💬'), data.message);
            this.currentChat = { type: 'private', target: data.targetUser };
            this.setPrompt();
        });

        this.wsClient.on('exchange_public_key', (data) => {
            // Key processing is done in WebSocketClient.handleExchangePublicKey
            if (this.debugMode) {
                console.log(chalk.yellow('🔑'), `Received public key from ${data.targetUser}`);
            }
        });

        this.wsClient.on('key_exchanged', (data) => {
            console.log(chalk.green('🔑'), data.message);
        });

        this.wsClient.on('chat_ready', (data) => {
            console.log(chalk.green('🔒'), data.message);
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
                console.log(chalk.yellow('   ⚠️  The group creator left. A new creator will be assigned.'));
            }
            console.log(chalk.blue('   🔄 Re-keying the group...'));
            this.setPrompt();
        });

        this.wsClient.on('users_list', (data) => {
            this.commandHandler.showUsersList(data);
        });

        this.wsClient.on('groups_list', (data) => {
            this.commandHandler.showGroupsList(data);
        });

        this.wsClient.on('error', (data) => {
            console.log(chalk.red('❌'), data.message);
            if (data.details) {
                console.log(chalk.gray('   Details:'), data.details);
            }
            if (data.type) {
                console.log(chalk.gray('   Type:'), data.type);
            }
            if (this.rl) this.setPrompt();
        });

        this.wsClient.on('user_joined', (data) => {
            console.log(chalk.green('➕'), data.message);
        });

        this.wsClient.on('user_left', (data) => {
            console.log(chalk.gray('➖'), data.message);
        });

        this.wsClient.on('group_message_received', (data) => {
            this.messageHandler.handleGroupMessage(data);
        });
    }

    /**
     * Handles user input
     */
    handleInput(input) {
        if (!input) {
            this.setPrompt();
            return;
        }

        if (input.startsWith('/')) {
            this.commandHandler.handleCommand(input);
        } else {
            this.sendMessage(input);
        }
    }

    /**
     * Sends a message (encrypted in WebSocketClient before leaving the client)
     */
    async sendMessage(message) {
        if (!this.currentChat) {
            console.log(chalk.red('❌ You are not in a chat. Use /chat <user> or /group <name>'));
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
            console.log(chalk.red('❌ Error sending message:'), error.message);
            this.setPrompt();
        }
    }

    /**
     * Sets the prompt based on the current state
     */
    setPrompt() {
        let prompt;

        if (this.currentChat) {
            if (this.currentChat.type === 'private') {
                prompt = chalk.cyan(`[${this.username} → ${this.currentChat.target}] `);
            } else {
                prompt = chalk.blue(`[Group: ${this.currentChat.target}] `);
            }
        } else {
            prompt = chalk.green(`${this.username}> `);
        }

        this.rl.setPrompt(prompt);
        this.rl.prompt();
    }

    /**
     * Main menu
     */
    showMainMenu() {
        this.commandHandler.printCommands();
    }

    /**
     * Disconnects from the server
     */
    disconnect() {
        if (this.wsClient) {
            this.wsClient.disconnect();
        }
        console.log(chalk.yellow('👋 Disconnected from server.'));
        process.exit(0);
    }
}

const client = new SecureMessageClient();
client.start();
