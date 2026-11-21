/**
 * CLI command handler
 */

const chalk = require('chalk');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { getKeypairFile, getTofuStore } = require('../crypto/ed25519-tofu');

const COMMANDS = [
    ['/help', 'Show this help'],
    ['/users', 'List online users'],
    ['/chat <user>', 'Start a 1:1 chat'],
    ['/group <name>', 'Create or join a group'],
    ['/groups', 'List groups'],
    ['/leave', 'Leave the current chat/group'],
    ['/status', 'Connection status'],
    ['/keys', 'Show your keys'],
    ['/debug', 'Toggle debug mode'],
    ['/newprofile', 'Simulate a reinstall'],
    ['/delete @user', "Forget a user's TOFU pin"],
    ['/quit', 'Exit']
];

const LINE = '─────────────────────────────────────────────────────────────';

class CommandHandler {
    constructor(client) {
        this.client = client;
    }

    /**
     * Dispatches a user command
     */
    handleCommand(input) {
        const parts = input.split(' ').filter(Boolean);
        const command = parts[0].toLowerCase();
        const args = parts.slice(1);

        switch (command) {
            case '/help':
                this.showHelp();
                break;
            case '/users':
                this.client.wsClient.listUsers();
                break;
            case '/chat':
                this.startChat(args);
                break;
            case '/group':
                this.joinGroup(args);
                break;
            case '/groups':
                this.client.wsClient.listGroups();
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
                console.log(chalk.red('❌ Unknown command. Use /help to list commands.'));
                this.client.setPrompt();
        }
    }

    /**
     * Prints the command table
     */
    printCommands() {
        const width = 48;
        console.log(chalk.cyan('┌' + '─'.repeat(width) + '┐'));
        console.log(chalk.cyan('│ ' + 'Available commands:'.padEnd(width - 1) + '│'));
        console.log(chalk.cyan('│' + ' '.repeat(width) + '│'));
        for (const [cmd, desc] of COMMANDS) {
            console.log(chalk.cyan('│ ' + `${cmd.padEnd(15)}- ${desc}`.padEnd(width - 1) + '│'));
        }
        console.log(chalk.cyan('└' + '─'.repeat(width) + '┘'));
        console.log('');
    }

    /**
     * Shows help
     */
    showHelp() {
        this.printCommands();
        console.log(chalk.yellow('💡 Tips:'));
        console.log('   - To send a message, just type it (no /)');
        console.log('   - Use /chat <user> for a 1:1 conversation');
        console.log('   - Use /group <name> to create/join groups');
        console.log('   - Use /debug to see every cryptographic step');
        console.log('');
        console.log(chalk.cyan('🔒 Security (TOFU):'));
        console.log('   - /newprofile: simulates a reinstall (new identity)');
        console.log('   - /delete @user: forgets a pin (accepts a new identity)');
        console.log('   - Useful when someone legitimately reinstalls');
        this.client.setPrompt();
    }

    /**
     * Prints the user list
     */
    showUsersList(data) {
        console.log(chalk.blue('👥 Online users:'));

        if (data.users.length === 0) {
            console.log(chalk.gray('   Nobody online'));
        } else {
            data.users.forEach(user => {
                const status = user.isInChat ? chalk.yellow('(in a chat)') : chalk.green('(available)');
                console.log(chalk.white(`   - ${user.username}`), status);
            });
        }

        console.log(chalk.blue(`Total: ${data.count} user(s)`));
        this.client.setPrompt();
    }

    /**
     * Starts a 1:1 chat
     */
    startChat(args) {
        if (args.length === 0) {
            console.log(chalk.red('❌ Usage: /chat <user>'));
            this.client.setPrompt();
            return;
        }

        const targetUser = args[0];

        if (targetUser === this.client.username) {
            console.log(chalk.red('❌ You cannot chat with yourself'));
            this.client.setPrompt();
            return;
        }

        console.log(chalk.yellow(`Starting chat with ${targetUser}...`));
        this.client.wsClient.startChat(targetUser);
    }

    /**
     * Joins a group
     */
    joinGroup(args) {
        if (args.length === 0) {
            console.log(chalk.red('❌ Usage: /group <name>'));
            this.client.setPrompt();
            return;
        }

        const groupName = args[0];
        console.log(chalk.yellow(`👥 Joining group "${groupName}"...`));
        this.client.wsClient.joinGroup(groupName);
    }

    /**
     * Prints the group list
     */
    showGroupsList(data) {
        console.log(chalk.blue('👥 Groups:'));

        if (data.groups.length === 0) {
            console.log(chalk.gray('   No groups'));
        } else {
            data.groups.forEach(group => {
                const status = group.keysEstablished ? chalk.green('(secure)') : chalk.yellow('(setting up)');
                console.log(chalk.white(`   - ${group.name}`), status);
                console.log(chalk.gray(`     Members: ${group.members.join(', ')}`));
            });
        }

        console.log(chalk.blue(`Total: ${data.count} group(s)`));
        this.client.setPrompt();
    }

    /**
     * Leaves the current chat (or group: this triggers a re-key)
     */
    leaveChat() {
        if (!this.client.currentChat) {
            console.log(chalk.yellow('⚠️  You are not in a chat'));
            this.client.setPrompt();
            return;
        }

        if (this.client.currentChat.type === 'group') {
            const groupName = this.client.currentChat.target;
            console.log(chalk.yellow(`👋 Leaving group "${groupName}"...`));
            this.client.wsClient.leaveGroup(groupName);
        } else {
            console.log(chalk.yellow('👋 Leaving chat...'));
            this.client.wsClient.leaveChat();
        }
        this.client.currentChat = null;
    }

    /**
     * Shows connection status
     */
    showStatus() {
        const status = this.client.wsClient.getStatus();
        const chat = this.client.currentChat;

        console.log(chalk.blue('Connection status:'));
        console.log(chalk.white(`   - Server: ${this.client.serverUrl}`), status.isConnected ? chalk.green('✅') : chalk.red('❌'));
        console.log(chalk.white(`   - User: ${status.username}`));
        console.log(chalk.white(`   - ECDH keys: ${status.hasPublicKey ? '✅' : '❌'}`));
        console.log(chalk.white(`   - Session keys: ${status.sharedKeysCount}`));
        console.log(chalk.white(`   - Active chat: ${chat ? `${chat.target} (${chat.type === 'private' ? '1:1' : 'group'})` : 'none'}`));
        console.log(chalk.white(`   - Debug mode: ${this.client.debugMode ? 'on' : 'off'}`));
        this.client.setPrompt();
    }

    /**
     * Shows every key (including private ones, for study purposes)
     */
    showKeys() {
        const keyInfo = this.client.wsClient.getKeyInfo();

        if (keyInfo.error) {
            console.log(chalk.red(`❌ ${keyInfo.error}`));
            this.client.setPrompt();
            return;
        }

        console.log(chalk.blue('🔑 Key information:\n'));

        // ==================== PILLAR: INTEGRITY ====================
        console.log(chalk.magenta('┌─────────────────────────────────────────────────────────────┐'));
        console.log(chalk.magenta('│              🛡️  PILLAR: INTEGRITY                          │'));
        console.log(chalk.magenta('│         (Persistent identity - Ed25519)                     │'));
        console.log(chalk.magenta('└─────────────────────────────────────────────────────────────┘\n'));

        try {
            const ed25519KeypairFile = getKeypairFile(this.client.username);

            if (fs.existsSync(ed25519KeypairFile)) {
                const ed25519Data = JSON.parse(fs.readFileSync(ed25519KeypairFile, 'utf8'));

                if (!ed25519Data || !ed25519Data.publicKey || !ed25519Data.privateKey) {
                    throw new Error('Ed25519 file is corrupted or incomplete');
                }

                const fingerprint = crypto.createHash('sha256')
                    .update(Buffer.from(ed25519Data.publicKey, 'hex'))
                    .digest('hex');

                console.log(chalk.cyan('ED25519 - Long-term identity:'));
                console.log(chalk.gray(LINE));
                console.log(chalk.gray(`📄 File: ${path.relative(process.cwd(), ed25519KeypairFile)}\n`));

                console.log(chalk.red('🔴 Private key (NEVER share):'));
                console.log(chalk.gray(`   ${ed25519Data.privateKey.substring(0, 64)}...`));
                console.log(chalk.gray(`   (${ed25519Data.privateKey.length} chars / ${ed25519Data.privateKey.length / 2} bytes)`));
                console.log(chalk.gray('   Used to: sign ephemeral ECDH keys\n'));

                console.log(chalk.green('🔵 Public key (shared freely):'));
                console.log(chalk.gray(`   ${ed25519Data.publicKey.substring(0, 64)}...`));
                console.log(chalk.gray(`   (${ed25519Data.publicKey.length} chars / ${ed25519Data.publicKey.length / 2} bytes)`));
                console.log(chalk.gray('   Used by: others, to verify my signatures\n'));

                console.log(chalk.yellow('🔍 Fingerprint (unique identity):'));
                console.log(chalk.white(`   ${fingerprint}`));
                console.log(chalk.gray('   (SHA-256 of the public key)'));
                console.log(chalk.gray('   Used for: TOFU - detecting identity changes\n'));

                // TOFU store - known identities
                const tofuFile = getTofuStore(this.client.username);
                console.log(chalk.gray(LINE));
                console.log(chalk.cyan('TOFU - Known identities (Trust On First Use):'));
                console.log(chalk.gray(LINE));
                console.log(chalk.gray(`📄 File: ${path.relative(process.cwd(), tofuFile)}\n`));

                if (fs.existsSync(tofuFile)) {
                    const pinnedKeys = JSON.parse(fs.readFileSync(tofuFile, 'utf8'));
                    const peers = Object.entries(pinnedKeys);

                    if (peers.length > 0) {
                        console.log(chalk.white(`Stored identities: ${peers.length}\n`));

                        peers.forEach(([peerName, data]) => {
                            if (!data || !data.ed25519PubHex) {
                                console.log(chalk.red(`❌ Invalid data for ${peerName}\n`));
                                return;
                            }

                            console.log(chalk.white(`👤 ${peerName}:`));
                            console.log(chalk.gray(`   Public key: ${data.ed25519PubHex.substring(0, 40)}...`));
                            console.log(chalk.yellow(`   Fingerprint: ${data.fingerprint}`));
                            console.log(chalk.gray(`   First seen: ${new Date(data.firstSeen).toLocaleString()}`));
                            console.log(chalk.green('   Status: ✓ known, trusted identity\n'));
                        });
                    } else {
                        console.log(chalk.gray('No identities stored yet.'));
                        console.log(chalk.gray('(They are stored the first time you talk to someone)\n'));
                    }
                } else {
                    console.log(chalk.gray('TOFU file not created yet.'));
                    console.log(chalk.gray('(It is created the first time you talk to someone)\n'));
                }

            } else {
                console.log(chalk.yellow('❌ Ed25519 file not found.'));
                console.log(chalk.gray('(It is created when you connect)\n'));
            }

        } catch (error) {
            console.log(chalk.red('❌ Error loading Ed25519 information:'), error.message);
            console.log('');
        }

        // ==================== PILLAR: CONFIDENTIALITY ====================
        console.log(chalk.magenta('┌─────────────────────────────────────────────────────────────┐'));
        console.log(chalk.magenta('│           🔐 PILLAR: CONFIDENTIALITY                        │'));
        console.log(chalk.magenta('│           (Ephemeral session keys)                          │'));
        console.log(chalk.magenta('└─────────────────────────────────────────────────────────────┘\n'));

        console.log(chalk.cyan('ECDH - Ephemeral key:'));
        console.log(chalk.gray(LINE));
        console.log(chalk.yellow('⚠️  Generated on EVERY CONNECTION (discarded on disconnect)\n'));

        if (keyInfo.hasPrivateKey) {
            console.log(chalk.red('🔴 ECDH private key (in memory only):'));
            console.log(chalk.gray(`   ${keyInfo.privateKeyHex}`));
            console.log(chalk.gray(`   (${keyInfo.privateKeyHex.length / 2} bytes)`));
            console.log(chalk.gray(`   Curve: ${keyInfo.curve}`));
            console.log(chalk.gray('   Used to: compute the ECDH shared secret\n'));
        }

        if (keyInfo.hasPublicKey) {
            console.log(chalk.green('🔵 ECDH public key (sent to others):'));
            console.log(chalk.gray(`   ${keyInfo.publicKeyHex}`));
            console.log(chalk.gray(`   (${keyInfo.publicKeyHex.length / 2} bytes)`));
            console.log(chalk.gray(`   Curve: ${keyInfo.curve}`));
            console.log(chalk.gray('   Used by: others, to compute the shared secret with you\n'));
        }

        console.log(chalk.gray(LINE));
        console.log(chalk.cyan('Derived session keys (HKDF):'));
        console.log(chalk.gray(LINE));
        console.log(chalk.yellow('⚠️  Kept in memory (lost on disconnect)'));
        console.log(chalk.yellow('⚠️  Derived via HKDF from the ECDH shared secret\n'));

        if (keyInfo.sharedKeysCount > 0) {
            console.log(chalk.white(`Total: ${keyInfo.sharedKeysCount} active key(s)\n`));

            this.client.wsClient.sharedKeys.forEach((key, peer) => {
                if (peer.includes(':')) {
                    const [groupName, peerName] = peer.split(':');
                    console.log(chalk.white(`👥 Group "${groupName}" with ${peerName}:`));
                } else {
                    console.log(chalk.white(`👤 1:1 chat with ${peer}:`));
                }
                console.log(chalk.gray(`   encKey (AES-128-GCM): ${key.toString('hex')}`));
                console.log(chalk.gray(`   (${key.length} bytes / ${key.length * 8} bits)`));
                console.log(chalk.gray('   Derived via: HKDF-SHA256(ECDH shared secret)\n'));
            });
        } else {
            console.log(chalk.gray('No session keys established yet.'));
            console.log(chalk.gray('(Use /chat <user> to start a key exchange)\n'));
        }

        console.log(chalk.gray(LINE));
        console.log(chalk.cyan('Group keys:'));
        console.log(chalk.gray(LINE));
        console.log(chalk.yellow('⚠️  Kept in memory (lost on disconnect)'));
        console.log(chalk.yellow('⚠️  Generated by the creator and distributed inside envelopes\n'));

        if (keyInfo.groupKeysCount > 0) {
            console.log(chalk.white(`Total: ${keyInfo.groupKeysCount} active group(s)\n`));

            this.client.wsClient.groupKeys.forEach((key, groupName) => {
                console.log(chalk.white(`👥 Group "${groupName}":`));
                console.log(chalk.gray(`   Group key (AES-128-GCM): ${key.toString('hex')}`));
                console.log(chalk.gray(`   (${key.length} bytes / ${key.length * 8} bits)`));
                console.log(chalk.gray('   Type: random (generated by the creator)'));
                console.log(chalk.gray('   Received: inside an envelope encrypted with a pairwise key\n'));
            });
        } else {
            console.log(chalk.gray('No group keys yet.'));
            console.log(chalk.gray('(Use /group <name> to create/join a group)\n'));
        }

        this.client.setPrompt();
    }

    /**
     * Toggles debug mode
     */
    toggleDebug() {
        this.client.debugMode = !this.client.debugMode;
        this.client.wsClient.debugMode = this.client.debugMode;
        console.log(chalk.blue(`Debug mode: ${this.client.debugMode ? 'on' : 'off'}`));
        this.client.setPrompt();
    }

    /**
     * Simulates an app reinstall (deletes the local identity)
     */
    newProfile() {
        console.log(chalk.yellow('\n⚠️  WARNING: you are about to DELETE your current profile!'));
        console.log(chalk.yellow('   This removes:'));
        console.log(chalk.gray('   • Your Ed25519 identity (long-term key)'));
        console.log(chalk.gray('   • Every stored TOFU identity'));
        console.log(chalk.gray('   • Every active session key'));
        console.log('');
        console.log(chalk.red('   This cannot be undone!'));
        console.log(chalk.yellow('\n   It simulates uninstalling and reinstalling the app.'));
        console.log(chalk.yellow('   Other users will get a TOFU alert when talking to you.\n'));

        const ed25519File = getKeypairFile(this.client.username);
        const tofuFile = getTofuStore(this.client.username);
        const deleted = [];

        if (fs.existsSync(ed25519File)) {
            fs.unlinkSync(ed25519File);
            deleted.push('✓ Ed25519 identity deleted');
        }

        if (fs.existsSync(tofuFile)) {
            fs.unlinkSync(tofuFile);
            deleted.push('✓ TOFU store deleted');
        }

        this.client.wsClient.clearSession();
        deleted.push('✓ Current session cleared');

        console.log(chalk.green('\n🔄 Profile reset:'));
        deleted.forEach(msg => console.log(chalk.green(`   ${msg}`)));

        console.log(chalk.yellow('\n⚠️  You need to RECONNECT to generate a new profile:'));
        console.log(chalk.cyan('   1. Use /quit to disconnect'));
        console.log(chalk.cyan('   2. Run again:'));
        console.log(chalk.white(`      node client/cli/main.js --username ${this.client.username}`));
        console.log(chalk.cyan('   3. A new Ed25519 key pair will be generated automatically\n'));

        this.client.setPrompt();
    }

    /**
     * Deletes the TOFU pin of a specific user
     */
    deleteTofuPin(args) {
        if (args.length === 0) {
            console.log(chalk.red('❌ Usage: /delete @user'));
            console.log(chalk.gray('   Example: /delete @Alice'));
            this.client.setPrompt();
            return;
        }

        const targetUser = args[0].replace(/^@/, '');

        if (targetUser === this.client.username) {
            console.log(chalk.red('❌ You cannot delete your own profile this way'));
            console.log(chalk.yellow('   Use /newprofile to reset your profile'));
            this.client.setPrompt();
            return;
        }

        const tofuFile = getTofuStore(this.client.username);

        if (!fs.existsSync(tofuFile)) {
            console.log(chalk.yellow('⚠️  You have no TOFU records yet'));
            this.client.setPrompt();
            return;
        }

        try {
            const pins = JSON.parse(fs.readFileSync(tofuFile, 'utf8'));

            if (!pins[targetUser]) {
                console.log(chalk.yellow(`⚠️  You have no TOFU record for ${targetUser}`));
                console.log(chalk.gray(`   Recorded users: ${Object.keys(pins).join(', ') || 'none'}`));
                this.client.setPrompt();
                return;
            }

            const oldFingerprint = pins[targetUser].fingerprint;
            delete pins[targetUser];
            fs.writeFileSync(tofuFile, JSON.stringify(pins, null, 2));

            console.log(chalk.green(`\n✅ TOFU record for ${targetUser} deleted!`));
            console.log(chalk.gray(`   Removed fingerprint: ${oldFingerprint.substring(0, 16)}...`));
            console.log(chalk.yellow(`\n⚠️  Next time you talk to ${targetUser}:`));
            console.log(chalk.cyan('   • It will be treated as a FIRST CONNECTION'));
            console.log(chalk.cyan('   • The new fingerprint will be stored'));
            console.log(chalk.cyan(`   • Use this only if you know ${targetUser} really reset their profile\n`));

        } catch (err) {
            console.log(chalk.red(`❌ Error deleting TOFU record: ${err.message}`));
        }

        this.client.setPrompt();
    }

    /**
     * Exits
     */
    quit() {
        console.log(chalk.yellow('👋 Exiting...'));
        this.client.disconnect();
    }
}

module.exports = CommandHandler;
