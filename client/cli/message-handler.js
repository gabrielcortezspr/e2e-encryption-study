/**
 * Displays received and sent messages
 * (messages arrive here already validated and decrypted by WebSocketClient)
 */

const chalk = require('chalk');

class MessageHandler {
    constructor(client) {
        this.client = client;
    }

    printEnvelope(envelope) {
        console.log(chalk.gray(`   [Debug] Envelope v${envelope.v}:`));
        console.log(chalk.gray(`      Timestamp: ${new Date(envelope.ts).toISOString()}`));
        console.log(chalk.gray(`      Nonce: ${envelope.nonce.substring(0, 16)}...`));
        console.log(chalk.gray(`      Tag: ${envelope.tag.substring(0, 16)}...`));
    }

    /**
     * Received private message
     */
    async handleReceivedMessage(data) {
        const { from, message, envelope, timestamp } = data;

        if (!message) {
            console.log(chalk.red(`❌ Message from ${from} was not received correctly`));
            this.client.setPrompt();
            return;
        }

        const time = new Date(timestamp).toLocaleTimeString();
        console.log(chalk.green(`[${time}] ${from}:`), chalk.white(message));

        if (this.client.debugMode && envelope) {
            this.printEnvelope(envelope);
        }

        this.client.setPrompt();
    }

    /**
     * Received group message
     */
    async handleGroupMessage(data) {
        const { from, groupName, message, envelope, timestamp } = data;

        if (!message) {
            console.log(chalk.red(`❌ Group message from ${from} was not received correctly`));
            this.client.setPrompt();
            return;
        }

        const time = new Date(timestamp).toLocaleTimeString();
        console.log(chalk.blue(`[${time}] [Group: ${groupName}] ${from}:`), chalk.white(message));

        if (this.client.debugMode && envelope) {
            this.printEnvelope(envelope);
        }

        this.client.setPrompt();
    }

    /**
     * Sent message (local confirmation)
     */
    handleSentMessage(data) {
        const { message, envelope, target, isGroup } = data;

        if (this.client.debugMode && envelope) {
            console.log(chalk.white('🔍 Debug - envelope sent:'));
            console.log(chalk.white(`   Original: ${message}`));
            console.log(chalk.white(`   Envelope v${envelope.v}:`));
            console.log(chalk.white(`      Timestamp: ${new Date(envelope.ts).toISOString()}`));
            console.log(chalk.white(`      From: ${envelope.from}`));
            console.log(chalk.white(`      To: ${envelope.to}`));
            console.log(chalk.white(`      Nonce: ${envelope.nonce.substring(0, 16)}...`));
            console.log(chalk.white(`      CT: ${envelope.ct.substring(0, 32)}...`));
            console.log(chalk.white(`      Tag: ${envelope.tag.substring(0, 16)}...`));
            console.log(chalk.white(`   Full envelope (for tools/decrypt-envelope.js):`));
            console.log(chalk.gray(`   ${JSON.stringify(envelope)}`));

            const key = isGroup
                ? this.client.wsClient.groupKeys.get(target)
                : this.client.wsClient.sharedKeys.get(target);
            if (key) {
                console.log(chalk.white(`   ${isGroup ? 'Group' : 'Session'} key (${target}): ${key.toString('hex')}`));
            } else {
                console.log(chalk.yellow(`   ⚠️  No key found for ${target}`));
            }
        }

        console.log(chalk.green(`✅ Message sent to ${target}`));
        this.client.setPrompt();
    }
}

module.exports = MessageHandler;
