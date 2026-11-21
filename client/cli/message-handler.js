/**
 * Manipulador de mensagens do cliente
 */

const chalk = require('chalk');

class MessageHandler {
    constructor(client) {
        this.client = client;
    }

    /**
     * Manipula mensagem recebida
     * Mensagem já foi validada e descriptografada no WebSocketClient (end-to-end)
     */
    async handleReceivedMessage(data) {
        try {
            const { from, message, envelope, timestamp } = data;
            
            // ✅ Mensagem já foi validada e descriptografada no cliente (end-to-end)
            if (!message) {
                console.log(chalk.red(`❌ Mensagem não recebida corretamente de ${from}`));
                this.client.setPrompt();
                return;
            }
            
            // Mostrar mensagem descriptografada
            const time = new Date(timestamp).toLocaleTimeString();
            console.log(chalk.green(`[${time}] ${from}:`), chalk.white(message));
            
            // Se debug ativado, mostrar envelope
            if (this.client.debugMode && envelope) {
                console.log(chalk.gray(`   [Debug] Envelope v${envelope.v}:`));
                console.log(chalk.gray(`      Timestamp: ${new Date(envelope.ts).toISOString()}`));
                console.log(chalk.gray(`      Nonce: ${envelope.nonce.substring(0, 16)}...`));
                console.log(chalk.gray(`      Tag: ${envelope.tag.substring(0, 16)}...`));
            }
            
            this.client.setPrompt();
            
        } catch (error) {
            console.log(chalk.red(`❌ Erro ao processar mensagem de ${data.from}:`));
            console.log(chalk.gray('   Detalhes:'), error.message);
            this.client.setPrompt();
        }
    }

    /**
     * Manipula mensagem de grupo recebida
     * ✅ Mensagem já foi validada e descriptografada no WebSocketClient (end-to-end)
     */
    async handleGroupMessage(data) {
        try {
            const { from, groupName, message, envelope, timestamp } = data;
            
            // ✅ Mensagem já foi validada e descriptografada no cliente (end-to-end)
            if (!message) {
                console.log(chalk.red(`❌ Mensagem de grupo não recebida corretamente de ${from}`));
                this.client.setPrompt();
                return;
            }
            
            // Mostrar mensagem no formato de grupo
            const time = new Date(timestamp).toLocaleTimeString();
            console.log(chalk.blue(`[${time}] [Grupo: ${groupName}] ${from}:`), chalk.white(message));
            
            // Se debug ativado, mostrar envelope
            if (this.client.debugMode && envelope) {
                console.log(chalk.gray(`   [Debug] Envelope v${envelope.v}:`));
                console.log(chalk.gray(`      Timestamp: ${new Date(envelope.ts).toISOString()}`));
                console.log(chalk.gray(`      Nonce: ${envelope.nonce.substring(0, 16)}...`));
                console.log(chalk.gray(`      Tag: ${envelope.tag.substring(0, 16)}...`));
            }
            
            this.client.setPrompt();
            
        } catch (error) {
            console.log(chalk.red(`❌ Erro ao processar mensagem de grupo de ${data.from}:`));
            console.log(chalk.gray('   Detalhes:'), error.message);
            this.client.setPrompt();
        }
    }

    /**
     * Manipula mensagem enviada
     */
    handleSentMessage(data) {
        const { message, envelope, target, isGroup } = data;
        
        if (this.client.debugMode && envelope) {
            console.log(chalk.white(`🔍 Debug - Envelope enviado:`));
            console.log(chalk.white(`   Original: ${message}`));
            console.log(chalk.white(`   Envelope v${envelope.v}:`));
            console.log(chalk.white(`      Timestamp: ${new Date(envelope.ts).toISOString()}`));
            console.log(chalk.white(`      From: ${envelope.from}`));
            console.log(chalk.white(`      To: ${envelope.to}`));
            console.log(chalk.white(`      Nonce: ${envelope.nonce.substring(0, 16)}...`));
            console.log(chalk.white(`      CT: ${envelope.ct.substring(0, 32)}...`));
            console.log(chalk.white(`      Tag: ${envelope.tag.substring(0, 16)}...`));
            
            // Buscar e mostrar a chave usada
            let key = null;
            if (isGroup) {
                key = this.client.wsClient.groupKeys.get(target);
                if (key) {
                    console.log(chalk.white(`   Chave de grupo (${target}): ${key.toString('hex')}`));
                } else {
                    console.log(chalk.yellow(`   ⚠️  Chave de grupo não encontrada para ${target}`));
                }
            } else {
                key = this.client.wsClient.sharedKeys.get(target);
                if (key) {
                    console.log(chalk.white(`   Chave compartilhada (${target}): ${key.toString('hex')}`));
                } else {
                    console.log(chalk.yellow(`   ⚠️  Chave compartilhada não encontrada com ${target}`));
                }
            }
        }
        
        // A mensagem já foi enviada, apenas mostrar confirmação
        console.log(chalk.green(`✅ Mensagem enviada para ${target}`));
        this.client.setPrompt();
    }
}

module.exports = MessageHandler;
