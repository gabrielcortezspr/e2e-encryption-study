/**
 * Modelo de Usuário para o sistema de mensagens
 * End-to-End Encryption: Servidor armazena apenas chaves públicas
 * Integridade: Armazena também chave pública Ed25519 e assinatura
 */

class User {
    constructor(username, socketId) {
        this.username = username;
        this.socketId = socketId;
        this.isOnline = true;
        this.connectedAt = new Date();
        this.publicKey = null; // ✅ Chave pública ECDH (chave privada fica no cliente)
        this.ed25519PublicKey = null; // ✅ Chave pública Ed25519 para verificação
        this.signature = null; // ✅ Assinatura da chave ECDH
        this.currentChat = null; // Chat ativo atual
        this.currentGroup = null; // Grupo ativo atual
    }

    /**
     * Define a chave pública do usuário e credenciais de autenticação
     * ✅ Apenas chaves públicas são armazenadas no servidor
     */
    setPublicKey(publicKey, ed25519Pub = null, signature = null) {
        this.publicKey = publicKey;
        if (ed25519Pub) {
            this.ed25519PublicKey = ed25519Pub;
        }
        if (signature) {
            this.signature = signature;
        }
    }

    /**
     * Define chat ativo
     */
    setCurrentChat(chatType, target) {
        this.currentChat = { type: chatType, target: target };
    }

    /**
     * Limpa chat ativo
     */
    clearCurrentChat() {
        this.currentChat = null;
    }

    /**
     * Verifica se está em um chat
     */
    isInChat() {
        return this.currentChat !== null;
    }

    /**
     * Retorna informações do usuário
     */
    getInfo() {
        return {
            username: this.username,
            isOnline: this.isOnline,
            connectedAt: this.connectedAt,
            hasPublicKey: !!this.publicKey,
            hasEd25519Key: !!this.ed25519PublicKey,
            hasSignature: !!this.signature,
            currentChat: this.currentChat,
            currentGroup: this.currentGroup
        };
    }

    /**
     * Marca usuário como offline
     */
    setOffline() {
        this.isOnline = false;
    }

    /**
     * Marca usuário como online
     */
    setOnline() {
        this.isOnline = true;
    }
}

module.exports = User;

