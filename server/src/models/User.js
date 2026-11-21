/**
 * User model
 * End-to-end: the server only stores PUBLIC keys
 * (ECDH public key, Ed25519 public key and the signature over the ECDH key)
 */

class User {
    constructor(username, socketId) {
        this.username = username;
        this.socketId = socketId;
        this.isOnline = true;
        this.connectedAt = new Date();
        this.publicKey = null;        // ECDH public key (the private key stays on the client)
        this.ed25519PublicKey = null; // Ed25519 public key, for verification
        this.signature = null;        // Ed25519 signature over the ECDH key
        this.currentChat = null;      // Active chat
        this.currentGroup = null;     // Active group
    }

    /**
     * Sets the user's public key and authentication credentials
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

    setCurrentChat(chatType, target) {
        this.currentChat = { type: chatType, target: target };
    }

    clearCurrentChat() {
        this.currentChat = null;
    }

    isInChat() {
        return this.currentChat !== null;
    }

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

    setOffline() {
        this.isOnline = false;
    }

    setOnline() {
        this.isOnline = true;
    }
}

module.exports = User;
