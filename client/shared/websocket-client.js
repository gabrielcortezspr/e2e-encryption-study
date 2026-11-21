/**
 * WebSocket client: protocol + all client-side cryptography
 *
 * End-to-end: private keys never leave the client; the server only relays
 * public keys and already-encrypted envelopes.
 * Integrity: Ed25519 signatures + TOFU pinning + HKDF + AEAD envelope.
 */

const io = require('socket.io-client');
const EventEmitter = require('events');
const crypto = require('crypto');
const ECDHManual = require('../crypto/ecdh-manual');
const { setUsername, signECDHPublicKey, verifyAndPinPeer, ensureEd25519KeyPair } = require('../crypto/ed25519-tofu');
const { deriveSessionKeys } = require('../crypto/hkdf');
const { encryptMessage, decryptMessage } = require('../crypto/envelope');

// Server events that are simply forwarded to the UI
const FORWARDED_EVENTS = [
    'chat_started', 'key_exchanged', 'chat_ready', 'message_sent',
    'group_joined', 'member_joined_group', 'users_list', 'groups_list',
    'chat_left', 'user_joined', 'error'
];

class WebSocketClient extends EventEmitter {
    constructor(serverUrl, username, debugMode = false) {
        super();
        this.serverUrl = serverUrl;
        this.username = username;
        this.socket = null;
        this.isConnected = false;
        this.publicKey = null;
        this.ecdh = null;               // Client ECDH instance (ephemeral)
        this.sharedKeys = new Map();    // Pairwise session keys: peer or "group:peer" -> Buffer
        this.groupKeys = new Map();     // Group keys: groupName -> Buffer
        this.debugMode = debugMode;
        this.processedKeys = new Set(); // Public keys already processed (avoids loops)

        // Key files are named after the user
        setUsername(username);
    }

    /**
     * Connects to the server.
     * Generates ECDH keys locally (the private key stays on the client)
     * and signs the ECDH public key with Ed25519.
     */
    async connect() {
        return new Promise((resolve, reject) => {
            try {
                if (this.debugMode) {
                    console.log('\n╔═══════════════════════════════════════════════════════════════╗');
                    console.log('║              🔐 SECURITY PILLARS - CONNECTION                 ║');
                    console.log('╚═══════════════════════════════════════════════════════════════╝');
                    console.log('\n┌─── PILLAR: INTEGRITY ────────────────────────────────────────┐');
                }

                // Persistent Ed25519 identity (TOFU)
                ensureEd25519KeyPair(this.debugMode);

                if (this.debugMode) {
                    console.log('└──────────────────────────────────────────────────────────────┘');
                    console.log('\n┌─── PILLAR: CONFIDENTIALITY ──────────────────────────────────┐');
                }
                this.ecdh = new ECDHManual(false);
                const keyPair = this.ecdh.generateKeyPair();
                this.publicKey = keyPair.publicKey.toString('hex');
                if (this.debugMode) {
                    console.log('│ ✓ ECDH keys generated (private key kept locally)');
                }

                // Sign the ECDH public key with Ed25519
                if (this.debugMode) {
                    console.log('└──────────────────────────────────────────────────────────────┘');
                    console.log('\n┌─── PILLAR: INTEGRITY (Key Authentication) ───────────────────┐');
                }
                const signedKey = signECDHPublicKey(this.publicKey, this.debugMode);
                if (this.debugMode) {
                    console.log('└──────────────────────────────────────────────────────────────┘\n');
                }

                this.socket = io(this.serverUrl, {
                    transports: ['websocket'],
                    timeout: 10000
                });

                let registered = false;

                this.socket.on('connect', () => {
                    if (!this.debugMode) {
                        console.log('✓ Connected to WebSocket server');
                    }
                    this.isConnected = true;

                    // Send the signed ECDH public key + Ed25519 public key
                    this.socket.emit('user_connect', {
                        username: this.username,
                        publicKey: this.publicKey,
                        ed25519Pub: signedKey.ed25519Pub,
                        signature: signedKey.signature
                    });
                });

                this.socket.on('disconnect', () => {
                    console.log('Disconnected from server');
                    this.isConnected = false;
                });

                this.socket.on('connect_error', (error) => {
                    console.error('Connection error:', error.message);
                    reject(error);
                });

                // A server error before registration (e.g. username taken) aborts connect()
                this.socket.once('error', (data) => {
                    if (!registered) {
                        this.socket.disconnect();
                        reject(new Error(data && data.message ? data.message : 'Server error'));
                    }
                });

                this.setupEventHandlers();

                // Resolve once the server confirms registration
                this.socket.on('user_connected', (data) => {
                    registered = true;
                    this.emit('user_connected', data);
                    resolve(data);
                });

            } catch (error) {
                reject(error);
            }
        });
    }

    /**
     * Sets up server event handlers
     */
    setupEventHandlers() {
        for (const event of FORWARDED_EVENTS) {
            this.socket.on(event, (data) => this.emit(event, data));
        }

        this.socket.on('exchange_public_key', (data) => {
            // Compute the shared key ON THE CLIENT
            this.handleExchangePublicKey(data);
            this.emit('exchange_public_key', data);
        });

        this.socket.on('message_received', (data) => {
            // Decrypt ON THE CLIENT
            this.handleReceivedMessage(data);
        });

        this.socket.on('user_left', (data) => {
            // The peer's ECDH key was ephemeral: drop the stale 1:1 session key
            if (data && data.username) {
                this.forgetPeer(data.username);
            }
            this.emit('user_left', data);
        });

        this.socket.on('group_left', (data) => {
            // We left: clear our group keys
            if (data.groupName && data.clearGroupKey) {
                this.clearGroupKeys(data.groupName);
                if (this.debugMode) {
                    console.log(`🧹 Keys for group ${data.groupName} cleared (you left)`);
                }
            }
            this.emit('group_left', data);
        });

        this.socket.on('member_left_group', (data) => {
            // Another member left: drop that member's keys so they can rejoin later
            if (data.groupName && data.leftMember) {
                this.clearMemberKeysFromGroup(data.groupName, data.leftMember);
                if (this.debugMode) {
                    console.log(`👋 ${data.leftMember} left group ${data.groupName}`);
                    console.log(`   🧹 Keys for ${data.leftMember} removed from cache`);
                    console.log('   Waiting for the server to request a new group key...');
                }
            }
            this.emit('member_left_group', data);
        });

        this.socket.on('clear_group_key', (data) => {
            // We are the only remaining member
            if (data.groupName) {
                this.clearGroupKeys(data.groupName);
                if (this.debugMode) {
                    console.log(`🧹 Key for group ${data.groupName} cleared: ${data.reason}`);
                }
            }
            this.emit('clear_group_key', data);
        });

        this.socket.on('generate_and_distribute_group_key', (data) => {
            // Only sent to the group creator
            this.generateAndDistributeGroupKey(data);
            this.emit('generate_and_distribute_group_key', data);
        });

        this.socket.on('group_key_received', (data) => {
            this.handleGroupKeyReceived(data);
            this.emit('group_key_received', data);
        });

        this.socket.on('group_message_received', (data) => {
            this.handleReceivedGroupMessage(data);
        });
    }

    /**
     * Handles a received private message: validates and decrypts the v1 envelope
     */
    async handleReceivedMessage(data) {
        const { from, envelope } = data;

        try {
            const sharedKey = this.sharedKeys.get(from);

            if (!sharedKey) {
                console.error(`Shared key not found for ${from}`);
                this.emit('error', {
                    message: `Shared key not found for ${from}`,
                    type: 'NoSharedKey'
                });
                return;
            }

            if (this.debugMode) {
                console.log('\n┌─── PILLAR: INTEGRITY (Validation) + CONFIDENTIALITY (Decrypt) ───┐');
            }
            const decrypted = decryptMessage(envelope, sharedKey, from, this.debugMode);
            if (this.debugMode) {
                console.log('└──────────────────────────────────────────────────────────────┘\n');
            }

            this.emit('message_received', {
                from: from,
                message: decrypted,
                envelope: envelope, // kept for debugging
                timestamp: envelope.ts || new Date().toISOString()
            });

        } catch (error) {
            console.error('Error validating/decrypting message:', error.message);
            this.emit('error', {
                message: `Error decrypting message from ${from}`,
                details: error.message,
                type: 'DecryptionError'
            });
        }
    }

    /**
     * Handles a received group message: validates and decrypts the v1 envelope
     */
    async handleReceivedGroupMessage(data) {
        const { from, groupName, envelope } = data;

        try {
            const groupKey = this.groupKeys.get(groupName);

            if (!groupKey) {
                console.error(`Group key not found for ${groupName}`);
                this.emit('error', {
                    message: `Group key not found for ${groupName}`,
                    type: 'NoGroupKey'
                });
                return;
            }

            if (this.debugMode) {
                console.log('\n┌─── PILLAR: INTEGRITY (Validation) + CONFIDENTIALITY (Decrypt) ───┐');
            }
            const decrypted = decryptMessage(envelope, groupKey, from, this.debugMode);
            if (this.debugMode) {
                console.log('└──────────────────────────────────────────────────────────────┘\n');
            }

            this.emit('group_message_received', {
                from: from,
                groupName: groupName,
                message: decrypted,
                envelope: envelope,
                timestamp: envelope.ts || new Date().toISOString()
            });

        } catch (error) {
            console.error('Error validating/decrypting group message:', error.message);
            this.emit('error', {
                message: `Error decrypting group message from ${from}`,
                details: error.message,
                type: 'GroupDecryptionError'
            });
        }
    }

    /**
     * Starts a 1:1 chat
     */
    startChat(targetUser) {
        this.ensureConnected();
        this.socket.emit('start_chat', { targetUser });
    }

    /**
     * Handles a public key routed by the server.
     * Verifies the Ed25519 signature (TOFU), computes the ECDH shared secret
     * locally and derives the session key via HKDF.
     * Does not send our key back (the server already routed both directions).
     */
    handleExchangePublicKey(data) {
        const { targetUser, publicKey, ed25519Pub, signature, isGroup, groupName } = data;

        if (!this.ecdh) {
            console.error('ECDH not initialized');
            return;
        }

        if (!publicKey) {
            console.error('Public key not provided');
            return;
        }

        if (!ed25519Pub || !signature) {
            console.error(`⚠️  Peer ${targetUser} sent no Ed25519 signature. Connection rejected.`);
            this.emit('error', {
                message: `Peer ${targetUser} sent no authentication credentials`,
                type: 'MissingAuthentication'
            });
            return;
        }

        // Skip keys we already processed. For groups the group name is part of
        // the id, so the same peer can be processed again after leaving/rejoining.
        const keyId = groupName
            ? `${groupName}:${targetUser}:${publicKey.substring(0, 16)}`
            : `${targetUser}:${publicKey.substring(0, 16)}`;

        if (this.processedKeys.has(keyId)) {
            if (this.debugMode) {
                console.log(`Public key from ${targetUser} already processed, ignoring...`);
            }
            return;
        }
        this.processedKeys.add(keyId);

        try {
            if (this.debugMode) {
                console.log('\n╔═══════════════════════════════════════════════════════════════╗');
                console.log(`║         🔐 SECURITY PILLARS - Exchange with ${targetUser.padEnd(17)}║`);
                console.log('╚═══════════════════════════════════════════════════════════════╝');
                console.log('\n┌─── PILLAR: INTEGRITY (Identity Verification) ────────────────┐');
            }

            verifyAndPinPeer(targetUser, ed25519Pub, publicKey, signature, this.debugMode);

            if (this.debugMode) {
                console.log('└──────────────────────────────────────────────────────────────┘');
                console.log('\n┌─── PILLAR: CONFIDENTIALITY (Key Establishment) ──────────────┐');
            }

            const sharedSecret = this.ecdh.computeSharedSecret(Buffer.from(publicKey, 'hex'));
            if (this.debugMode) {
                console.log('│ ✓ ECDH shared secret computed');
            }

            // HKDF with a context unique to the pair
            const context = [this.username, targetUser].sort().join(':');
            const { encKey } = deriveSessionKeys(sharedSecret, context, this.debugMode);

            if (this.debugMode) {
                console.log('└──────────────────────────────────────────────────────────────┘');
            }

            if (isGroup && groupName) {
                this.sharedKeys.set(`${groupName}:${targetUser}`, encKey);
            } else {
                this.sharedKeys.set(targetUser, encKey);
            }

            if (!this.debugMode) {
                console.log(`✓ Session key established with ${targetUser}`);
            }

        } catch (error) {
            console.error('Error computing shared key:', error.message);
            this.processedKeys.delete(keyId);
        }
    }

    /**
     * Looks up the pairwise key with a member (group-scoped first, then 1:1)
     */
    getPairwiseKey(groupName, member) {
        return this.sharedKeys.get(`${groupName}:${member}`) || this.sharedKeys.get(member);
    }

    /**
     * Generates and distributes a group key (group creator only).
     * The key is random and is sent to each member inside an envelope
     * encrypted with that member's pairwise key.
     */
    async generateAndDistributeGroupKey(data) {
        const { groupName, members } = data;

        if (!groupName || !members) {
            console.error('Not enough data to generate the group key');
            return;
        }

        try {
            if (this.debugMode) {
                console.log('\n╔═══════════════════════════════════════════════════════════════╗');
                console.log(`║      🔐 GROUP KEY: ${groupName.padEnd(43)}║`);
                console.log('╚═══════════════════════════════════════════════════════════════╝');
                console.log('\n┌─── PILLAR: CONFIDENTIALITY ──────────────────────────────────┐');
            }

            const groupKey = crypto.randomBytes(16); // 128 bits

            if (this.debugMode) {
                console.log('│ ► Generating AES-128 group key...');
                console.log(`│ ✓ Key generated: ${groupKey.toString('hex').substring(0, 16)}...`);
                console.log('│');
                console.log('│ ► Distributing key to members...');
            } else {
                console.log(`Generating key for group ${groupName}...`);
            }

            const encryptedKeys = [];

            for (const member of members) {
                if (member === this.username) {
                    continue;
                }

                const sharedKey = this.getPairwiseKey(groupName, member);
                if (!sharedKey) {
                    console.error(`Shared key not found with ${member}`);
                    continue;
                }

                const envelope = encryptMessage(groupKey.toString('hex'), sharedKey, this.username, member);
                encryptedKeys.push({ member, encryptedKey: envelope });

                if (this.debugMode) {
                    console.log(`│ ✓ Key encrypted for ${member}`);
                }
            }

            this.groupKeys.set(groupName, groupKey);

            if (this.debugMode) {
                console.log('└──────────────────────────────────────────────────────────────┘');
                console.log('\n┌─── PILLAR: INTEGRITY ────────────────────────────────────────┐');
                console.log('│ ✓ Each envelope carries an authentication tag');
                console.log('│ ✓ Protected against replay and tampering');
                console.log('└──────────────────────────────────────────────────────────────┘\n');
            }

            // The server only routes the (encrypted) keys
            this.socket.emit('distribute_group_key', { groupName, encryptedKeys });

            console.log(`Key for group ${groupName} generated and sent to ${encryptedKeys.length} member(s)`);

        } catch (error) {
            console.error(`Error generating/distributing key for group ${groupName}:`, error.message);
        }
    }

    /**
     * Handles a received (encrypted) group key
     */
    async handleGroupKeyReceived(data) {
        const { groupName, encryptedKey, from } = data;

        try {
            if (this.debugMode) {
                console.log('\n╔═══════════════════════════════════════════════════════════════╗');
                console.log(`║      📥 RECEIVING GROUP KEY: ${groupName.padEnd(33)}║`);
                console.log('╚═══════════════════════════════════════════════════════════════╝');
                console.log('\n┌─── PILLAR: INTEGRITY + CONFIDENTIALITY ──────────────────────┐');
            }

            const sharedKey = this.getPairwiseKey(groupName, from);
            if (!sharedKey) {
                console.error(`Shared key with ${from} not found; cannot decrypt group key`);
                return;
            }

            if (this.debugMode) {
                console.log(`│ ► Decrypting key received from ${from}...`);
            }

            const groupKeyHex = decryptMessage(encryptedKey, sharedKey, from, this.debugMode);
            this.groupKeys.set(groupName, Buffer.from(groupKeyHex, 'hex'));

            if (this.debugMode) {
                console.log('└──────────────────────────────────────────────────────────────┘');
            }
            console.log(`Key for group ${groupName} received and decrypted`);

        } catch (error) {
            console.error(`Error decrypting key for group ${groupName}:`, error.message);
        }
    }

    /**
     * Sends a message: encrypts it into a v1 envelope ON THE CLIENT first
     */
    async sendMessage(data) {
        this.ensureConnected();

        const { message, targetUser, isGroup } = data;

        const key = isGroup
            ? this.groupKeys.get(targetUser)
            : this.sharedKeys.get(targetUser);

        if (!key) {
            throw new Error(`No key found for ${isGroup ? 'group' : 'user'} ${targetUser}`);
        }

        try {
            if (this.debugMode) {
                console.log('\n┌─── PILLAR: CONFIDENTIALITY (Encrypt) + INTEGRITY (Tag) ─────────┐');
            }
            const envelope = encryptMessage(message, key, this.username, targetUser, isGroup, this.debugMode);
            if (this.debugMode) {
                console.log('└──────────────────────────────────────────────────────────────┘\n');
            }

            this.socket.emit('send_message', {
                envelope: envelope,
                targetUser: targetUser,
                isGroup: isGroup || false
            });

            this.emit('message_sent', {
                message: message,
                envelope: envelope,
                target: targetUser,
                isGroup: isGroup || false
            });

        } catch (error) {
            console.error('Error encrypting message:', error.message);
            throw error;
        }
    }

    /**
     * Joins (or creates) a group
     */
    joinGroup(groupName) {
        this.ensureConnected();
        this.socket.emit('join_group', { groupName });
    }

    /**
     * Leaves a group
     */
    leaveGroup(groupName) {
        this.ensureConnected();
        this.socket.emit('leave_group', { groupName });
    }

    /**
     * Leaves the current 1:1 chat (session keys are kept to resume the conversation)
     */
    leaveChat() {
        this.ensureConnected();
        this.socket.emit('leave_chat');
    }

    /**
     * Clears every key related to a group (used when we leave)
     */
    clearGroupKeys(groupName) {
        this.groupKeys.delete(groupName);

        for (const keyId of Array.from(this.sharedKeys.keys())) {
            if (keyId.startsWith(`${groupName}:`)) {
                this.sharedKeys.delete(keyId);
            }
        }

        for (const keyId of Array.from(this.processedKeys)) {
            if (keyId.startsWith(`${groupName}:`)) {
                this.processedKeys.delete(keyId);
            }
        }

        if (this.debugMode) {
            console.log(`Keys for group ${groupName} cleared`);
        }
    }

    /**
     * Clears the keys of a member who left a group, so they can rejoin as "new"
     */
    clearMemberKeysFromGroup(groupName, memberName) {
        this.sharedKeys.delete(`${groupName}:${memberName}`);
        this.sharedKeys.delete(memberName);

        // processedKeys format: groupName:memberName:publicKeyPrefix
        const toRemove = Array.from(this.processedKeys)
            .filter(keyId => keyId.startsWith(`${groupName}:${memberName}:`));
        toRemove.forEach(keyId => this.processedKeys.delete(keyId));

        if (this.debugMode) {
            console.log(`🧹 Keys for ${memberName} removed from group ${groupName} cache`);
            console.log(`   Removed ${toRemove.length} processedKeys entries`);
        }
    }

    /**
     * Forgets the 1:1 session key of a peer who disconnected
     * (group-scoped keys are cleared by member_left_group)
     */
    forgetPeer(username) {
        this.sharedKeys.delete(username);
        for (const keyId of Array.from(this.processedKeys)) {
            if (keyId.startsWith(`${username}:`)) {
                this.processedKeys.delete(keyId);
            }
        }
    }

    /**
     * Lists online users
     */
    listUsers() {
        this.ensureConnected();
        this.socket.emit('list_users');
    }

    /**
     * Lists groups
     */
    listGroups() {
        this.ensureConnected();
        this.socket.emit('list_groups');
    }

    /**
     * Disconnects from the server
     */
    disconnect() {
        if (this.socket) {
            this.socket.disconnect();
            this.isConnected = false;
        }
    }

    ensureConnected() {
        if (!this.isConnected) {
            throw new Error('Not connected to the server');
        }
    }

    /**
     * Connection status
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
     * Key information (including the ECDH private key)
     * WARNING: the private key is sensitive! Shown for educational purposes.
     */
    getKeyInfo() {
        if (!this.ecdh) {
            return {
                error: 'ECDH not initialized',
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
     * Clears the whole current session (ephemeral keys and state).
     * Used by /newprofile.
     */
    clearSession() {
        this.publicKey = null;
        this.ecdh = null;

        this.sharedKeys.clear();
        this.groupKeys.clear();
        this.processedKeys.clear();

        console.log('   ✓ Ephemeral ECDH keys cleared');
        console.log('   ✓ Derived (HKDF) keys cleared');
        console.log('   ✓ Processing cache cleared');
    }
}

module.exports = WebSocketClient;
