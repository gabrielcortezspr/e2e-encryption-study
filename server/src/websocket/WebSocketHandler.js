/**
 * WebSocket handler
 * End-to-end: the server only routes public keys and encrypted envelopes
 *
 * Events received from clients:
 *   user_connect, start_chat, send_message, join_group, leave_group,
 *   distribute_group_key, leave_chat, list_users, list_groups, disconnect
 *
 * Events sent to clients:
 *   user_connected, user_joined, user_left, chat_started, chat_ready, chat_left,
 *   exchange_public_key, message_sent, message_received, group_message_received,
 *   group_joined, group_left, member_joined_group, member_left_group,
 *   generate_and_distribute_group_key, group_key_received, clear_group_key,
 *   users_list, groups_list, error
 */

const crypto = require('crypto');
const User = require('../models/User');
const Group = require('../models/Group');

// Fixed delays used before signalling readiness (see "Known limitations")
const CHAT_READY_DELAY_MS = 500;
const GROUP_REKEY_DELAY_MS = 1000;

class WebSocketHandler {
    constructor(io) {
        this.io = io;
        this.users = new Map();  // username -> User
        this.groups = new Map(); // groupName -> Group

        this.setupEventHandlers();
    }

    setupEventHandlers() {
        this.io.on('connection', (socket) => {
            console.log(`Client connected: ${socket.id}`);

            socket.on('user_connect', (data) => this.handleUserConnect(socket, data));
            socket.on('start_chat', (data) => this.handleStartChat(socket, data));
            socket.on('send_message', (data) => this.handleSendMessage(socket, data));
            socket.on('join_group', (data) => this.handleJoinGroup(socket, data));
            socket.on('leave_group', (data) => this.handleLeaveGroup(socket, data));
            socket.on('distribute_group_key', (data) => this.handleDistributeGroupKey(socket, data));
            socket.on('leave_chat', () => this.handleLeaveChat(socket));
            socket.on('list_users', () => this.handleListUsers(socket));
            socket.on('list_groups', () => this.handleListGroups(socket));
            socket.on('disconnect', () => this.handleDisconnect(socket));
        });
    }

    /**
     * Builds the payload that carries a user's public credentials to a peer
     */
    publicKeyPayload(user, extra = {}) {
        return {
            targetUser: user.username,
            publicKey: user.publicKey,          // ECDH public key
            ed25519Pub: user.ed25519PublicKey,  // Ed25519 public key
            signature: user.signature,          // Signature over the ECDH key
            ...extra
        };
    }

    hasCredentials(user) {
        return !!(user && user.publicKey && user.ed25519PublicKey && user.signature);
    }

    /**
     * user_connect: the client sends its public keys (private keys stay on the client)
     */
    async handleUserConnect(socket, data) {
        try {
            const { username, publicKey, ed25519Pub, signature } = data || {};

            if (!username) {
                socket.emit('error', { message: 'Username is required' });
                return;
            }

            if (!publicKey) {
                socket.emit('error', { message: 'ECDH public key is required' });
                return;
            }

            if (!ed25519Pub || !signature) {
                socket.emit('error', { message: 'Authentication credentials (Ed25519) are required' });
                return;
            }

            if (this.users.has(username)) {
                socket.emit('error', { message: 'Username is already in use' });
                return;
            }

            // Store only public keys + signature. No keys are generated here.
            const user = new User(username, socket.id);
            user.setPublicKey(publicKey, ed25519Pub, signature);

            this.users.set(username, user);
            socket.username = username;

            const ed25519Fingerprint = crypto.createHash('sha256').update(ed25519Pub, 'hex').digest('hex');

            console.log(`User connected: ${username}`);
            console.log(`   ECDH key (ephemeral): ${publicKey.substring(0, 16)}...`);
            console.log(`   Ed25519 identity: ${ed25519Fingerprint.substring(0, 32)}...`);

            socket.emit('user_connected', {
                success: true,
                username: username,
                message: 'Connected!'
            });

            socket.broadcast.emit('user_joined', {
                username: username,
                message: `${username} joined`
            });

        } catch (error) {
            console.error('Error connecting user:', error);
            socket.emit('error', { message: 'Internal server error' });
        }
    }

    /**
     * start_chat: routes each side's public key + Ed25519 credentials to the other
     */
    async handleStartChat(socket, data) {
        try {
            const { targetUser } = data || {};
            const username = socket.username;

            if (!username || !targetUser) {
                socket.emit('error', { message: 'Invalid data' });
                return;
            }

            if (!this.users.has(targetUser)) {
                socket.emit('error', { message: 'User not found' });
                return;
            }

            if (username === targetUser) {
                socket.emit('error', { message: 'You cannot chat with yourself' });
                return;
            }

            const user = this.users.get(username);
            const target = this.users.get(targetUser);

            if (!this.hasCredentials(user) || !this.hasCredentials(target)) {
                socket.emit('error', { message: 'Incomplete authentication credentials' });
                return;
            }

            user.setCurrentChat('private', targetUser);
            target.setCurrentChat('private', username);

            console.log(`Chat started: ${username} <-> ${targetUser} (routing ECDH + Ed25519 keys)`);

            socket.emit('exchange_public_key', this.publicKeyPayload(target, { isGroup: false }));
            this.io.to(target.socketId).emit('exchange_public_key', this.publicKeyPayload(user, { isGroup: false }));

            socket.emit('chat_started', {
                success: true,
                targetUser: targetUser,
                message: `Chat started with ${targetUser}. Exchanging keys...`
            });

            this.io.to(target.socketId).emit('chat_started', {
                success: true,
                targetUser: username,
                message: `${username} started a chat with you. Exchanging keys...`
            });

            // Give both clients time to derive their keys
            setTimeout(() => {
                socket.emit('chat_ready', {
                    targetUser: targetUser,
                    message: `Secure chat established with ${targetUser}!`
                });

                this.io.to(target.socketId).emit('chat_ready', {
                    targetUser: username,
                    message: `Secure chat established with ${username}!`
                });
            }, CHAT_READY_DELAY_MS);

        } catch (error) {
            console.error('Error starting chat:', error);
            socket.emit('error', { message: 'Internal server error' });
        }
    }

    /**
     * send_message: the envelope is already encrypted by the client; just route it
     */
    async handleSendMessage(socket, data) {
        try {
            const { envelope, targetUser, isGroup } = data || {};
            const username = socket.username;

            if (!username || !envelope || !targetUser) {
                socket.emit('error', { message: 'Invalid data' });
                return;
            }

            const user = this.users.get(username);
            if (!user) {
                socket.emit('error', { message: 'User not found' });
                return;
            }

            if (isGroup) {
                await this.handleGroupMessage(user, envelope, targetUser);
            } else {
                await this.handlePrivateMessage(user, envelope, targetUser);
            }

        } catch (error) {
            console.error('Error sending message:', error);
            socket.emit('error', {
                message: 'Error sending message',
                details: error.message,
                type: error.name || 'UnknownError'
            });
        }
    }

    /**
     * Routes a private envelope (never decrypted here)
     */
    async handlePrivateMessage(user, envelope, targetUser) {
        const target = this.users.get(targetUser);

        console.log(`Routing private envelope: ${user.username} -> ${targetUser} (v${envelope.v}, ts:${envelope.ts})`);

        if (!target) {
            this.io.to(user.socketId).emit('error', {
                message: 'Target user not found',
                details: `User ${targetUser} is not online`,
                type: 'TargetNotFound'
            });
            return;
        }

        this.io.to(target.socketId).emit('message_received', {
            from: user.username,
            envelope: envelope,
            timestamp: envelope.ts
        });
    }

    /**
     * Routes a group envelope to every online member (never decrypted here)
     */
    async handleGroupMessage(user, envelope, groupName) {
        const group = this.groups.get(groupName);

        console.log(`Routing group envelope: ${user.username} -> ${groupName} (v${envelope.v}, ts:${envelope.ts})`);

        if (!group) {
            this.io.to(user.socketId).emit('error', {
                message: 'Group not found',
                details: `Group ${groupName} does not exist`,
                type: 'GroupNotFound'
            });
            return;
        }

        if (!group.isMember(user.username)) {
            this.io.to(user.socketId).emit('error', {
                message: 'You are not a member of this group',
                details: `User ${user.username} is not a member of ${groupName}`,
                type: 'NotGroupMember'
            });
            return;
        }

        group.members.forEach(memberName => {
            const member = this.users.get(memberName);
            if (member && member.isOnline) {
                this.io.to(member.socketId).emit('group_message_received', {
                    from: user.username,
                    groupName: groupName,
                    envelope: envelope,
                    timestamp: envelope.ts
                });
            }
        });
    }

    /**
     * Routes public keys (with Ed25519 credentials) between every pair of
     * group members, so each pair derives a pairwise key
     */
    async establishGroupKeys(group) {
        const members = Array.from(group.members);
        console.log(`Routing public keys for group ${group.name} (${members.length} members)`);

        for (let i = 0; i < members.length; i++) {
            for (let j = i + 1; j < members.length; j++) {
                const user1 = this.users.get(members[i]);
                const user2 = this.users.get(members[j]);

                if (!user1 || !user2 || !user1.isOnline || !user2.isOnline) continue;
                if (!this.hasCredentials(user1) || !this.hasCredentials(user2)) {
                    console.error(`❌ Incomplete credentials: ${members[i]} or ${members[j]}`);
                    continue;
                }

                const extra = { isGroup: true, groupName: group.name };
                this.io.to(user1.socketId).emit('exchange_public_key', this.publicKeyPayload(user2, extra));
                this.io.to(user2.socketId).emit('exchange_public_key', this.publicKeyPayload(user1, extra));
            }
        }
    }

    /**
     * Asks the group creator to generate and distribute a new group key
     */
    notifyGroupKeyGeneration(groupName) {
        const group = this.groups.get(groupName);
        if (!group) return;

        const members = Array.from(group.members);
        const creatorUser = this.users.get(group.creator);

        console.log(`🔔 Requesting group key: ${groupName} (${members.length} members, creator: ${group.creator})`);

        if (creatorUser && creatorUser.isOnline) {
            this.io.to(creatorUser.socketId).emit('generate_and_distribute_group_key', {
                groupName: groupName,
                members: members,
                message: `Generate and distribute the key for ${groupName}`
            });
        } else {
            console.error(`❌ Group creator ${group.creator} is not online`);
        }
    }

    /**
     * distribute_group_key: routes each encrypted key to its member
     * (the server cannot decrypt them)
     */
    async handleDistributeGroupKey(socket, data) {
        try {
            const { groupName, encryptedKeys } = data || {};
            const username = socket.username;

            const group = this.groups.get(groupName);
            if (!group) {
                socket.emit('error', { message: 'Group not found' });
                return;
            }

            if (group.creator !== username) {
                socket.emit('error', { message: 'Only the group creator can distribute the key' });
                return;
            }

            if (!Array.isArray(encryptedKeys)) {
                socket.emit('error', { message: 'Invalid data' });
                return;
            }

            console.log(`🔐 Distributing key for group ${groupName} to ${encryptedKeys.length} member(s)`);
            group.markKeyDistributed();

            encryptedKeys.forEach(({ member, encryptedKey }) => {
                const memberUser = this.users.get(member);
                if (memberUser && memberUser.isOnline && group.isMember(member)) {
                    this.io.to(memberUser.socketId).emit('group_key_received', {
                        groupName: groupName,
                        encryptedKey: encryptedKey,
                        from: username,
                        message: `Key for group ${groupName} received`
                    });
                }
            });

        } catch (error) {
            console.error('Error distributing group key:', error);
            socket.emit('error', { message: 'Error distributing group key' });
        }
    }

    /**
     * Routes public keys between a new member and every existing member
     */
    async initiateGroupKeyExchange(socket, groupName) {
        const group = this.groups.get(groupName);
        if (!group) return;

        const username = socket.username;
        const user = this.users.get(username);

        if (!this.hasCredentials(user)) {
            console.error(`❌ User ${username} has incomplete credentials`);
            return;
        }

        console.log(`🔄 Routing public keys for new member ${username} in group ${groupName}`);

        const extra = { isGroup: true, groupName };
        for (const memberName of group.members) {
            if (memberName === username) continue;

            const member = this.users.get(memberName);
            if (!member || !member.isOnline) continue;
            if (!this.hasCredentials(member)) {
                console.error(`❌ Member ${memberName} has incomplete credentials`);
                continue;
            }

            socket.emit('exchange_public_key', this.publicKeyPayload(member, extra));
            this.io.to(member.socketId).emit('exchange_public_key', this.publicKeyPayload(user, extra));
        }
    }

    /**
     * join_group: creates the group or joins an existing one (and re-keys)
     */
    async handleJoinGroup(socket, data) {
        try {
            const { groupName } = data || {};
            const username = socket.username;

            if (!username || !groupName) {
                socket.emit('error', { message: 'Invalid data' });
                return;
            }

            const user = this.users.get(username);

            if (!this.groups.has(groupName)) {
                // New group: the user is the creator
                const group = new Group(groupName, username);
                this.groups.set(groupName, group);
                user.setCurrentChat('group', groupName);
                user.currentGroup = groupName;

                console.log(`👥 Group created: ${groupName} by ${username}`);

                socket.emit('group_joined', {
                    success: true,
                    groupName: groupName,
                    isCreator: true,
                    message: `Group "${groupName}" created!`
                });
                // No keys needed yet (single member)
                return;
            }

            const group = this.groups.get(groupName);

            if (group.isMember(username)) {
                socket.emit('error', { message: 'You are already a member of this group' });
                return;
            }

            group.addMember(username);
            user.setCurrentChat('group', groupName);
            user.currentGroup = groupName;

            console.log(`👥 ${username} joined group ${groupName}`);

            socket.emit('group_joined', {
                success: true,
                groupName: groupName,
                isCreator: false,
                members: Array.from(group.members),
                message: `You joined group "${groupName}"`
            });

            group.members.forEach(memberName => {
                if (memberName === username) return;
                const member = this.users.get(memberName);
                if (member) {
                    this.io.to(member.socketId).emit('member_joined_group', {
                        groupName: groupName,
                        newMember: username,
                        message: `${username} joined the group`
                    });
                }
            });

            await this.initiateGroupKeyExchange(socket, groupName);

            // New member: generate a NEW group key for everyone
            if (group.members.size >= 2) {
                console.log(`🔄 New member: re-keying group ${groupName}`);
                setTimeout(() => this.notifyGroupKeyGeneration(groupName), GROUP_REKEY_DELAY_MS);
            }

        } catch (error) {
            console.error('Error joining group:', error);
            socket.emit('error', { message: 'Internal server error' });
        }
    }

    /**
     * leave_group: removes the member and re-keys the remaining members,
     * so the member who left cannot read future messages
     */
    async handleLeaveGroup(socket, data) {
        try {
            const { groupName } = data || {};
            const username = socket.username;

            if (!username || !groupName) {
                socket.emit('error', { message: 'Invalid data' });
                return;
            }

            const group = this.groups.get(groupName);
            if (!group) {
                socket.emit('error', { message: 'Group not found' });
                return;
            }

            if (!group.isMember(username)) {
                socket.emit('error', { message: 'You are not a member of this group' });
                return;
            }

            const user = this.users.get(username);
            if (user && user.currentGroup === groupName) {
                user.clearCurrentChat();
                user.currentGroup = null;
            }

            const wasCreator = group.creator === username;
            group.removeMember(username);

            console.log(`👋 ${username} left group ${groupName}`);

            // Tell the user who left to clear their group keys
            socket.emit('group_left', {
                success: true,
                groupName: groupName,
                clearGroupKey: true,
                message: `You left group "${groupName}"`
            });

            group.members.forEach(memberName => {
                const member = this.users.get(memberName);
                if (member) {
                    this.io.to(member.socketId).emit('member_left_group', {
                        groupName: groupName,
                        leftMember: username,
                        message: `${username} left the group`,
                        wasCreator: wasCreator
                    });
                }
            });

            if (group.members.size >= 2) {
                console.log(`🔄 Re-keying group ${groupName} (remaining: ${Array.from(group.members).join(', ')})`);

                // Existing pairwise keys stay valid; only re-establish missing pairs
                await this.establishGroupKeys(group);
                setTimeout(() => this.notifyGroupKeyGeneration(groupName), GROUP_REKEY_DELAY_MS);

            } else if (group.members.size === 1) {
                // A single member left: there is no group secret anymore
                const lastUser = this.users.get(Array.from(group.members)[0]);
                if (lastUser) {
                    this.io.to(lastUser.socketId).emit('clear_group_key', {
                        groupName: groupName,
                        reason: 'You are the only remaining member'
                    });
                }
                group.invalidateKey();
                console.log(`ℹ️  Group ${groupName} now has a single member; key discarded`);

            } else {
                this.groups.delete(groupName);
                console.log(`🗑️  Group ${groupName} removed (no members)`);
            }

        } catch (error) {
            console.error('Error leaving group:', error);
            socket.emit('error', { message: 'Internal server error' });
        }
    }

    /**
     * leave_chat
     */
    handleLeaveChat(socket) {
        const user = socket.username && this.users.get(socket.username);
        if (!user) return;

        user.clearCurrentChat();
        user.currentGroup = null;

        socket.emit('chat_left', {
            success: true,
            message: 'You left the chat'
        });

        console.log(`👋 ${user.username} left the chat`);
    }

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
     * disconnect: leaves every group (re-keying them) and frees the username
     */
    async handleDisconnect(socket) {
        const username = socket.username;
        const user = username && this.users.get(username);

        // Ignore sockets that never completed user_connect or were replaced
        if (!user || user.socketId !== socket.id) {
            return;
        }

        user.setOffline();

        for (const group of Array.from(this.groups.values())) {
            if (group.isMember(username)) {
                await this.handleLeaveGroup(socket, { groupName: group.name });
            }
        }

        // The user's ECDH key was ephemeral; reconnecting generates new keys
        this.users.delete(username);

        console.log(`👋 User disconnected: ${username}`);

        socket.broadcast.emit('user_left', {
            username: username,
            message: `${username} left`
        });
    }
}

module.exports = WebSocketHandler;
