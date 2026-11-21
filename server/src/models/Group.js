/**
 * Modelo de Grupo para conversas em grupo
 */

class Group {
    constructor(name, creator) {
        this.name = name;
        this.creator = creator;
        this.members = new Set([creator]);
        this.createdAt = new Date();
        this.groupKey = null; // Chave de grupo derivada de todas as chaves compartilhadas
        this.memberKeys = new Map(); // Chaves compartilhadas entre membros
        this.isActive = true;
    }

    /**
     * Adiciona membro ao grupo
     */
    addMember(username) {
        this.members.add(username);
    }

    /**
     * Remove membro do grupo
     * Limpa todas as chaves relacionadas a este membro
     */
    removeMember(username) {
        this.members.delete(username);
        
        // Limpar todas as chaves compartilhadas que envolvem este membro
        // As chaves são armazenadas como pares ordenados (ex: "alice-bob")
        const keysToRemove = [];
        for (const [keyPair, key] of this.memberKeys) {
            const [member1, member2] = keyPair.split('-');
            if (member1 === username || member2 === username) {
                keysToRemove.push(keyPair);
            }
        }
        keysToRemove.forEach(keyPair => this.memberKeys.delete(keyPair));
        
        // Limpar chave de grupo (será regenerada)
        this.groupKey = null;
        
        // Se o criador sair, transfere para outro membro
        if (this.creator === username && this.members.size > 0) {
            this.creator = Array.from(this.members)[0];
        }
    }

    /**
     * Limpa todas as chaves do grupo (útil para recriar secret share)
     */
    clearAllKeys() {
        this.memberKeys.clear();
        this.groupKey = null;
    }

    /**
     * Verifica se usuário é membro
     */
    isMember(username) {
        return this.members.has(username);
    }

    /**
     * Define chave compartilhada entre dois membros
     */
    setMemberKey(member1, member2, key) {
        const keyPair = [member1, member2].sort().join('-');
        this.memberKeys.set(keyPair, key);
    }

    /**
     * Obtém chave compartilhada entre dois membros
     */
    getMemberKey(member1, member2) {
        const keyPair = [member1, member2].sort().join('-');
        return this.memberKeys.get(keyPair);
    }

    /**
     * Gera chave de grupo baseada em todas as chaves compartilhadas
     */
    generateGroupKey() {
        if (this.memberKeys.size === 0) {
            return null;
        }

        // XOR de todas as chaves compartilhadas para gerar chave de grupo
        let groupKey = Buffer.alloc(16); // 128 bits para IDEA
        
        for (const [keyPair, key] of this.memberKeys) {
            if (key && key.length === 16) {
                for (let i = 0; i < 16; i++) {
                    groupKey[i] ^= key[i];
                }
            }
        }

        this.groupKey = groupKey;
        return groupKey;
    }

    /**
     * Verifica se todas as chaves compartilhadas foram estabelecidas
     */
    areAllKeysEstablished() {
        const expectedPairs = (this.members.size * (this.members.size - 1)) / 2;
        return this.memberKeys.size === expectedPairs;
    }

    /**
     * Retorna informações do grupo
     */
    getInfo() {
        return {
            name: this.name,
            creator: this.creator,
            members: Array.from(this.members),
            memberCount: this.members.size,
            createdAt: this.createdAt,
            hasGroupKey: !!this.groupKey,
            keysEstablished: this.areAllKeysEstablished(),
            isActive: this.isActive
        };
    }

    /**
     * Retorna lista de membros online (precisa ser verificado externamente)
     */
    getOnlineMembers(onlineUsers) {
        return Array.from(this.members).filter(member => 
            onlineUsers.has(member) && onlineUsers.get(member).isOnline
        );
    }
}

module.exports = Group;

