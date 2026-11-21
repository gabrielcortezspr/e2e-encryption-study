/**
 * Modelo de Grupo para conversas em grupo
 *
 * O servidor NÃO conhece a chave do grupo: ela é gerada pelo criador e
 * distribuída cifrada (um envelope por membro, com a chave pairwise de cada um).
 * Aqui só guardamos membros e se a chave atual já foi distribuída.
 */

class Group {
    constructor(name, creator) {
        this.name = name;
        this.creator = creator;
        this.members = new Set([creator]);
        this.createdAt = new Date();
        this.keyDistributedAt = null; // Quando o criador distribuiu a chave atual
        this.isActive = true;
    }

    /**
     * Adiciona membro ao grupo (a chave atual deixa de valer: haverá re-key)
     */
    addMember(username) {
        this.members.add(username);
        this.invalidateKey();
    }

    /**
     * Remove membro do grupo (a chave atual deixa de valer: haverá re-key)
     * Se o criador sair, a função de criador passa para outro membro.
     */
    removeMember(username) {
        this.members.delete(username);
        this.invalidateKey();

        if (this.creator === username && this.members.size > 0) {
            this.creator = Array.from(this.members)[0];
        }
    }

    /**
     * Marca que a chave do grupo precisa ser regenerada
     */
    invalidateKey() {
        this.keyDistributedAt = null;
    }

    /**
     * Marca que o criador distribuiu uma nova chave
     */
    markKeyDistributed() {
        this.keyDistributedAt = new Date();
    }

    /**
     * Verifica se usuário é membro
     */
    isMember(username) {
        return this.members.has(username);
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
            keysEstablished: !!this.keyDistributedAt,
            isActive: this.isActive
        };
    }
}

module.exports = Group;
