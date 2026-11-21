# 🧪 Testes dos Comandos /newprofile e /delete

## Comandos Implementados

### 1. `/newprofile` - Simula Reinstalação
Simula desinstalar e reinstalar a aplicação:
- ✅ Deleta sua identidade Ed25519 (chave de longo prazo)
- ✅ Deleta seu registro TOFU de outros usuários
- ✅ Limpa todas as chaves de sessão (ECDH, HKDF)
- ✅ Você precisa reconectar para gerar novo perfil

### 2. `/delete @usuario` - Remove Registro TOFU
Remove o registro TOFU de um usuário específico:
- ✅ Deleta o fingerprint armazenado daquele usuário
- ✅ Próxima conexão será tratada como "primeira vez"
- ✅ Ideal para quando alguém usou `/newprofile`

---

## 📋 Cenário de Teste 1: Alice Reinstala (Bob precisa confiar novamente)

### Situação Inicial
- Alice e Bob já conversaram antes
- Ambos têm TOFU do outro armazenado

### Passos:

#### 1. Alice usa `/newprofile`

```bash
# Terminal de Alice
/newprofile
```

**Saída esperada:**
```
⚠️  ATENÇÃO: Você está prestes a DELETAR seu perfil atual!
   Isso vai remover:
   • Sua identidade Ed25519 (chave de longo prazo)
   • Todas as identidades TOFU armazenadas
   • Todas as conexões ativas

   Esta ação é IRREVERSÍVEL!

   Isso simula você desinstalar e reinstalar a aplicação.
   Outros usuários receberão alerta TOFU ao falar com você.

🔄 Perfil resetado:
   ✓ Identidade Ed25519 deletada
   ✓ Registro TOFU deletado
   ✓ Sessão atual limpa
   ✓ Chaves ECDH efêmeras limpas
   ✓ Chaves derivadas (HKDF) limpas
   ✓ Cache de processamento limpo

⚠️  Você precisa RECONECTAR para gerar novo perfil:
   1. Use /quit para desconectar
   2. Execute ./start-test.sh novamente
   3. Novo par Ed25519 será gerado automaticamente
```

#### 2. Alice desconecta e reconecta

```bash
# Alice desconecta
/quit

# Alice reconecta (novo terminal)
./start-test.sh
# Digite: Alice
```

**Saída esperada:**
```
┌─── PILAR: INTEGRIDADE ───────────────────────────────────────┐
│ ✓ Nova chave de autenticação gerada
│   ID: f3e2d1c0b9a8...
└──────────────────────────────────────────────────────────────┘
```

#### 3. Bob tenta falar com Alice (ALERTA TOFU!)

```bash
# Terminal de Bob
/chat Alice
```

**Saída esperada:**
```
┌─────────────────────────────────────────────────────────────┐
│         ⚠️  ALERTA DE SEGURANÇA - IDENTIDADE MUDOU         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ Usuário: Alice                                              │
│                                                             │
│ Fingerprint Esperado (armazenado):                          │
│   f267115f32b856fc17f4477e8e7a...                           │
│                                                             │
│ Fingerprint Recebido (novo):                                │
│   f3e2d1c0b9a87654321fedcba...                              │
│                                                             │
│ Possíveis causas:                                           │
│   • Ataque Man-in-the-Middle (MITM)                         │
│   • Alice reinstalou o sistema                              │
│   • Alice deletou arquivo ed25519_keypair                   │
│                                                             │
│ ❌ CONEXÃO REJEITADA POR SEGURANÇA                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘

❌ Erro ao estabelecer chave compartilhada: TOFU: Identidade de Alice mudou!
```

#### 4. Bob decide confiar na nova identidade de Alice

```bash
# Terminal de Bob
/delete @Alice
```

**Saída esperada:**
```
✅ Registro TOFU de Alice deletado com sucesso!
   Fingerprint removido: f267115f32b856fc17f4477e...

⚠️  Próxima vez que falar com Alice:
   • Será tratado como PRIMEIRA CONEXÃO
   • Novo fingerprint será armazenado
   • Ideal se Alice usou /newprofile
```

#### 5. Bob tenta falar com Alice novamente

```bash
# Terminal de Bob
/chat Alice
```

**Saída esperada:**
```
┌─────────────────────────────────────────────────────────────┐
│         🔔 PRIMEIRA CONEXÃO COM Alice                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ Trust On First Use (TOFU) - Identidade registrada          │
│                                                             │
│ Fingerprint: f3e2d1c0b9a87654321fedcba...                  │
│                                                             │
│ Esta identidade será verificada em futuros contatos.       │
│ Se mudar, será emitido um alerta de segurança.             │
│                                                             │
└─────────────────────────────────────────────────────────────┘

✓ Chat com Alice estabelecido
```

#### 6. Conversa funciona normalmente

```bash
# Bob envia mensagem
Olá Alice! Aceitei sua nova identidade.

# Alice recebe e responde
Obrigada Bob! Reinstalei meu sistema.
```

---

## 📋 Cenário de Teste 2: Uso Incorreto dos Comandos

### Teste 2.1: Tentar deletar próprio perfil com `/delete`

```bash
# Alice tenta
/delete @Alice
```

**Saída esperada:**
```
❌ Não é possível deletar seu próprio perfil
   Use /newprofile para resetar seu perfil
```

### Teste 2.2: Deletar usuário que não existe no TOFU

```bash
# Bob tenta deletar Charlie (nunca falou com ele)
/delete @Charlie
```

**Saída esperada:**
```
⚠️  Você não tem registro TOFU de Charlie
   Usuários registrados: Alice, David
```

### Teste 2.3: Deletar sem TOFU store

```bash
# Charlie (novo usuário) tenta deletar alguém
/delete @Alice
```

**Saída esperada:**
```
⚠️  Você não tem nenhum registro TOFU ainda
```

### Teste 2.4: Usar `/delete` sem argumentos

```bash
/delete
```

**Saída esperada:**
```
❌ Use: /delete @usuario
   Exemplo: /delete @Alice
```

---

## 📋 Cenário de Teste 3: Grupo com Reinstalação

### Situação:
- Alice, Bob e Charlie estão no grupo "Redes"
- Alice usa `/newprofile` e reconecta
- Bob e Charlie precisam confiar na nova Alice

### Passos:

```bash
# 1. Alice reinstala
/newprofile
/quit
./start-test.sh
# Digite: Alice

# 2. Alice entra no grupo novamente
/group Redes

# 3. Bob tenta estabelecer chave com Alice
# (TOFU alerta!)

# 4. Bob confia na nova Alice
/delete @Alice

# 5. Bob pode falar com Alice novamente
# (Chave de grupo é redistribuída)

# 6. Charlie também precisa fazer:
/delete @Alice
```

---

## 🔍 Verificação dos Arquivos

### Ver registros TOFU antes de `/delete`:
```bash
cat client/.keys/pinned_keys_Bob.json
```

Saída:
```json
{
  "Alice": {
    "fingerprint": "f267115f32b856fc17f4477e8e7a61f1039408f920e1b58c70d85e4edce228b8",
    "ed25519PubHex": "302a300506032b6570032100829c09c50eca3c0080f0eb4c90d3cd41cb41b9f4fc8c97e510000d4289583d19",
    "firstSeen": "2025-11-24T05:57:45.869Z"
  }
}
```

### Ver registros TOFU depois de `/delete @Alice`:
```bash
cat client/.keys/pinned_keys_Bob.json
```

Saída:
```json
{}
```

### Verificar que Alice não tem mais Ed25519 após `/newprofile`:
```bash
ls -la client/.keys/ed25519_keypair_Alice.json
# Arquivo não existe!

ls -la client/.keys/pinned_keys_Alice.json  
# Arquivo não existe!
```

### Verificar novo Ed25519 após reconectar:
```bash
cat client/.keys/ed25519_keypair_Alice.json
# Novo arquivo com novas chaves!
```

---

## ✅ Checklist de Validação

### `/newprofile`:
- [ ] Exibe aviso claro sobre ação irreversível
- [ ] Deleta `ed25519_keypair_${username}.json`
- [ ] Deleta `pinned_keys_${username}.json`
- [ ] Limpa chaves ECDH da sessão atual
- [ ] Limpa Maps de sharedKeys e groupKeys
- [ ] Instrui usuário a reconectar
- [ ] Ao reconectar, gera novo Ed25519

### `/delete @usuario`:
- [ ] Remove entrada específica do TOFU
- [ ] Não deleta outros registros
- [ ] Exibe fingerprint removido
- [ ] Informa que próxima conexão será "primeira vez"
- [ ] Rejeita se tentar deletar a si mesmo
- [ ] Rejeita se usuário não existe no TOFU
- [ ] Funciona com ou sem `@` no nome

### Integração TOFU:
- [ ] Alerta de identidade mudou aparece
- [ ] Alerta de primeira conexão aparece após `/delete`
- [ ] Chat funciona normalmente após re-confiar
- [ ] Grupos funcionam após re-confiar
- [ ] Outros membros também precisam usar `/delete`

---

## 🎯 Casos de Uso Reais

### 1. **Usuário reinstalou o sistema**
```bash
# Pessoa que reinstalou:
/newprofile
/quit
./start-test.sh

# Amigos dela:
/delete @NomeDoAmigo
/chat NomeDoAmigo  # Funciona!
```

### 2. **Suspeita de comprometimento**
```bash
# Se você acha que alguém está usando chave comprometida:
/delete @UsuarioSuspeito
# Não fale com ele até ter certeza da nova identidade
```

### 3. **Teste de segurança**
```bash
# Testar TOFU:
/newprofile  # Simula ataque (troca de identidade)
/quit
./start-test.sh
# Outros devem ver alerta!
```

---

## 📝 Comandos Rápidos para Ajuda

Ver ajuda:
```bash
/help
```

Saída inclui:
```
│ /newprofile    - Simula reinstalação    │
│ /delete @user  - Remove TOFU de usuário │
```

---

## ⚠️ Avisos Importantes

1. **`/newprofile` é irreversível!**
   - Você perde sua identidade de longo prazo
   - Todos que já falaram com você precisarão usar `/delete`

2. **`/delete` não é bidirecional**
   - Se Bob deleta Alice, Alice ainda tem TOFU de Bob
   - Cada usuário precisa fazer seu próprio `/delete`

3. **Em grupos:**
   - Se um membro usa `/newprofile`, todos precisam usar `/delete` nele
   - Chaves de grupo são redistribuídas automaticamente

4. **Segurança:**
   - Só use `/delete` se você CONFIA que a pessoa reinstalou
   - Não use `/delete` se suspeita de MITM real
