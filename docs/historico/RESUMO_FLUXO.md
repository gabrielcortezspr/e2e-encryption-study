> ⚠️ **Documento histórico.** Descreve uma versão antiga do projeto, em que as
> mensagens seriam cifradas com IDEA e a chave era derivada com SHA-256 truncado,
> sem Ed25519/TOFU nem envelope autenticado. O código atual usa AES-128-GCM, HKDF e
> Ed25519 + TOFU. Veja [`../ARQUITETURA.md`](../ARQUITETURA.md) e
> [`../FLUXO_COMPLETO.md`](../FLUXO_COMPLETO.md) para o fluxo atual.

# 📋 Resumo do Fluxo ECDH + IDEA

## 🔄 Fluxo Simplificado: Chat 1:1

### 1️⃣ Conexão

```
Alice conecta → Servidor gera par ECDH (privada + pública)
```

### 2️⃣ Iniciar Chat

```
Alice: /chat Bob
→ Servidor inicia troca automática de chaves
```

### 3️⃣ Troca de Chaves ECDH

```
Alice recebe chave pública de Bob
→ Alice calcula: sharedSecret = ECDH(Alice.privada, Bob.pública)
→ Alice deriva: ideaKey = SHA-256(sharedSecret)[0:16]
→ Alice armazena: ideaKey (128 bits)

Bob recebe chave pública de Alice
→ Bob calcula: sharedSecret = ECDH(Bob.privada, Alice.pública)
→ Bob deriva: ideaKey = SHA-256(sharedSecret)[0:16]
→ Bob armazena: ideaKey (128 bits)

✅ Resultado: Alice e Bob têm a MESMA chave IDEA (calculada independentemente)
```

### 4️⃣ Enviar Mensagem

```
Alice: "Oi Bob!"
→ Servidor criptografa: encrypted = AES-128-ECB("Oi Bob!", ideaKey)
→ Servidor envia para Bob: encrypted (hex)
→ Servidor descriptografa: "Oi Bob!" (para exibir)
→ Bob vê: "Oi Bob!"
```

---

## 👥 Fluxo Simplificado: Chat em Grupo

### 1️⃣ Criar/Entrar no Grupo

```
Alice: /group Equipe
→ Servidor cria grupo ou adiciona Alice
```

### 2️⃣ Troca de Chaves em Grupo

```
Para cada par de membros (Alice↔Bob, Alice↔Charlie, Bob↔Charlie):
→ Estabelece chave compartilhada via ECDH (igual chat 1:1)
→ Armazena no grupo: group.setMemberKey(member1, member2, ideaKey)
```

### 3️⃣ Gerar Chave de Grupo

```
Quando todas as chaves compartilhadas estão estabelecidas:
→ Chave de grupo = key1 XOR key2 XOR key3 ... (XOR de todas)
→ Distribui chave de grupo para todos os membros
```

### 4️⃣ Enviar Mensagem em Grupo

```
Alice: "Olá grupo!"
→ Servidor criptografa: encrypted = AES-128-ECB("Olá grupo!", groupKey)
→ Servidor envia para todos os membros: encrypted (hex)
→ Todos veem: "Olá grupo!"
```

---

## 🔑 Estrutura de Chaves

### ECDH

- **Chave privada**: 32 bytes (256 bits)
- **Chave pública**: 65 bytes (520 bits)
- **Shared Secret**: 32 bytes (256 bits)
- **Curva**: secp256k1

### IDEA (derivada do ECDH)

- **Tamanho**: 16 bytes (128 bits)
- **Origem**: SHA-256(sharedSecret)[0:16]
- **Uso**: Criptografia AES-128-ECB

### Grupo

- **Chave de grupo**: 16 bytes (128 bits)
- **Geração**: XOR de todas as chaves compartilhadas
- **Propriedade**: Mesma chave para todos os membros

---

## 🎯 Pontos-Chave

1. **ECDH**: Gera chave compartilhada sem transmitir a chave diretamente
2. **IDEA**: Criptografa mensagens com chave de 128 bits
3. **Grupo**: Chave única gerada via XOR de todas as chaves compartilhadas
4. **Segurança**: Chaves nunca são transmitidas, apenas chaves públicas
5. **Debug**: Modo debug mostra chave e texto criptografado para análise

---

## 🛠️ Tecnologias Usadas

- **Node.js**: Servidor WebSocket
- **crypto (Node.js)**: ECDH, SHA-256, AES-128
- **Socket.IO**: Comunicação WebSocket
- **JavaScript**: 100% nativo (sem Python)

---

## 📊 Diagrama de Sequência (Simplificado)

### Chat 1:1

```
Alice          Servidor          Bob
  │               │               │
  ├─connect──────>│               │
  │<─publicKey────┤               │
  │               │               │
  ├─/chat Bob────>│               │
  │               ├─exchange─────>│
  │<─exchange─────┤               │
  │               │<─exchange─────┤
  │               │               │
  ├─exchange──────>│               │
  │               │ Calcula key   │
  │<─key_exchanged┤               │
  │               │               │
  │               │<─exchange─────┤
  │               │ Calcula key   │
  │               ├─key_exchanged>│
  │               │               │
  │<─chat_ready───┤               │
  │               ├─chat_ready───>│
  │               │               │
  ├─send("Oi")───>│               │
  │               │ Encrypt       │
  │<─message_sent─┤               │
  │               │ Decrypt       │
  │               ├─message──────>│
  │               │ ("Oi")        │
```

### Chat em Grupo

```
Alice    Bob    Charlie    Servidor
  │       │        │           │
  ├─/group─────────>│           │
  │       │        │           │
  │       │        │<─exchange─┤
  │       │<─exchange───────────┤
  │       │        │           │
  │       │        │─exchange─>│
  │<─exchange───────┤           │
  │       │        │           │
  │       │        │           │ (Todas as chaves estabelecidas)
  │       │        │           │
  │       │        │           │ (Gera groupKey = XOR de todas)
  │       │        │           │
  │<─group_key─────┤           │
  │       │<─group_key─────────┤
  │       │        │<─group_key┤
  │       │        │           │
  ├─send("Olá")───>│           │
  │       │        │           │ (Encrypt com groupKey)
  │       │<─message───────────┤
  │       │        │<─message──┤
  │       │        │           │
```

---

## 🔍 Debug

### Ativar Debug

```bash
node client/cli/main.js --username Alice --debug
# ou
/debug
```

### O que aparece no debug

```
🔍 Debug - Mensagem enviada:
   Original: oi
   Criptografada: 876a4ff79431d438af20a4eef1ee3546
   Chave compartilhada (Bob): 929fd12870e7e6b7ba1bef0e305375a8
   Para descriptografar manualmente:
      node utils/decrypt.js 929fd12870e7e6b7ba1bef0e305375a8 876a4ff79431d438af20a4eef1ee3546
```

### Descriptografar manualmente

```bash
node utils/decrypt.js <chave_hex> <texto_criptografado_hex>
```

---

## ✅ Checklist do Fluxo

### Chat 1:1

- [ ] Usuário conecta → Par ECDH gerado
- [ ] Chat iniciado → Troca automática de chaves públicas
- [ ] Chaves públicas trocadas → Chave compartilhada calculada
- [ ] Chave compartilhada → Chave IDEA derivada (SHA-256)
- [ ] Ambas as chaves estabelecidas → Chat pronto
- [ ] Mensagem enviada → Criptografada com chave IDEA
- [ ] Mensagem recebida → Descriptografada e exibida

### Chat em Grupo

- [ ] Grupo criado/entrado → Membros adicionados
- [ ] Troca de chaves entre todos os pares → Chaves compartilhadas estabelecidas
- [ ] Todas as chaves estabelecidas → Chave de grupo gerada (XOR)
- [ ] Chave de grupo distribuída → Todos os membros recebem
- [ ] Mensagem enviada → Criptografada com chave de grupo
- [ ] Mensagem recebida → Descriptografada e exibida para todos

---

## 🚀 Comandos Úteis

```bash
# Iniciar servidor
node server/server.js

# Conectar cliente (modo debug)
node client/cli/main.js --username Alice --debug

# Comandos no cliente
/chat Bob          # Iniciar chat 1:1
/group Equipe      # Criar/entrar em grupo
/debug             # Toggle debug
/users             # Listar usuários
/groups            # Listar grupos

# Descriptografar manualmente
node utils/decrypt.js <chave> <texto_criptografado>
```
