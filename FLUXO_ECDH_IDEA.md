# 🔐 Fluxo Completo: ECDH + IDEA

Documentação detalhada do fluxo de troca de chaves (ECDH) e criptografia (IDEA) no sistema.

## 📋 Índice

1. [Visão Geral](#visão-geral)
2. [Fluxo de Chat 1:1](#fluxo-de-chat-11)
3. [Fluxo de Chat em Grupo](#fluxo-de-chat-em-grupo)
4. [Detalhes Técnicos](#detalhes-técnicos)

---

## 🎯 Visão Geral

O sistema utiliza:

- **ECDH (Elliptic Curve Diffie-Hellman)**: Para troca segura de chaves
- **IDEA (via AES-128-ECB)**: Para criptografia das mensagens
- **Curva ECDH**: secp256k1 (mesma do Bitcoin)
- **Chave IDEA**: 128 bits (16 bytes)

---

## 💬 Fluxo de Chat 1:1

### Etapa 1: Conexão do Usuário

```
Cliente → Servidor: user_connect { username: "Alice" }
```

**No Servidor:**

1. Cria objeto `User` para Alice
2. Gera par de chaves ECDH:
   ```javascript
   const ecdh = new ECDHManual(false);
   const keyPair = ecdh.generateKeyPair();
   // keyPair.privateKey: 32 bytes (chave privada)
   // keyPair.publicKey: 65 bytes (chave pública não comprimida)
   ```
3. Armazena ECDH no objeto User
4. Envia chave pública para o cliente:
   ```javascript
   socket.emit("user_connected", {
     publicKey: keyPair.publicKey.toString("hex"),
   });
   ```

**Resultado:** Alice tem par de chaves ECDH e sua chave pública foi enviada ao cliente.

---

### Etapa 2: Iniciar Chat

```
Alice → Servidor: start_chat { targetUser: "Bob" }
```

**No Servidor:**

1. Verifica se Bob está online
2. Define chat ativo para Alice e Bob
3. **Inicia troca automática de chaves:**
   - Alice recebe chave pública de Bob
   - Bob recebe chave pública de Alice

**Eventos enviados:**

```javascript
// Para Alice
socket.emit("exchange_public_key", {
  targetUser: "Bob",
  publicKey: bobPublicKeyHex,
});

// Para Bob
socket.emit("exchange_public_key", {
  targetUser: "Alice",
  publicKey: alicePublicKeyHex,
});
```

---

### Etapa 3: Troca de Chaves ECDH

**No Servidor (quando recebe `exchange_public_key`):**

Para Alice (recebendo chave pública de Bob):

1. **Calcular chave compartilhada:**

   ```javascript
   const publicKeyBuffer = Buffer.from(bobPublicKey, "hex");
   const sharedSecret = alice.ecdh.computeSharedSecret(publicKeyBuffer);
   // sharedSecret: 32 bytes (resultado do ECDH)
   ```

2. **Derivar chave IDEA (128 bits):**

   ```javascript
   const ideaKey = alice.ecdh.deriveIDEAKey(sharedSecret);
   // Processo:
   // 1. Hash SHA-256 do sharedSecret
   // 2. Pegar primeiros 16 bytes (128 bits)
   // ideaKey: 16 bytes (chave para IDEA)
   ```

3. **Armazenar chave compartilhada:**

   ```javascript
   alice.setSharedKey("Bob", ideaKey);
   ```

4. **Enviar chave para o cliente (para debug):**
   ```javascript
   socket.emit("key_exchanged", {
     targetUser: "Bob",
     sharedKey: ideaKey.toString("hex"), // 32 caracteres hex
     message: "Chave compartilhada estabelecida com Bob!",
   });
   ```

**O mesmo processo acontece para Bob** (recebendo chave pública de Alice).

---

### Etapa 4: Chat Pronto

**Quando ambas as chaves estão estabelecidas:**

```javascript
if (alice.getSharedKey("Bob") && bob.getSharedKey("Alice")) {
  // Enviar evento chat_ready para ambos
  socket.emit("chat_ready", {
    targetUser: "Bob",
    message: "Chat seguro estabelecido com Bob!",
  });
}
```

**Resultado:** Alice e Bob têm a mesma chave IDEA compartilhada (mas calculada independentemente).

---

### Etapa 5: Enviar Mensagem Criptografada

```
Alice → Servidor: send_message {
  message: "Oi Bob!",
  targetUser: "Bob"
}
```

**No Servidor:**

1. **Buscar chave compartilhada:**

   ```javascript
   const sharedKey = alice.getSharedKey("Bob");
   // sharedKey: Buffer de 16 bytes
   ```

2. **Criptografar mensagem com IDEA:**

   ```javascript
   const encrypted = await ideaBridge.encryptMessage("Oi Bob!", sharedKey);
   // Processo interno:
   // 1. Usa AES-128-ECB (substituição de IDEA)
   // 2. Converte mensagem UTF-8 para hex
   // 3. Aplica padding PKCS#7 se necessário
   // encrypted: string hex (ex: "876a4ff79431d438af20a4eef1ee3546")
   ```

3. **Enviar para Alice (confirmação):**

   ```javascript
   socket.emit("message_sent", {
     message: "Oi Bob!",
     encrypted: encrypted,
     target: "Bob",
     isGroup: false,
   });
   ```

4. **Enviar para Bob (mensagem descriptografada):**
   ```javascript
   // Servidor descriptografa e envia texto plano
   const decrypted = await ideaBridge.decryptMessage(encrypted, sharedKey);
   socket.emit("message_received", {
     from: "Alice",
     encrypted: encrypted, // texto criptografado (para debug)
     message: "Oi Bob!", // texto plano (para exibição)
     timestamp: new Date().toISOString(),
   });
   ```

**Nota:** O servidor descriptografa a mensagem antes de enviar ao destinatário para simplificar o cliente. Em produção, o cliente deveria descriptografar.

---

## 👥 Fluxo de Chat em Grupo

### Etapa 1: Criar/Entrar em Grupo

```
Alice → Servidor: join_group { groupName: "Equipe" }
```

**Se grupo não existe (criar):**

1. Cria objeto `Group`
2. Adiciona Alice como membro e criador
3. Não há troca de chaves ainda (apenas 1 membro)

**Se grupo já existe (entrar):**

1. Adiciona Alice ao grupo
2. **Inicia troca de chaves com todos os membros existentes:**
   ```javascript
   // Para cada membro existente (ex: Bob, Charlie)
   socket.emit("exchange_public_key", {
     targetUser: "Bob",
     publicKey: bobPublicKey,
     isGroup: true,
     groupName: "Equipe",
   });
   ```

---

### Etapa 2: Troca de Chaves em Grupo

**Processo similar ao chat 1:1, mas com contexto de grupo:**

1. **Alice estabelece chave com Bob:**

   - Alice calcula `sharedSecret` com chave pública de Bob
   - Deriva `ideaKey` (128 bits)
   - Armazena no grupo:
     ```javascript
     group.setMemberKey("Alice", "Bob", ideaKey);
     ```

2. **Alice estabelece chave com Charlie:**

   - Processo idêntico
   - Armazena: `group.setMemberKey("Alice", "Charlie", ideaKey2)`

3. **Repete para todos os pares:**
   - Bob ↔ Charlie
   - etc.

---

### Etapa 3: Gerar Chave de Grupo

**Quando todas as chaves compartilhadas estão estabelecidas:**

```javascript
if (group.areAllKeysEstablished()) {
  // Gerar chave de grupo via XOR
  const groupKey = group.generateGroupKey();
  // Processo:
  // 1. Inicia com Buffer.alloc(16) (zeros)
  // 2. Para cada chave compartilhada:
  //    groupKey[i] ^= sharedKey[i] (XOR bit a bit)
  // 3. Resultado: chave de grupo única
}
```

**Exemplo com 3 membros (Alice, Bob, Charlie):**

- Chaves compartilhadas: Alice↔Bob, Alice↔Charlie, Bob↔Charlie
- Chave de grupo = key1 XOR key2 XOR key3

**Distribuir chave de grupo:**

```javascript
group.members.forEach((member) => {
  socket.emit("group_key_distributed", {
    groupName: "Equipe",
    groupKey: groupKey.toString("hex"),
  });
});
```

---

### Etapa 4: Enviar Mensagem em Grupo

```
Alice → Servidor: send_message {
  message: "Olá grupo!",
  targetUser: "Equipe",
  isGroup: true
}
```

**No Servidor:**

1. **Buscar chave de grupo:**

   ```javascript
   const groupKey = group.groupKey; // Buffer de 16 bytes
   ```

2. **Criptografar mensagem:**

   ```javascript
   const encrypted = await ideaBridge.encryptMessage("Olá grupo!", groupKey);
   ```

3. **Enviar para todos os membros:**
   ```javascript
   group.members.forEach((member) => {
     socket.emit("group_message_received", {
       from: "Alice",
       groupName: "Equipe",
       encrypted: encrypted,
       message: "Olá grupo!", // texto plano
       timestamp: new Date().toISOString(),
     });
   });
   ```

---

## 🔧 Detalhes Técnicos

### ECDH Manual

**Classe:** `ECDHManual`

**Métodos principais:**

1. `generateKeyPair()`: Gera par de chaves (privada + pública)
2. `computeSharedSecret(otherPublicKey)`: Calcula chave compartilhada
3. `deriveIDEAKey(sharedSecret)`: Deriva chave de 128 bits

**Fluxo interno:**

```
1. Gera chave privada aleatória (32 bytes)
2. Calcula chave pública usando curva secp256k1 (65 bytes)
3. Recebe chave pública do outro usuário
4. Calcula sharedSecret usando ECDH (32 bytes)
5. Aplica SHA-256 no sharedSecret
6. Pega primeiros 16 bytes = chave IDEA (128 bits)
```

### IDEA Bridge (JavaScript)

**Classe:** `IDEABridgeJS`

**Implementação atual:**

- Usa **AES-128-ECB** como substituição de IDEA
- Modo: ECB (Electronic Codebook)
- Padding: PKCS#7
- Chave: 128 bits (16 bytes)

**Métodos:**

1. `encryptMessage(message, key)`: Criptografa string UTF-8
2. `decryptMessage(ciphertext, key)`: Descriptografa string hex

**Fluxo de criptografia:**

```
1. Recebe mensagem (string UTF-8) e chave (Buffer 16 bytes)
2. Cria cipher AES-128-ECB com a chave
3. Converte mensagem UTF-8 → hex
4. Aplica criptografia
5. Retorna string hex do texto criptografado
```

**Fluxo de descriptografia:**

```
1. Recebe texto criptografado (string hex) e chave (Buffer 16 bytes)
2. Cria decipher AES-128-ECB com a chave
3. Descriptografa hex → UTF-8
4. Remove padding PKCS#7
5. Retorna string UTF-8 da mensagem original
```

---

## 📊 Diagrama de Fluxo

### Chat 1:1

```
┌─────────┐                    ┌──────────┐                    ┌─────────┐
│  Alice  │                    │ Servidor │                    │   Bob   │
└────┬────┘                    └────┬─────┘                    └────┬────┘
     │                               │                               │
     │ 1. user_connect               │                               │
     ├──────────────────────────────>│                               │
     │                               │ Gera par ECDH                │
     │                               │ (privateKey + publicKey)     │
     │ 2. user_connected             │                               │
     │<──────────────────────────────┤                               │
     │ (publicKey)                   │                               │
     │                               │                               │
     │ 3. start_chat("Bob")          │                               │
     ├──────────────────────────────>│                               │
     │                               │ 4. exchange_public_key       │
     │<──────────────────────────────┤                               │
     │ (Bob's publicKey)             │                               │
     │                               │ 5. exchange_public_key       │
     │                               ├──────────────────────────────>│
     │                               │ (Alice's publicKey)          │
     │                               │                               │
     │ 6. exchange_public_key        │                               │
     ├──────────────────────────────>│                               │
     │                               │ Calcula sharedSecret         │
     │                               │ Deriva ideaKey (SHA-256)     │
     │ 7. key_exchanged              │                               │
     │<──────────────────────────────┤                               │
     │ (sharedKey)                   │                               │
     │                               │ 8. exchange_public_key       │
     │                               │<──────────────────────────────┤
     │                               │ Calcula sharedSecret         │
     │                               │ Deriva ideaKey (SHA-256)     │
     │                               │ 9. key_exchanged             │
     │                               ├──────────────────────────────>│
     │                               │ (sharedKey)                  │
     │                               │                               │
     │ 10. chat_ready                │                               │
     │<──────────────────────────────┤                               │
     │                               │ 11. chat_ready               │
     │                               ├──────────────────────────────>│
     │                               │                               │
     │ 12. send_message("Oi")        │                               │
     ├──────────────────────────────>│                               │
     │                               │ Criptografa com ideaKey      │
     │ 13. message_sent              │                               │
     │<──────────────────────────────┤                               │
     │ (encrypted)                   │                               │
     │                               │ Descriptografa               │
     │                               │ 14. message_received         │
     │                               ├──────────────────────────────>│
     │                               │ ("Oi")                       │
```

### Chat em Grupo

```
┌─────────┐  ┌─────────┐  ┌─────────┐
│  Alice  │  │   Bob   │  │ Charlie │
└────┬────┘  └────┬────┘  └────┬────┘
     │            │            │
     │ 1. join_group("Equipe") │
     ├───────────>│            │
     │            │            │
     │ 2. Estabelece chaves com Bob e Charlie
     │            │            │
     │ 3. Todas as chaves estabelecidas
     │            │            │
     │ 4. Gera chave de grupo (XOR de todas)
     │            │            │
     │ 5. group_key_distributed
     │<───────────┤<───────────┤
     │            │            │
     │ 6. send_message("Olá grupo!")
     ├───────────>│            │
     │            │            │
     │ 7. Criptografa com groupKey
     │            │            │
     │ 8. group_message_received
     │            │<───────────┤
     │<───────────┤            │
     │            │            │
```

---

## 🔑 Estrutura de Chaves

### Chaves ECDH

- **Chave privada**: 32 bytes (256 bits)
- **Chave pública**: 65 bytes (520 bits, formato não comprimido)
- **Curva**: secp256k1

### Chaves IDEA

- **Tamanho**: 16 bytes (128 bits)
- **Origem**: Primeiros 16 bytes do SHA-256 do sharedSecret ECDH
- **Formato**: Buffer (servidor) ou string hex (cliente)

### Chaves de Grupo

- **Tamanho**: 16 bytes (128 bits)
- **Geração**: XOR de todas as chaves compartilhadas entre membros
- **Propriedade**: Mesma chave para todos os membros do grupo

---

## 🔍 Debug e Monitoramento

### Modo Debug no Cliente

Quando ativado (`--debug` ou `/debug`), o cliente exibe:

```
🔍 Debug - Mensagem enviada:
   Original: oi
   Criptografada: 876a4ff79431d438af20a4eef1ee3546
   Chave compartilhada (Bob): 929fd12870e7e6b7ba1bef0e305375a8
   Para descriptografar manualmente:
      node utils/decrypt.js 929fd12870e7e6b7ba1bef0e305375a8 876a4ff79431d438af20a4eef1ee3546
```

### Logs do Servidor

O servidor registra:

- Geração de pares de chaves ECDH
- Estabelecimento de chaves compartilhadas
- Criptografia/descriptografia de mensagens
- Geração de chaves de grupo

---

## 🛠️ Utilitários

### Script de Descriptografia

```bash
node utils/decrypt.js <chave_hex> <texto_criptografado_hex>
```

**Funcionalidades:**

- Validação de comprimento de chave (32 caracteres hex)
- Validação de texto criptografado (comprimento par)
- Correção automática se faltar 1 caractere
- Descriptografia usando mesma implementação do servidor

---

## 📝 Notas Importantes

1. **Segurança**: O servidor descriptografa as mensagens antes de enviar ao destinatário. Em produção, o cliente deveria descriptografar localmente.

2. **IDEA vs AES**: O sistema usa AES-128-ECB como substituição de IDEA para simplicidade. IDEA real seria mais complexo de implementar.

3. **Chaves de Grupo**: A chave de grupo é gerada via XOR de todas as chaves compartilhadas. Isso garante que todos os membros tenham a mesma chave.

4. **ECDH**: A implementação usa a biblioteca nativa `crypto` do Node.js para ECDH, mas com uma interface educativa que mostra cada etapa.

5. **Persistência**: As chaves não são persistentes. Se o servidor reiniciar, todas as chaves são perdidas e precisam ser regeneradas.

---

## 🔄 Próximos Passos Possíveis

1. **Implementar IDEA real** em vez de AES
2. **Persistência de chaves** (com segurança adequada)
3. **Cliente descriptografa localmente** (sem servidor descriptografar)
4. **Assinatura digital** para verificação de autenticidade
5. **Perfect Forward Secrecy** (regenerar chaves periodicamente)
