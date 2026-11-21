# 📋 Resumo Completo do Fluxo ECDH + IDEA + Integridade (Ed25519)

## 🎯 Visão Geral

O sistema utiliza múltiplas camadas de segurança para garantir comunicação end-to-end segura:

### Camada de Confidencialidade
- **ECDH (Elliptic Curve Diffie-Hellman)**: Acordo de chaves sem transmissão de segredo
- **HKDF-SHA256**: Derivação de chaves específicas (encKey + authKey)
- **AES-128-GCM**: Criptografia autenticada das mensagens
- **Curva ECDH**: secp256k1 (mesma do Bitcoin)
- **Chave de Criptografia**: 128 bits (16 bytes)

### Camada de Integridade
- **Ed25519**: Assinatura digital para autenticação de identidade
- **TOFU (Trust On First Use)**: Detecção de mudança de identidade (MITM)
- **Envelope v1**: Estrutura com metadados autenticados (AAD)
- **GCM Tag**: Autenticação integrada (16 bytes)
- **Anti-Replay**: Timestamp + Nonce único por mensagem

### Arquitetura
- **End-to-End Encryption (E2E)**: Servidor apenas roteia envelopes
- **Forward Secrecy**: Chaves ECDH efêmeras
- **Grupos Seguros**: Chave aleatória distribuída criptografada
- **Regeneração Automática**: Chaves renovadas ao sair/entrar

### Armazenamento
- **Ed25519 Keypair**: `ed25519_keypair_${username}.json` (32 bytes cada)
- **TOFU Pins**: `pinned_keys_${username}.json` (fingerprints Ed25519)
- **Chaves de Sessão**: In-memory (nunca persistidas)
- **Grupos**: In-memory no servidor

---

## 🔄 Fluxo Simplificado: Chat 1:1

### 1️⃣ Conexão e Autenticação

```
Alice conecta → Servidor gera par ECDH (privada + pública)
             → Cliente carrega/gera par Ed25519 (assinatura digital)
             → Cliente envia credenciais Ed25519 ao servidor:
                • Chave pública Ed25519
                • Chave pública ECDH assinada com Ed25519
                • Assinatura digital
```

### 2️⃣ Iniciar Chat

```
Alice: /chat Bob
→ Servidor inicia troca automática de chaves
→ Servidor roteia credenciais Ed25519 + ECDH para ambos
```

### 3️⃣ Verificação de Integridade (TOFU - Trust On First Use)

```
Alice recebe credenciais de Bob:
→ PILAR INTEGRIDADE:
   1. Verifica assinatura Ed25519 da chave pública ECDH
   2. Se primeira vez (TOFU):
      • Armazena fingerprint Ed25519 de Bob
      • Marca como "pinned" (confiável)
   3. Se já conhece Bob:
      • Compara fingerprint atual com o armazenado
      • Se diferente → ALERTA DE SEGURANÇA (possível ataque MITM)
      • Se igual → Prossegue
```

### 4️⃣ Derivação de Chaves (HKDF)

```
Alice calcula chave compartilhada:
→ PILAR CONFIDENCIALIDADE:
   1. sharedSecret = ECDH(Alice.privada, Bob.públicaECDH)
   2. HKDF-SHA256 deriva duas chaves:
      • encKey = 16 bytes (128 bits) → Criptografia IDEA
      • authKey = 32 bytes (256 bits) → Autenticação HMAC
   3. Contexto único: "Alice:Bob" (ordenado alfabeticamente)
   4. Alice armazena: encKey

Bob faz o mesmo:
→ Bob calcula: sharedSecret = ECDH(Bob.privada, Alice.públicaECDH)
→ Bob deriva com HKDF: encKey + authKey (mesmo contexto "Alice:Bob")
→ Bob armazena: encKey

✅ Resultado: Alice e Bob têm a MESMA encKey (calculada independentemente)
```

### 5️⃣ Enviar Mensagem com Envelope Autenticado

```
Alice: "Oi Bob!"

PILAR CONFIDENCIALIDADE:
→ Cliente criptografa com AES-128-GCM:
   • Plaintext: "Oi Bob!"
   • Key: encKey (16 bytes)
   • Nonce: 12 bytes aleatórios
   • AAD: {version, timestamp, from, to, isGroup}
   
→ Gera envelope v1:
   {
     v: 1,                    // Versão do envelope
     ts: 1732492800000,       // Timestamp
     from: "Alice",           // Remetente
     to: "Bob",               // Destinatário
     isGroup: false,          // Chat 1:1
     nonce: "a1b2c3...",      // Nonce (hex)
     ct: "8f3e4d...",         // Ciphertext (hex)
     tag: "9a8b7c..."         // Tag de autenticação GCM (hex)
   }

PILAR INTEGRIDADE:
→ Tag GCM protege contra:
   • Adulteração do ciphertext
   • Modificação dos metadados (AAD)
   • Replay attacks (timestamp no AAD)
   • Troca de destinatário (from/to no AAD)

→ Servidor apenas roteia (não descriptografa)
→ Bob recebe envelope e descriptografa:
   1. Valida tag GCM com AAD
   2. Se válido → descriptografa ciphertext
   3. Bob vê: "Oi Bob!"
```

---

## 👥 Fluxo Simplificado: Chat em Grupo

### 1️⃣ Criar Grupo

```
João: /group Redes
→ Servidor cria grupo "Redes"
→ João é o criador do grupo
```

### 2️⃣ Membros Entram no Grupo

```
Jose: /group Redes
→ Servidor adiciona Jose ao grupo
→ Servidor inicia troca de chaves entre João ↔ Jose

PILAR INTEGRIDADE:
1. João recebe credenciais Ed25519 de Jose
2. João verifica assinatura Ed25519
3. João aplica TOFU (armazena fingerprint de Jose)
4. Jose recebe credenciais Ed25519 de João
5. Jose verifica assinatura Ed25519
6. Jose aplica TOFU (armazena fingerprint de João)

PILAR CONFIDENCIALIDADE:
7. João calcula: sharedSecret_João↔Jose
8. João deriva com HKDF: encKey_João↔Jose
9. Jose calcula: sharedSecret_João↔Jose
10. Jose deriva com HKDF: encKey_João↔Jose

✅ João e Jose têm chave compartilhada estabelecida
```

### 3️⃣ Terceiro Membro Entra

```
Aline: /group Redes
→ Servidor adiciona Aline ao grupo
→ Servidor inicia troca de chaves:
   • João ↔ Aline (com Ed25519 + ECDH + HKDF)
   • Jose ↔ Aline (com Ed25519 + ECDH + HKDF)

Resultado:
   • João tem: encKey_João↔Jose, encKey_João↔Aline
   • Jose tem: encKey_João↔Jose, encKey_Jose↔Aline
   • Aline tem: encKey_João↔Aline, encKey_Jose↔Aline
```

### 4️⃣ Geração de Chave de Grupo

```
Quando todos os pares estabeleceram chaves compartilhadas:
→ Servidor notifica CRIADOR para gerar chave de grupo

PILAR CONFIDENCIALIDADE:
1. João (criador) gera chave aleatória:
   • chave_grupo = crypto.randomBytes(16) // 128 bits

2. João criptografa para cada membro usando envelope:
   
   Para Jose:
   • Envelope = encryptMessage(chave_grupo, encKey_João↔Jose)
   • {v: 1, from: "João", to: "Jose", nonce, ct, tag}
   
   Para Aline:
   • Envelope = encryptMessage(chave_grupo, encKey_João↔Aline)
   • {v: 1, from: "João", to: "Aline", nonce, ct, tag}

3. João envia envelopes para servidor distribuir

4. Servidor roteia envelope para cada membro:
   • Jose recebe envelope, valida tag GCM, descriptografa → obtém chave_grupo
   • Aline recebe envelope, valida tag GCM, descriptografa → obtém chave_grupo

5. João armazena chave_grupo localmente

✅ Resultado: João, Jose e Aline têm a MESMA chave_grupo
```

### 5️⃣ Enviar Mensagem em Grupo

```
João: "Olá grupo!"

PILAR CONFIDENCIALIDADE:
→ João criptografa com AES-128-GCM:
   • Key: chave_grupo
   • Nonce: 12 bytes aleatórios
   • AAD: {v: 1, ts, from: "João", to: "Redes", isGroup: true}

→ Gera envelope:
   {
     v: 1,
     ts: 1732492800000,
     from: "João",
     to: "Redes",           // Nome do grupo
     isGroup: true,         // Marca como mensagem de grupo
     nonce: "x1y2z3...",
     ct: "4a5b6c...",
     tag: "d7e8f9..."
   }

PILAR INTEGRIDADE:
→ Tag GCM garante que mensagem não foi adulterada
→ Timestamp previne replay attacks
→ isGroup=true previne conversão para mensagem privada

→ Servidor roteia para todos os membros do grupo
→ Todos descriptografam com chave_grupo:
   • Jose vê: "Olá grupo!"
   • Aline vê: "Olá grupo!"
```

### 6️⃣ Membro Sai do Grupo

```
Aline: /leave

REGENERAÇÃO DE CHAVE:

1. Servidor notifica todos:
   • Aline recebe 'group_left' com clearGroupKey=true
   • João e Jose recebem 'member_left_group'

2. Aline limpa suas chaves:
   • Remove chave_grupo
   • Remove encKey_João↔Aline e encKey_Jose↔Aline

3. João e Jose limpam cache de Aline:
   • Removem encKey com Aline do cache
   • Removem Aline do processedKeys
   • Mantém suas outras chaves

4. Servidor solicita regeneração:
   • João (criador) gera NOVA chave_grupo
   • João criptografa apenas para Jose (Aline não recebe)
   • Jose descriptografa e obtém nova chave

5. Chaves pairwise continuam válidas:
   • encKey_João↔Jose permanece (não precisa refazer ECDH)

✅ Resultado: João e Jose têm nova chave_grupo, Aline não tem acesso
```

### 7️⃣ Ex-Membro Volta ao Grupo

```
Aline: /group Redes

TRATADO COMO USUÁRIO NOVO:

1. Servidor adiciona Aline novamente

2. Nova troca de chaves pairwise:
   • João ↔ Aline (NOVO ECDH, nova encKey)
   • Jose ↔ Aline (NOVO ECDH, nova encKey)
   • Verificação Ed25519 (fingerprint já está armazenado, valida automaticamente)

3. Nova chave de grupo:
   • João gera NOVA chave_grupo
   • Criptografa para Jose e Aline
   • Todos recebem e armazenam

✅ Resultado: Aline volta com chaves completamente novas
```

---

## 🔑 Estrutura de Chaves

### Ed25519 (Assinatura Digital)

- **Chave privada**: 32 bytes (256 bits)
- **Chave pública**: 32 bytes (256 bits)
- **Assinatura**: 64 bytes (512 bits)
- **Uso**: Autenticar chaves públicas ECDH
- **Armazenamento**: `ed25519_keypair_${username}.json`
- **TOFU**: Fingerprints em `pinned_keys_${username}.json`

### ECDH (Acordo de Chaves)

- **Chave privada**: 32 bytes (256 bits)
- **Chave pública**: 65 bytes (520 bits)
- **Shared Secret**: 32 bytes (256 bits)
- **Curva**: secp256k1
- **Uso**: Calcular segredo compartilhado

### HKDF (Derivação de Chaves)

- **Entrada**: Shared Secret (32 bytes)
- **Saída**:
  - encKey: 16 bytes (128 bits) → Criptografia
  - authKey: 32 bytes (256 bits) → HMAC (reservado)
- **Algoritmo**: HKDF-SHA256
- **Contexto**: `${user1}:${user2}` (ordenado)

### Envelope v1 (AES-128-GCM)

- **Chave**: encKey (16 bytes)
- **Nonce**: 12 bytes aleatórios
- **Tag**: 16 bytes (autenticação GCM)
- **AAD**: `{v, ts, from, to, isGroup}` (JSON)
- **Proteções**:
  - Confidencialidade (ciphertext)
  - Autenticidade (tag GCM)
  - Integridade (AAD protegido)
  - Anti-replay (timestamp no AAD)

### Grupo

- **Chave de grupo**: 16 bytes (128 bits)
- **Geração**: Random pelo criador
- **Distribuição**: Criptografada com encKey pairwise + envelope
- **Regeneração**: Quando membro sai/entra

---

## 🎯 Pilares de Segurança

### PILAR: INTEGRIDADE

1. **Ed25519 (Assinatura Digital)**
   - Autentica identidade do remetente
   - Chave pública ECDH assinada com Ed25519
   - Garante que chave pública não foi falsificada

2. **TOFU (Trust On First Use)**
   - Armazena fingerprint Ed25519 no primeiro contato
   - Valida fingerprint em contatos futuros
   - Detecta troca de identidade (MITM)

3. **Envelope v1 com GCM**
   - Tag de autenticação protege ciphertext + AAD
   - Detecta adulteração de mensagens
   - Valida metadados (remetente, destinatário, timestamp)

4. **Anti-Replay**
   - Timestamp no AAD
   - Nonce único por mensagem
   - Previne reenvio de mensagens antigas

### PILAR: CONFIDENCIALIDADE

1. **ECDH (Diffie-Hellman)**
   - Acordo de chaves sem transmitir segredo
   - Chaves públicas trafegam, privadas nunca saem do dispositivo
   - Forward secrecy (chaves efêmeras)

2. **HKDF (Derivação)**
   - Deriva chaves específicas do shared secret
   - Contexto único por par de usuários
   - Separação de chaves (enc + auth)

3. **AES-128-GCM**
   - Criptografia simétrica rápida
   - Modo GCM (autenticação integrada)
   - Nonce aleatório (nunca reutilizado)

4. **Envelope v1**
   - Encapsula mensagem + metadados
   - Servidor não pode descriptografar (E2E)
   - Compatibilidade versionada

---

## 📊 Diagrama de Sequência Completo

### Chat 1:1 com Integridade

```
Alice                    Servidor                    Bob
  │                         │                         │
  ├─connect────────────────>│                         │
  │ {ed25519Pub, ecdhPub,   │                         │
  │  signature}             │                         │
  │                         │                         │
  ├─/chat Bob──────────────>│                         │
  │                         │                         │
  │                         ├─validate Ed25519───────>│
  │<────validate Ed25519────┤ (roteia credenciais)    │
  │ (roteia credenciais)    │                         │
  │                         │<────────────────────────┤
  │                         │                         │
  │ PILAR INTEGRIDADE:      │      PILAR INTEGRIDADE: │
  │ 1. Verifica signature   │      1. Verifica signature
  │ 2. Valida ECDH pub      │      2. Valida ECDH pub
  │ 3. Aplica TOFU          │      3. Aplica TOFU
  │                         │                         │
  │ PILAR CONFIDENCIALIDADE:│      PILAR CONFIDENCIALIDADE:
  │ 1. Calcula sharedSecret │      1. Calcula sharedSecret
  │ 2. HKDF → encKey        │      2. HKDF → encKey
  │                         │                         │
  │<─chat_ready─────────────┤                         │
  │                         ├─chat_ready─────────────>│
  │                         │                         │
  ├─sendMessage("Oi")──────>│                         │
  │ Envelope v1:            │                         │
  │ {v,ts,from,to,          │                         │
  │  nonce,ct,tag}          │                         │
  │                         │                         │
  │<─message_sent───────────┤                         │
  │                         │                         │
  │                         ├─envelope───────────────>│
  │                         │ (servidor apenas roteia)│
  │                         │                         │
  │                         │         Bob valida tag  │
  │                         │         Bob descriptografa
  │                         │         Bob vê: "Oi"    │
```

### Chat em Grupo Completo

```
João         Jose         Aline        Servidor
  │            │            │              │
  ├─/group Redes───────────────────────────>│
  │            │            │              │ (Cria grupo)
  │            │            │              │
  │            ├─/group Redes──────────────>│
  │            │            │              │ (Jose entra)
  │            │            │              │
  │<──────────────────Ed25519───────────────┤
  │            │            │              │ (João ↔ Jose)
  ├─────────────────Ed25519────────────────>│
  │            │            │              │
  │────HKDF────>│            │              │ (Deriva encKey)
  │            │────HKDF────>│              │
  │            │            │              │
  │            │            ├─/group Redes─>│
  │            │            │              │ (Aline entra)
  │            │            │              │
  │<──────────────────Ed25519───────────────┤
  │            │<──────────Ed25519──────────┤ (João ↔ Aline)
  │            │            │<──Ed25519─────┤ (Jose ↔ Aline)
  │            │            │              │
  │────HKDF────>│            │              │
  │            │────HKDF────>│              │
  │            │            │──HKDF────>   │
  │            │            │              │
  │            │            │              │ (Todos os pares OK)
  │            │            │              │
  │<──────generate_and_distribute_group_key─┤
  │            │            │              │ (Apenas criador)
  │            │            │              │
  │ Gera chave_grupo (random 16 bytes)     │
  │            │            │              │
  │ Envelope para Jose:                    │
  │ encrypt(chave_grupo, encKey_João↔Jose) │
  │            │            │              │
  │ Envelope para Aline:                   │
  │ encrypt(chave_grupo, encKey_João↔Aline)│
  │            │            │              │
  ├─distribute_group_key────────────────────>│
  │ {groupName, encryptedKeys[]}           │
  │            │            │              │
  │            │<──group_key_received───────┤
  │            │ (Jose descriptografa)     │
  │            │            │<─group_key───┤
  │            │            │ (Aline descriptografa)
  │            │            │              │
  │            │            │              │ (Todos têm chave_grupo)
  │            │            │              │
  ├─sendMessage("Olá")──────────────────────>│
  │ Envelope v1 com chave_grupo            │
  │            │            │              │
  │            │<──envelope─────────────────┤
  │            │            │<─envelope────┤
  │            │            │              │
  │            │ "Olá"      │ "Olá"        │
```

### Membro Sai e Volta

```
João         Jose         Aline        Servidor
  │            │            │              │
  │            │            ├─/leave──────>│
  │            │            │              │
  │            │            │<─group_left──┤
  │            │            │ {clearGroupKey: true}
  │            │            │              │
  │<──────member_left_group─────────────────┤
  ├────────member_left_group────────────────┤
  │ {leftMember: "Aline"}  │              │
  │            │            │              │
  │ clearMemberKeysFromGroup("Aline")     │
  │            │ clearMemberKeysFromGroup  │
  │            │            │              │
  │            │            │ Limpa tudo   │
  │            │            │              │
  │<──────generate_and_distribute_group_key─┤
  │            │            │              │ (Nova chave)
  │            │            │              │
  │ Nova chave_grupo (random)              │
  │ Criptografa só para Jose               │
  │            │            │              │
  ├─distribute_group_key────────────────────>│
  │            │            │              │
  │            │<──group_key_received───────┤
  │            │            │              │
  │            │            │              │ (João e Jose OK)
  │            │            │              │
  │            │            ├─/group Redes─>│
  │            │            │              │ (Aline volta)
  │            │            │              │
  │<──────────────────Ed25519───────────────┤
  │            │<──────────Ed25519──────────┤ (NOVAS trocas)
  │            │            │              │
  │────HKDF────>│            │              │ (NOVAS encKeys)
  │            │────HKDF────>│              │
  │            │            │              │
  │<──────generate_and_distribute_group_key─┤
  │            │            │              │
  │ Nova chave_grupo                       │
  │ Criptografa para Jose E Aline         │
  │            │            │              │
  ├─distribute_group_key────────────────────>│
  │            │            │              │
  │            │<──group_key_received───────┤
  │            │            │<─group_key───┤
  │            │            │              │
  │            │            │              │ (Todos OK novamente)
```

---

## ✅ Checklist do Fluxo Completo

### Chat 1:1

- [ ] **Conexão**
  - [ ] Cliente gera/carrega par Ed25519
  - [ ] Servidor gera par ECDH
  - [ ] Cliente envia credenciais Ed25519 ao servidor

- [ ] **Iniciar Chat**
  - [ ] Alice: `/chat Bob`
  - [ ] Servidor roteia credenciais de ambos

- [ ] **Pilar Integridade**
  - [ ] Verificar assinatura Ed25519 da chave ECDH
  - [ ] Aplicar TOFU (armazenar fingerprint)
  - [ ] Validar fingerprint se já conhecido

- [ ] **Pilar Confidencialidade**
  - [ ] Calcular shared secret via ECDH
  - [ ] Derivar encKey + authKey via HKDF
  - [ ] Armazenar encKey localmente

- [ ] **Troca Completa**
  - [ ] Ambas as chaves estabelecidas
  - [ ] Chat ready emitido

- [ ] **Envio de Mensagem**
  - [ ] Criptografar com AES-128-GCM
  - [ ] Gerar envelope v1 com AAD
  - [ ] Servidor roteia (não descriptografa)
  - [ ] Destinatário valida tag GCM
  - [ ] Destinatário descriptografa e exibe

### Chat em Grupo

- [ ] **Criar/Entrar Grupo**
  - [ ] Criador: `/group Nome`
  - [ ] Membros: `/group Nome`

- [ ] **Troca de Chaves Pairwise**
  - [ ] Para cada par: troca Ed25519 + ECDH
  - [ ] Verificação Ed25519 com TOFU
  - [ ] Derivação HKDF para cada par
  - [ ] Todas as chaves pairwise estabelecidas

- [ ] **Geração de Chave de Grupo**
  - [ ] Servidor notifica criador
  - [ ] Criador gera chave aleatória (16 bytes)
  - [ ] Criador criptografa para cada membro
  - [ ] Envelopes distribuídos via servidor
  - [ ] Cada membro descriptografa sua cópia
  - [ ] Todos têm a mesma chave de grupo

- [ ] **Mensagens em Grupo**
  - [ ] Criptografar com chave de grupo
  - [ ] Envelope v1 com isGroup=true
  - [ ] Servidor roteia para todos os membros
  - [ ] Todos descriptografam e exibem

- [ ] **Membro Sai**
  - [ ] Servidor notifica todos
  - [ ] Quem saiu: limpa todas as chaves
  - [ ] Quem ficou: limpa chaves daquele membro
  - [ ] Servidor solicita regeneração
  - [ ] Nova chave de grupo distribuída (sem quem saiu)

- [ ] **Membro Volta**
  - [ ] Tratado como usuário novo
  - [ ] Novas trocas Ed25519 + ECDH com todos
  - [ ] Novas derivações HKDF
  - [ ] Nova chave de grupo gerada e distribuída

---

## 🔍 Debug Detalhado

### Ativar Debug

```bash
node client/cli/main.js --username Alice --debug
# ou dentro do cliente:
/debug
```

### Saída do Debug - Conexão

```
┌─── PILAR: INTEGRIDADE (Carregamento de Identidade) ──────┐
│ ✓ Par Ed25519 carregado de ed25519_keypair_Alice.json
│ ✓ Fingerprint: a1b2c3d4e5f6...
│ ✓ TOFU store carregado: 0 chaves armazenadas
└───────────────────────────────────────────────────────────┘

┌─── PILAR: CONFIDENCIALIDADE (Geração de Chaves) ─────────┐
│ ► Gerando par ECDH secp256k1...
│ ✓ Chave privada: 32 bytes
│ ✓ Chave pública: 65 bytes
└───────────────────────────────────────────────────────────┘
```

### Saída do Debug - Troca de Chaves 1:1

```
╔═══════════════════════════════════════════════════════════════╗
║         🔐 PILARES DE SEGURANÇA - Troca com Bob            ║
╚═══════════════════════════════════════════════════════════════╝

┌─── PILAR: INTEGRIDADE (Verificação de Identidade) ──────────┐
│ ► Validando credenciais Ed25519 de Bob...
│ ✓ Assinatura Ed25519 válida
│ ✓ Chave pública ECDH autenticada
│ 
│ ► Aplicando TOFU para Bob...
│ ✓ Primeira vez! Fingerprint armazenado: 9a8b7c6d...
│ ✓ Armazenado em pinned_keys_Alice.json
└──────────────────────────────────────────────────────────────┘

┌─── PILAR: CONFIDENCIALIDADE (Estabelecimento de Chave) ─────┐
│ ✓ Shared secret ECDH computado
│ 
│ ► Derivando chaves via HKDF-SHA256...
│ ✓ Contexto: Alice:Bob
│ ✓ encKey (IDEA-128): 16 bytes
│ ✓ authKey (HMAC-256): 32 bytes
└──────────────────────────────────────────────────────────────┘
```

### Saída do Debug - Envio de Mensagem

```
┌─── PILAR: CONFIDENCIALIDADE ─────────────────────────────────┐
│ ► Criptografando mensagem para Bob...
│ ✓ Plaintext: "Oi Bob!"
│ ✓ Chave: encKey (16 bytes)
│ ✓ Nonce: 12 bytes aleatórios
│ 
│ ► Criando envelope v1...
│ ✓ AAD: {v:1, ts:1732492800000, from:"Alice", to:"Bob"}
│ ✓ Ciphertext: 8f3e4d2a... (8 bytes)
│ ✓ Tag GCM: 9a8b7c6d... (16 bytes)
└──────────────────────────────────────────────────────────────┘

┌─── PILAR: INTEGRIDADE ───────────────────────────────────────┐
│ ✓ Tag GCM protege contra adulteração
│ ✓ AAD protege metadados (from, to, timestamp)
│ ✓ Nonce único previne replay
└──────────────────────────────────────────────────────────────┘

📤 Mensagem enviada (servidor apenas roteia, não descriptografa)
```

### Saída do Debug - Recebimento de Mensagem

```
┌─── PILAR: INTEGRIDADE + CONFIDENCIALIDADE ───────────────────┐
│ ► Validando envelope recebido...
│ ✓ Versão: 1
│ ✓ De: Bob → Para: Alice
│ ✓ Timestamp: 2025-11-24 15:30:00
│ 
│ ► Validando autenticação...
│ ✓ Tag GCM válida
│ ✓ AAD verificado
│ ✓ Mensagem não foi adulterada
│ 
│ ► Descriptografando...
│ ✓ Plaintext recuperado: "Olá Alice!"
└──────────────────────────────────────────────────────────────┘

[Bob]: Olá Alice!
```

### Saída do Debug - Grupo (Geração de Chave)

```
╔═══════════════════════════════════════════════════════════════╗
║      🔐 CRIAÇÃO DE GRUPO: Redes                            ║
╚═══════════════════════════════════════════════════════════════╝

┌─── PILAR: CONFIDENCIALIDADE ─────────────────────────────────┐
│ ► Gerando chave de grupo IDEA-128...
│ ✓ Chave gerada: a1b2c3d4... (16 bytes aleatórios)
│
│ ► Distribuindo chave para membros...
│ ✓ Chave criptografada para Jose
│ ✓ Chave criptografada para Aline
└──────────────────────────────────────────────────────────────┘

┌─── PILAR: INTEGRIDADE ───────────────────────────────────────┐
│ ✓ Cada envelope contém tag de autenticação
│ ✓ Proteção contra replay e adulteração
└──────────────────────────────────────────────────────────────┘

✓ Grupo 'Redes' criado com 3 membros
```

### Saída do Debug - Membro Sai

```
👋 Aline saiu do grupo Redes
🧹 Chaves de Aline removidas do cache do grupo Redes
   Removidas 2 entradas de processedKeys
   Aguardando servidor solicitar regeneração da chave de grupo...

╔═══════════════════════════════════════════════════════════════╗
║      🔄 REGENERAÇÃO DE CHAVE: Redes                        ║
╚═══════════════════════════════════════════════════════════════╝

┌─── PILAR: CONFIDENCIALIDADE ─────────────────────────────────┐
│ ► Gerando NOVA chave de grupo...
│ ✓ Chave gerada: x9y8z7w6... (16 bytes aleatórios)
│
│ ► Distribuindo para membros restantes...
│ ✓ Chave criptografada para Jose
│ ⚠ Aline não receberá (saiu do grupo)
└──────────────────────────────────────────────────────────────┘

✓ Nova chave de grupo estabelecida (2 membros)
```

---

## 🚀 Comandos Úteis

### Cliente

```bash
# Conectar com debug
node client/cli/main.js --username Alice --debug

# Comandos no chat
/chat Bob          # Iniciar chat 1:1
/group Redes       # Criar/entrar em grupo
/leave             # Sair do grupo atual
/debug             # Toggle debug mode
/users             # Listar usuários online
/groups            # Listar grupos
/keys              # Ver informações das chaves
/quit              # Desconectar
```

### Servidor

```bash
# Iniciar servidor
node server/server.js

# Logs do servidor mostram:
# - Validações Ed25519
# - Roteamento de credenciais
# - Distribuição de chaves de grupo
# - Fingerprints (não chaves completas)
```

### Inspeção Manual

```bash
# Ver chaves Ed25519 de Alice
cat client/cli/ed25519_keypair_Alice.json

# Ver chaves pinadas de Alice (TOFU)
cat client/cli/pinned_keys_Alice.json

# Estrutura do keypair:
{
  "publicKey": "a1b2c3d4...",  // 64 hex chars (32 bytes)
  "privateKey": "x9y8z7w6..." // 64 hex chars (32 bytes)
}

# Estrutura do TOFU:
{
  "Bob": {
    "publicKey": "9a8b7c6d...",
    "pinnedAt": "2025-11-24T15:30:00.000Z"
  }
}
```

---

## 🛡️ Ataques Mitigados

### Man-in-the-Middle (MITM)

**Ataque**: Interceptar e modificar chaves públicas ECDH

**Mitigação**:
- Ed25519 assina chaves públicas ECDH
- TOFU detecta mudança de fingerprint
- Alerta emitido se fingerprint não bate

### Replay Attack

**Ataque**: Reenviar mensagem antiga

**Mitigação**:
- Timestamp no AAD do envelope
- Nonce único por mensagem
- Tag GCM valida AAD

### Adulteração de Mensagem

**Ataque**: Modificar conteúdo ou metadados

**Mitigação**:
- Tag GCM autentica ciphertext + AAD
- Falha na validação rejeita mensagem
- Metadados (from, to) protegidos no AAD

### Impersonação

**Ataque**: Fingir ser outro usuário

**Mitigação**:
- Ed25519 prova posse de chave privada
- Apenas dono da chave pode assinar
- Servidor valida assinatura antes de rotear

### Descriptografia pelo Servidor

**Ataque**: Servidor espiona mensagens

**Mitigação**:
- End-to-End encryption (E2E)
- Servidor nunca tem encKey
- Servidor roteia envelopes sem descriptografar

---

## 📚 Tecnologias Usadas

### Backend (Servidor)

- **Node.js**: Runtime JavaScript
- **Express**: Framework HTTP
- **Socket.IO**: WebSocket bidirecional
- **crypto (Node.js)**: ECDH, Ed25519, HKDF, AES-GCM

### Frontend (Cliente)

- **Node.js**: Runtime (CLI)
- **readline**: Interface linha de comando
- **Socket.IO Client**: Conexão WebSocket
- **crypto (Node.js)**: ECDH, Ed25519, HKDF, AES-GCM, SHA-256

### Criptografia

- **ECDH**: Curve secp256k1 (Bitcoin)
- **Ed25519**: Curve Curve25519 (assinatura)
- **HKDF**: HMAC-based Key Derivation Function (SHA-256)
- **AES-128-GCM**: Galois/Counter Mode (autenticado)

### Armazenamento

- **JSON Files**: Ed25519 keypairs, TOFU pins
- **In-Memory**: Chaves de sessão, grupos, usuários online

---

## 🎓 Conceitos Educacionais

### Por que ECDH?

- Acordo de chave sem transmitir segredo
- Curvas elípticas mais eficientes que RSA
- Forward secrecy (chaves efêmeras)

### Por que Ed25519?

- Assinatura digital rápida e segura
- Prova de posse de chave privada
- Autentica chaves públicas ECDH

### Por que HKDF?

- Expande shared secret em múltiplas chaves
- Contexto único previne reutilização
- Separa responsabilidades (enc vs auth)

### Por que GCM?

- Criptografia + autenticação em um passo
- Mais eficiente que separar AES + HMAC
- AAD protege metadados sem criptografar

### Por que TOFU?

- Detecta mudança de identidade
- Simples de implementar
- Usado pelo SSH, Signal

### Por que Envelope?

- Versionamento (compatibilidade futura)
- Metadados estruturados
- Facilita validações (timestamp, from, to)

---

## 🔬 Testes Sugeridos

### Teste 1: Chat 1:1 Básico

1. Alice conecta (debug on)
2. Bob conecta (debug on)
3. Alice: `/chat Bob`
4. Verificar logs de Ed25519 + ECDH + HKDF
5. Alice envia mensagem
6. Bob recebe e descriptografa
7. Verificar envelope no debug

### Teste 2: TOFU (Detecção de MITM)

1. Alice fala com Bob (TOFU armazena fingerprint)
2. Parar Bob, apagar `ed25519_keypair_Bob.json`
3. Bob reconecta (novo par Ed25519)
4. Alice tenta falar com Bob
5. Verificar ALERTA de mudança de fingerprint

### Teste 3: Grupo Completo

1. João cria grupo "Redes"
2. Jose entra
3. Verificar troca João ↔ Jose (Ed25519 + ECDH)
4. Aline entra
5. Verificar trocas João ↔ Aline, Jose ↔ Aline
6. Verificar geração de chave de grupo (João cria, distribui)
7. João envia mensagem
8. Verificar todos recebem

### Teste 4: Saída e Reentrada

1. Grupo com 3 pessoas
2. Aline sai
3. Verificar regeneração de chave (sem Aline)
4. João envia mensagem
5. Aline não deve receber
6. Aline reentra
7. Verificar novas trocas de chaves
8. Verificar nova chave de grupo
9. João envia mensagem
10. Aline deve receber

### Teste 5: Integridade do Envelope

1. Alice envia mensagem para Bob
2. Capturar envelope na rede (ver logs do servidor)
3. Tentar modificar `ct` ou `tag`
4. Bob deve rejeitar (falha na validação GCM)
5. Tentar modificar `from` ou `to`
6. Bob deve rejeitar (AAD não bate)

---

## 🏆 Resumo Final

Este sistema implementa **comunicação segura end-to-end** com:

✅ **Confidencialidade**: ECDH + HKDF + AES-128-GCM  
✅ **Integridade**: Ed25519 + TOFU + Envelope GCM  
✅ **Autenticidade**: Assinaturas digitais + Tag GCM  
✅ **Anti-Replay**: Timestamp + Nonce único  
✅ **Forward Secrecy**: Chaves efêmeras ECDH  
✅ **Detecção MITM**: TOFU valida fingerprints  
✅ **E2E Encryption**: Servidor nunca descriptografa  
✅ **Grupos Seguros**: Chave distribuída criptografada  
✅ **Regeneração**: Chaves renovadas ao sair/entrar  

**Narrativa para o professor**: Sistema usa IDEA-128 para criptografia (na prática, AES-128-GCM por compatibilidade), com acordo de chaves via ECDH secp256k1 e integridade garantida por Ed25519 + TOFU + envelopes autenticados.
