# 🛡️ Integridade: Ed25519 + TOFU

Documentação completa sobre a camada de integridade do sistema, explicando como funciona a assinatura digital Ed25519 e o mecanismo TOFU (Trust On First Use).

---

## 📋 Índice

1. [O que é Ed25519](#o-que-é-ed25519)
2. [Chaves Pública e Privada](#chaves-pública-e-privada)
3. [Como Funciona a Assinatura](#como-funciona-a-assinatura)
4. [TOFU - Trust On First Use](#tofu---trust-on-first-use)
5. [Interação Ed25519 + TOFU](#interação-ed25519--tofu)
6. [Armazenamento no Sistema](#armazenamento-no-sistema)
7. [Fases de Uso](#fases-de-uso)
8. [Por que Precisamos de Ambos](#por-que-precisamos-de-ambos)
9. [Cenário de Ataque MITM](#cenário-de-ataque-mitm)
10. [Comparação de Eficiência](#comparação-de-eficiência)

---

## 🔐 O que é Ed25519?

**Ed25519** é um algoritmo de **assinatura digital** baseado em criptografia de curva elíptica (especificamente, Curve25519). Ele permite:

- ✅ **Autenticar** a identidade do remetente
- ✅ **Provar** que uma mensagem não foi adulterada
- ✅ **Verificar** autoria sem revelar chave privada

### Características Técnicas

```
Algoritmo: EdDSA (Edwards-curve Digital Signature Algorithm)
Curva: Curve25519
Chave Pública: 32 bytes (256 bits)
Chave Privada: 32 bytes (256 bits)
Assinatura: 64 bytes (512 bits)
Segurança: ~128 bits (equivalente a RSA 3072)
Performance: Muito rápida (mais que RSA e ECDSA)
```

---

## 🔑 Chaves Pública e Privada

Ed25519 usa **criptografia assimétrica**, que sempre envolve dois componentes:

```
┌─────────────────────────────────────────────────────────────┐
│                    PAR DE CHAVES Ed25519                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  🔴 CHAVE PRIVADA (32 bytes)                                │
│  ├─ Mantida em SEGREDO absoluto                             │
│  ├─ Armazenada em: ed25519_keypair_${username}.json        │
│  ├─ NUNCA compartilhada com ninguém                         │
│  ├─ NUNCA enviada pela rede                                 │
│  └─ Usada para: ASSINAR dados (criar assinaturas)          │
│                                                             │
│  🔵 CHAVE PÚBLICA (32 bytes)                                │
│  ├─ Compartilhada LIVREMENTE                                │
│  ├─ Enviada para: Servidor e outros usuários               │
│  ├─ Armazenada por outros em: pinned_keys_${username}.json │
│  └─ Usada para: VERIFICAR assinaturas                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Por que Duas Chaves?

| Chave | Papel | Analogia |
|-------|-------|----------|
| **Privada** | Criar assinaturas | Seu anel de selo (medieval) |
| **Pública** | Verificar assinaturas | Imagem do seu selo (conhecida) |

**Propriedade Matemática**: 
- Qualquer coisa assinada com a chave privada **só pode** ser verificada com a chave pública correspondente
- Impossível derivar a chave privada a partir da pública (matemática de curvas elípticas)

---

## 📝 Como Funciona a Assinatura

### Analogia: Selo de Cera Medieval

Imagine que você está na Idade Média e quer enviar uma carta:

```
1. Você escreve a carta (mensagem)
2. Você dobra e lacra com cera quente
3. Você pressiona seu ANEL (chave privada) na cera
   → Deixa uma marca ÚNICA que só seu anel pode fazer
4. Destinatário recebe a carta
5. Destinatário vê a marca do seu anel na cera
6. Destinatário compara com imagem conhecida do seu anel (chave pública)
   → Confirma que foi VOCÊ quem enviou
   → Confirma que carta NÃO FOI ABERTA (cera intacta)
```

**Ed25519 faz exatamente isso digitalmente!**

### Processo Técnico

#### 1️⃣ Assinatura (Alice com chave privada)

```javascript
// Dados a assinar
const data = ecdhPublicKey; // Exemplo: chave ECDH

// Chave privada Ed25519 de Alice
const privateKey = ed25519PrivateKey; // 32 bytes

// Criar assinatura
const signature = crypto.sign(null, data, privateKey);
// signature: 64 bytes únicos para esse data + privateKey
```

**O que a assinatura garante:**
- ✅ Apenas quem tem a chave privada pode criar essa assinatura
- ✅ A assinatura é única para os dados específicos
- ✅ Se os dados mudarem, a assinatura não será válida

#### 2️⃣ Verificação (Bob com chave pública)

```javascript
// Dados recebidos
const data = ecdhPublicKey;        // O que foi assinado
const signature = receivedSignature; // Assinatura recebida
const publicKey = ed25519PublicKey;  // Chave pública de Alice

// Verificar assinatura
const isValid = crypto.verify(null, data, publicKey, signature);

if (isValid) {
  // ✓ Assinatura válida
  // ✓ Os dados foram criados por quem tem a chave privada correspondente
  // ✓ Os dados não foram modificados
} else {
  // ✗ Assinatura inválida
  // ✗ Possível adulteração ou falsificação
}
```

---

## 🔄 Fluxo Completo de Assinatura e Verificação

### Alice Assina sua Chave Pública ECDH

```
┌─────────────────────────────────────────────────────────────┐
│                    LADO DA ALICE                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ 1. Alice conecta ao sistema                                 │
│                                                             │
│ 2. Alice gera par ECDH efêmero (sessão):                    │
│    ecdhPrivateKey = [32 bytes aleatórios]                   │
│    ecdhPublicKey = [65 bytes derivados]                     │
│                                                             │
│ 3. Alice carrega sua identidade Ed25519:                    │
│    Arquivo: ed25519_keypair_Alice.json                      │
│    ed25519PrivateKey = [32 bytes do arquivo]                │
│    ed25519PublicKey = [32 bytes do arquivo]                 │
│                                                             │
│ 4. Alice ASSINA a chave ECDH com Ed25519:                   │
│    signature = sign(ecdhPublicKey, ed25519PrivateKey)      │
│    signature = [64 bytes únicos]                            │
│                                                             │
│ 5. Alice envia ao servidor:                                 │
│    {                                                        │
│      username: "Alice",                                     │
│      ecdhPublicKey: "04abc123...",  // Chave a ser verificada│
│      ed25519PublicKey: "302a30...", // Para verificar      │
│      signature: "a1b2c3d4..."       // Prova de autoria    │
│    }                                                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                      SERVIDOR                               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ ► Servidor apenas ROTEIA (não valida)                       │
│   Repassa credenciais para Bob                              │
│   Servidor é "cego" para validação Ed25519                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    LADO DO BOB                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ 1. Bob recebe credenciais de Alice:                         │
│    ecdhPublicKey, ed25519PublicKey, signature              │
│                                                             │
│ 2. Bob VERIFICA a assinatura:                               │
│    isValid = verify(                                        │
│      ecdhPublicKey,        // Dados que foram assinados    │
│      signature,             // Assinatura a verificar      │
│      ed25519PublicKey       // Chave pública de Alice      │
│    )                                                        │
│                                                             │
│ 3. Se isValid = TRUE:                                       │
│    ✓ A chave ECDH FOI criada por Alice                      │
│    ✓ A chave ECDH NÃO foi modificada no caminho            │
│    ✓ Bob pode confiar na chave ECDH                         │
│    ✓ Prossegue com TOFU                                     │
│                                                             │
│ 4. Se isValid = FALSE:                                      │
│    ❌ Assinatura inválida                                    │
│    ❌ Possível ataque MITM ou adulteração                    │
│    ❌ REJEITA tudo e não prossegue                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛡️ TOFU - Trust On First Use

### O que é TOFU?

**TOFU** (Trust On First Use) é uma estratégia de segurança inspirada no SSH:

**Princípio**: 
- **"Confie na primeira vez, desconfie de mudanças"**

**Como funciona**:
1. **Primeira vez** que você fala com alguém → Armazena a "impressão digital" (fingerprint) da identidade
2. **Próximas vezes** → Verifica se a impressão digital é a mesma
3. **Se mudou** → Alerta de possível ataque ou reinstalação

### Fluxo TOFU

```
┌─────────────────────────────────────────────────────────────┐
│                    PRIMEIRO CONTATO                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ Bob nunca falou com Alice antes                             │
│                                                             │
│ 1. Bob recebe ed25519PublicKey de Alice                     │
│                                                             │
│ 2. Bob calcula FINGERPRINT:                                 │
│    fingerprint = SHA-256(ed25519PublicKey)                  │
│    fingerprint = "a1b2c3d4e5f6789abcdef..." (64 chars hex) │
│                                                             │
│ 3. Bob verifica arquivo pinned_keys_Bob.json:               │
│    Alice está lá? ❌ NÃO                                     │
│                                                             │
│ 4. Bob ARMAZENA fingerprint (TOFU):                         │
│    Arquivo: pinned_keys_Bob.json                            │
│    {                                                        │
│      "Alice": {                                             │
│        "publicKey": "302a3005...a1b2c3d4",                  │
│        "pinnedAt": "2025-11-24T15:30:00.000Z"               │
│      }                                                      │
│    }                                                        │
│                                                             │
│ 5. Bob exibe alerta TOFU ao usuário:                        │
│    ┌─────────────────────────────────────────────────────┐ │
│    │   🔔 PRIMEIRA CONEXÃO COM Alice                      │ │
│    ├─────────────────────────────────────────────────────┤ │
│    │                                                      │ │
│    │ Trust On First Use (TOFU) - Identidade registrada   │ │
│    │                                                      │ │
│    │ Fingerprint: a1b2c3d4e5f6789abcdef...               │ │
│    │                                                      │ │
│    │ Esta identidade será verificada em futuros contatos.│ │
│    │ Se mudar, será emitido um alerta de segurança.      │ │
│    │                                                      │ │
│    └─────────────────────────────────────────────────────┘ │
│                                                             │
│ 6. Bob pensa: "OK, ESSA é a Alice. Vou lembrar."           │
│                                                             │
│ ✓ Primeira conexão aceita e identidade armazenada           │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                  CONTATOS FUTUROS (Normal)                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ Bob fala com Alice novamente (semana seguinte)              │
│                                                             │
│ 1. Bob recebe ed25519PublicKey de Alice                     │
│                                                             │
│ 2. Bob calcula fingerprint:                                 │
│    fingerprint_atual = SHA-256(ed25519PublicKey)            │
│    fingerprint_atual = "a1b2c3d4e5f6..." (mesmo)            │
│                                                             │
│ 3. Bob busca em pinned_keys_Bob.json:                       │
│    Alice está lá? ✓ SIM                                     │
│    fingerprint_armazenado = "a1b2c3d4e5f6..."               │
│                                                             │
│ 4. Bob compara:                                             │
│    fingerprint_atual == fingerprint_armazenado?             │
│    ✓ SIM → "É a mesma Alice que conheço!"                   │
│                                                             │
│ 5. Bob aceita conexão sem alertas                           │
│                                                             │
│ ✓ Identidade validada, conexão estabelecida                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│               CONTATOS FUTUROS (⚠️ ALERTA!)                 │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ Bob fala com Alice, mas CHAVE MUDOU                         │
│                                                             │
│ 1. Bob recebe ed25519PublicKey de Alice                     │
│                                                             │
│ 2. Bob calcula fingerprint:                                 │
│    fingerprint_atual = SHA-256(ed25519PublicKey)            │
│    fingerprint_atual = "x9y8z7w6v5u4..." (DIFERENTE!)       │
│                                                             │
│ 3. Bob busca em pinned_keys_Bob.json:                       │
│    Alice está lá? ✓ SIM                                     │
│    fingerprint_armazenado = "a1b2c3d4e5f6..." (antigo)      │
│                                                             │
│ 4. Bob compara:                                             │
│    fingerprint_atual == fingerprint_armazenado?             │
│    ❌ NÃO → "⚠️ ALERTA! Identidade mudou!"                   │
│                                                             │
│ 5. Bob exibe aviso ao usuário:                              │
│    ┌─────────────────────────────────────────────────────┐ │
│    │   ⚠️  ALERTA DE SEGURANÇA - IDENTIDADE MUDOU        │ │
│    ├─────────────────────────────────────────────────────┤ │
│    │                                                      │ │
│    │ Usuário: Alice                                       │ │
│    │                                                      │ │
│    │ Fingerprint Esperado (armazenado):                   │ │
│    │   a1b2c3d4e5f6...                                    │ │
│    │                                                      │ │
│    │ Fingerprint Recebido (novo):                         │ │
│    │   x9y8z7w6v5u4...                                    │ │
│    │                                                      │ │
│    │ Possíveis causas:                                    │ │
│    │   • Ataque Man-in-the-Middle (MITM)                  │ │
│    │   • Alice reinstalou o sistema                       │ │
│    │   • Alice deletou arquivo ed25519_keypair            │ │
│    │                                                      │ │
│    │ ❌ CONEXÃO REJEITADA POR SEGURANÇA                   │ │
│    │                                                      │ │
│    └─────────────────────────────────────────────────────┘ │
│                                                             │
│ 6. Sistema automaticamente REJEITA a conexão               │
│    (não há opção de aceitar por segurança)                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔗 Interação Ed25519 + TOFU

### Como Trabalham Juntos

Ed25519 e TOFU formam uma **dupla camada de segurança**:

```
┌─────────────────────────────────────────────────────────────┐
│                   CAMADA 1: Ed25519                         │
│              (Autentica Chaves Efêmeras)                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ Garante que:                                                │
│ ✓ Chave ECDH foi criada por quem tem ed25519PrivateKey     │
│ ✓ Chave ECDH não foi adulterada no caminho                 │
│ ✓ Servidor não pode forjar chaves em nome de Alice         │
│                                                             │
│ MAS NÃO garante:                                            │
│ ❌ Que ed25519PublicKey pertence realmente a Alice          │
│ ❌ Que não é um atacante com novo par Ed25519               │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                     CAMADA 2: TOFU                          │
│              (Autentica Identidade Persistente)             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ Garante que:                                                │
│ ✓ ed25519PublicKey é a MESMA de encontros anteriores       │
│ ✓ Detecta mudança de identidade entre sessões              │
│ ✓ Alerta se alguém tentar usar novo par Ed25519            │
│                                                             │
│ MAS NÃO garante:                                            │
│ ❌ Autenticidade do primeiro encontro (precisa confiar)     │
│ ❌ Que chaves efêmeras são autênticas (precisa Ed25519)     │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│               CAMADA 1 + 2: PROTEÇÃO COMPLETA               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ Ed25519 + TOFU juntos garantem:                             │
│ ✓ Autenticação de chaves efêmeras (Ed25519)                │
│ ✓ Consistência de identidade (TOFU)                        │
│ ✓ Detecção de MITM (ambos)                                 │
│ ✓ Detecção de falsificação (ambos)                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Fluxo Integrado

```
Alice conecta
│
├─ 1. Carrega ed25519_keypair_Alice.json (identidade persistente)
│   └─ Se não existir, gera e salva
│
├─ 2. Gera par ECDH efêmero (chave de sessão)
│   └─ Novo a cada conexão
│
├─ 3. ASSINA chave ECDH com Ed25519
│   └─ signature = sign(ecdhPub, ed25519Priv)
│
└─ 4. Envia credenciais
    {
      ecdhPublicKey: "04abc...",
      ed25519PublicKey: "302a...",
      signature: "a1b2..."
    }

Bob recebe credenciais
│
├─ 5. VERIFICA assinatura Ed25519 (Camada 1)
│   ├─ valid = verify(ecdhPub, signature, ed25519Pub)
│   └─ Se FALSO → REJEITA (possível adulteração)
│
├─ 6. VALIDA TOFU (Camada 2)
│   ├─ Calcula fingerprint = SHA-256(ed25519Pub)
│   ├─ Busca Alice em pinned_keys_Bob.json
│   │
│   ├─ CASO A: Primeira vez
│   │   └─ Armazena fingerprint (TOFU)
│   │
│   ├─ CASO B: Fingerprint bate
│   │   └─ "É a mesma Alice" → Aceita
│   │
│   └─ CASO C: Fingerprint mudou
│       └─ ALERTA → Pede confirmação
│
└─ 7. Se passou ambas as camadas:
    └─ Deriva chave compartilhada com ecdhPub
```

---

## 💾 Armazenamento no Sistema

### Onde as Chaves São Armazenadas

```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENTE (Alice)                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  📁 DISCO (Persistente - Sobrevive a reinicializações)      │
│  ─────────────────────────────────────────────────────────  │
│                                                             │
│  📄 ed25519_keypair_Alice.json                              │
│  Localização: client/.keys/ed25519_keypair_Alice.json        │
│  Conteúdo:                                                  │
│  {                                                          │
│    "publicKey": "302a300506032b6570032100a1b2c3...",       │
│    "privateKey": "302e020100300506032b657004220420x9y8..." │
│  }                                                          │
│  Tamanho: ~128 bytes                                        │
│  Criado: Primeira conexão (uma vez)                         │
│  Usado: Toda conexão (sempre carregado)                     │
│  Propósito: IDENTIDADE de longo prazo                       │
│                                                             │
│  📄 pinned_keys_Alice.json                                  │
│  Localização: client/.keys/pinned_keys_Alice.json            │
│  Conteúdo:                                                  │
│  {                                                          │
│    "Bob": {                                                 │
│      "publicKey": "302a300506032b6570032100...",            │
│      "pinnedAt": "2025-11-24T15:30:00.000Z"                 │
│    },                                                       │
│    "Charlie": {                                             │
│      "publicKey": "302a300506032b6570032100...",            │
│      "pinnedAt": "2025-11-24T16:45:00.000Z"                 │
│    }                                                        │
│  }                                                          │
│  Tamanho: ~200 bytes por usuário                            │
│  Criado: Primeira vez que Alice fala com cada pessoa       │
│  Atualizado: Quando Alice aceita mudança de fingerprint    │
│  Propósito: TOFU - Detectar mudanças de identidade         │
│                                                             │
│  ─────────────────────────────────────────────────────────  │
│                                                             │
│  💾 RAM (Efêmero - Perdido ao desconectar)                  │
│  ─────────────────────────────────────────────────────────  │
│                                                             │
│  Objeto WebSocketClient em memória:                        │
│  {                                                          │
│    privateKey: Buffer<32 bytes>,   // ECDH privada (efêmera)│
│    publicKey: Buffer<65 bytes>,    // ECDH pública (efêmera)│
│    sharedKeys: Map {               // Chaves derivadas     │
│      'Bob' => Buffer<16 bytes>,    // encKey para Bob      │
│      'test:Charlie' => Buffer<16>  // encKey grupo "test"  │
│    },                                                       │
│    processedKeys: Set {            // Cache anti-loop      │
│      'Bob:04abc123...',                                     │
│      'test:Charlie:04def456...'                             │
│    },                                                       │
│    groupKeys: Map {                // Chaves de grupo      │
│      'test' => Buffer<16 bytes>                             │
│    }                                                        │
│  }                                                          │
│                                                             │
│  Criado: A cada conexão                                     │
│  Descartado: Ao desconectar ou /quit                        │
│  Propósito: Chaves de SESSÃO (forward secrecy)             │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    SERVIDOR (Node.js)                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  💾 RAM (In-Memory - Não persiste)                          │
│  ─────────────────────────────────────────────────────────  │
│                                                             │
│  Map de usuários online:                                    │
│  users = Map {                                              │
│    'Alice' => User {                                        │
│      socketId: 'abc123xyz...',                              │
│      username: 'Alice',                                     │
│      publicKey: '04abc123...',        // ECDH pública       │
│      ed25519PublicKey: '302a30...',   // Ed25519 pública   │
│      signature: 'a1b2c3d4...'         // Assinatura ECDH   │
│    },                                                       │
│    'Bob' => User { ... }                                    │
│  }                                                          │
│                                                             │
│  Map de grupos:                                             │
│  groups = Map {                                             │
│    'Redes' => Group {                                       │
│      creator: 'João',                                       │
│      members: Set { 'João', 'Jose', 'Aline' },             │
│      memberKeys: Map {                                      │
│        'João:Jose' => true,                                 │
│        'João:Aline' => true,                                │
│        'Jose:Aline' => true                                 │
│      }                                                      │
│    }                                                        │
│  }                                                          │
│                                                             │
│  ⚠️  SERVIDOR NÃO ARMAZENA:                                 │
│  ❌ Chaves privadas Ed25519 (nunca saem do cliente)         │
│  ❌ Chaves privadas ECDH (nunca saem do cliente)            │
│  ❌ Chaves compartilhadas (sharedKeys)                       │
│  ❌ Chaves de grupo (groupKeys)                              │
│  ❌ Fingerprints TOFU                                        │
│                                                             │
│  Servidor apenas:                                           │
│  ✓ Roteia credenciais públicas                              │
│  ✓ Controla membros de grupos                               │
│  ✓ Roteia envelopes criptografados                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Ciclo de Vida dos Arquivos

```
┌─────────────────────────────────────────────────────────────┐
│ ed25519_keypair_Alice.json                                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ ► Primeira Conexão:                                         │
│   ├─ Verifica se arquivo existe                             │
│   ├─ ❌ NÃO → Gera novo par Ed25519                         │
│   ├─ Salva no disco                                         │
│   └─ ✓ Identidade criada                                    │
│                                                             │
│ ► Conexões Seguintes:                                       │
│   ├─ Verifica se arquivo existe                             │
│   ├─ ✓ SIM → Carrega do disco                              │
│   └─ ✓ Mesma identidade                                     │
│                                                             │
│ ► Ao Desconectar:                                           │
│   └─ Arquivo PERMANECE no disco                             │
│                                                             │
│ ► Se Deletar Arquivo:                                       │
│   ├─ Próxima conexão gera NOVO par                          │
│   ├─ NOVA identidade                                        │
│   └─ ⚠️ TOFU de outros detectará mudança                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ pinned_keys_Alice.json                                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ ► Primeira Conversa com Bob:                                │
│   ├─ Alice recebe ed25519PublicKey de Bob                   │
│   ├─ Calcula fingerprint                                    │
│   ├─ Verifica arquivo: Bob está? ❌ NÃO                     │
│   ├─ Adiciona Bob ao arquivo                                │
│   └─ ✓ TOFU aplicado                                        │
│                                                             │
│ ► Conversas Seguintes com Bob:                              │
│   ├─ Alice recebe ed25519PublicKey de Bob                   │
│   ├─ Calcula fingerprint                                    │
│   ├─ Verifica arquivo: Bob está? ✓ SIM                      │
│   ├─ Compara fingerprints                                   │
│   ├─ ✓ Igual → Aceita                                       │
│   └─ ❌ Diferente → Alerta                                   │
│                                                             │
│ ► Ao Desconectar:                                           │
│   └─ Arquivo PERMANECE no disco                             │
│                                                             │
│ ► Se Deletar Arquivo:                                       │
│   ├─ TOFU é resetado                                        │
│   └─ Próximas conversas = primeira vez                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Código de Implementação

#### Gerando/Carregando Ed25519

```javascript
// client/crypto/ed25519-tofu.js

function ensureEd25519Keypair(username, debugMode) {
  const filepath = `client/.keys/ed25519_keypair_${username}.json`;
  
  // 1. Tentar carregar do disco
  if (fs.existsSync(filepath)) {
    const data = JSON.parse(fs.readFileSync(filepath, 'utf8'));
    
    if (debugMode) {
      const fingerprint = calculateFingerprint(data.publicKey);
      console.log('✓ Par Ed25519 carregado');
      console.log(`  Fingerprint: ${fingerprint.substring(0, 16)}...`);
    }
    
    return {
      publicKey: crypto.createPublicKey({
        key: Buffer.from(data.publicKey, 'hex'),
        format: 'der',
        type: 'spki'
      }),
      privateKey: crypto.createPrivateKey({
        key: Buffer.from(data.privateKey, 'hex'),
        format: 'der',
        type: 'pkcs8'
      })
    };
  }
  
  // 2. Se não existe, gerar novo par
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  
  // 3. Salvar no disco
  fs.writeFileSync(filepath, JSON.stringify({
    publicKey: publicKey.export({ format: 'der', type: 'spki' }).toString('hex'),
    privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex')
  }, null, 2));
  
  if (debugMode) {
    console.log('✓ Novo par Ed25519 gerado e salvo');
  }
  
  return { publicKey, privateKey };
}
```

#### Aplicando TOFU

```javascript
// client/crypto/ed25519-tofu.js

function verifyAndPinPeer(peerName, ed25519Pub, ecdhPub, signature, debugMode) {
  // 1. Verificar assinatura Ed25519
  const isValid = crypto.verify(
    null,
    Buffer.from(ecdhPub, 'hex'),
    ed25519Pub,
    Buffer.from(signature, 'hex')
  );
  
  if (!isValid) {
    throw new Error('Assinatura Ed25519 inválida!');
  }
  
  // 2. Calcular fingerprint
  const fingerprint = calculateFingerprint(ed25519Pub);
  
  // 3. Carregar TOFU store
  const tofuFile = getTofuStore(username);
  let pinnedKeys = {};
  
  if (fs.existsSync(tofuFile)) {
    pinnedKeys = JSON.parse(fs.readFileSync(tofuFile, 'utf8'));
  }
  
  // 4. Verificar TOFU
  if (pinnedKeys[peerName]) {
    // Já conhecemos essa pessoa
    const storedFingerprint = calculateFingerprint(pinnedKeys[peerName].publicKey);
    
    if (storedFingerprint !== fingerprint) {
      // ALERTA: Fingerprint mudou!
      throw new Error(
        `⚠️ TOFU ALERTA: Fingerprint de ${peerName} mudou!\n` +
        `Esperado: ${storedFingerprint}\n` +
        `Recebido: ${fingerprint}\n` +
        `Possível MITM ou ${peerName} reinstalou sistema.`
      );
    }
    
    if (debugMode) {
      console.log(`✓ TOFU validado: ${peerName} reconhecido`);
    }
  } else {
    // Primeira vez - aplicar TOFU
    pinnedKeys[peerName] = {
      publicKey: ed25519Pub,
      pinnedAt: new Date().toISOString()
    };
    
    fs.writeFileSync(tofuFile, JSON.stringify(pinnedKeys, null, 2));
    
    if (debugMode) {
      console.log(`✓ TOFU aplicado: ${peerName} armazenado`);
      console.log(`  Fingerprint: ${fingerprint.substring(0, 16)}...`);
    }
  }
  
  return true;
}
```

---

## 📍 Fases de Uso

### FASE 1: Estabelecimento de Confiança (Uma vez por sessão)

**Quando acontece:**
- Alice conecta ao servidor
- Alice inicia chat com Bob (`/chat Bob`)
- Alice entra em grupo (`/group Redes`)

**O que é enviado:**

```javascript
{
  username: "Alice",
  ecdhPublicKey: "04abc123...",      // 130 chars (65 bytes)
  ed25519PublicKey: "302a30...",     // 64 chars (32 bytes)
  signature: "a1b2c3d4..."           // 128 chars (64 bytes)
}

Total: ~322 bytes de overhead
```

**O que acontece:**

1. **Bob verifica assinatura Ed25519**
   - Valida que `ecdhPublicKey` foi criada por Alice
   - Se falhar → REJEITA

2. **Bob aplica TOFU**
   - Calcula fingerprint de `ed25519PublicKey`
   - Compara com fingerprint armazenado
   - Se mudou → ALERTA

3. **Bob deriva chave compartilhada**
   - `sharedSecret = ECDH(Bob.priv, Alice.ecdhPub)`
   - `encKey = HKDF(sharedSecret)`
   - Armazena em RAM

**Frequência:** 
- UMA VEZ por sessão
- UMA VEZ por par de usuários em grupo

---

### FASE 2: Troca de Mensagens (Usa confiança já estabelecida)

**Quando acontece:**
- Alice envia mensagem para Bob
- Alice envia mensagem em grupo

**O que é enviado:**

```javascript
{
  v: 1,                              // Versão envelope
  ts: 1732492800000,                 // Timestamp
  from: "Alice",                     // Remetente
  to: "Bob",                         // Destinatário
  isGroup: false,                    // Chat 1:1 ou grupo
  nonce: "x1y2z3...",                // 24 chars (12 bytes)
  ct: "8f3e4d...",                   // Variável (mensagem cifrada)
  tag: "9a8b7c..."                   // 32 chars (16 bytes)
}

Total: ~150 bytes + tamanho da mensagem
```

**O que acontece:**

1. **Bob busca `encKey` em RAM**
   - Já foi estabelecida na Fase 1
   - Não precisa recomputar

2. **Bob valida tag GCM**
   - Autentica `ct` + metadados (AAD)
   - Se falhar → REJEITA (mensagem adulterada)

3. **Bob descriptografa**
   - `plaintext = decrypt(ct, encKey, nonce)`
   - Exibe mensagem

**Frequência:**
- A CADA MENSAGEM enviada
- Overhead: ~150 bytes fixos + mensagem

---

### Comparação de Overhead

```
┌─────────────────────────────────────────────────────────────┐
│ ❌ SE ENVIASSE CREDENCIAIS A CADA MENSAGEM (Hipotético)     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ Mensagem 1: "Oi"                                            │
│ ├─ Credenciais: 322 bytes                                   │
│ ├─ Envelope: 150 bytes                                      │
│ └─ Total: 472 bytes                                         │
│                                                             │
│ Mensagem 2: "Tudo bem?"                                     │
│ ├─ Credenciais: 322 bytes                                   │
│ ├─ Envelope: 150 bytes                                      │
│ └─ Total: 472 bytes                                         │
│                                                             │
│ 100 mensagens:                                              │
│ └─ 47,200 bytes (~46 KB de overhead!)                       │
│                                                             │
│ ❌ Problemas:                                                │
│ • Overhead enorme                                           │
│ • Verificação Ed25519 repetida (lenta)                     │
│ • Tráfego de rede desnecessário                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ ✅ COMO REALMENTE FUNCIONA (Eficiente)                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ Fase 1 (Uma vez):                                           │
│ └─ Credenciais: 322 bytes                                   │
│                                                             │
│ Fase 2 (100 mensagens):                                     │
│ ├─ Envelope 1: 150 bytes                                    │
│ ├─ Envelope 2: 150 bytes                                    │
│ └─ ... (100x)                                               │
│                                                             │
│ Total:                                                      │
│ └─ 322 + (100 × 150) = 15,322 bytes (~15 KB)               │
│                                                             │
│ ✅ Vantagens:                                                │
│ • 67% menos overhead (46 KB → 15 KB)                        │
│ • Ed25519 verificada UMA VEZ                                │
│ • Tráfego otimizado                                         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🤝 Por que Precisamos de Ambos?

### Ed25519 SEM TOFU

```
❌ Problema: Não detecta troca de identidade

Cenário:
1. Alice conecta → ed25519Pub1 → Bob verifica assinatura ✓
2. Alice desconecta
3. Alice reinstala sistema → NOVO ed25519Pub2
4. Alice conecta → ed25519Pub2 → Bob verifica assinatura ✓

Bob não percebe que é uma IDENTIDADE DIFERENTE!

Atacante poderia:
• Gerar novo par Ed25519
• Assinar suas próprias chaves ECDH
• Se passar por Alice
• Bob aceitaria (assinatura válida)
```

### TOFU SEM Ed25519

```
❌ Problema: Não autentica chaves efêmeras

Cenário:
1. Alice → ecdhPub1 → Bob armazena fingerprint(ecdhPub1)
2. MITM intercepta comunicação
3. MITM troca ecdhPub1 por ecdhPub2
4. Bob compara fingerprint... mas de QUÊ?

Sem Ed25519:
• Não há como provar quem criou ecdhPub
• MITM pode trocar chaves livremente
• TOFU não ajuda (não há identidade para validar)
```

### Ed25519 + TOFU (Juntos) ✅

```
✅ Solução completa:

1. Ed25519 PROVA que chave ECDH foi criada por Alice
   └─ Assinatura valida autenticidade da chave efêmera

2. TOFU DETECTA se Alice trocou sua identidade Ed25519
   └─ Fingerprint valida consistência da identidade

3. Juntos: Autenticidade + Persistência
   └─ MITM não pode trocar chaves (Ed25519 detecta)
   └─ MITM não pode trocar identidade (TOFU detecta)
```

---

## 🎭 Cenário de Ataque: MITM

### Sem Ed25519 + TOFU

```
Alice                MITM                Bob
  │                    │                  │
  ├─ecdhPub_Alice─────>│                  │
  │                    │                  │
  │                    ├─ecdhPub_MITM───>│
  │                    │                  │
  │                    │  Bob aceita!     │
  │                    │  (não tem como   │
  │                    │   verificar)     │
  │                    │                  │
  │<──ecdhPub_MITM─────┤                  │
  │                    │<─ecdhPub_Bob─────┤
  │                    │                  │
  │ Alice aceita!      │  Bob aceita!     │
  │ (não detecta MITM) │  (não detecta)   │
  │                    │                  │
  │─encrypt(msg)──────>│                  │
  │                    │─decrypt(msg)     │
  │                    │ Lê mensagem!     │
  │                    │─encrypt(msg)────>│
  │                    │                  │
  │                 ATAQUE SUCESSO!       │
  │            MITM lê todas mensagens    │
```

### Com Ed25519 (Sem TOFU)

```
Alice                MITM                Bob
  │                    │                  │
  ├─{ecdhPub_Alice,───>│                  │
  │  ed25519Pub_Alice, │                  │
  │  sig_Alice}        │                  │
  │                    │                  │
  │                    │ MITM gera novo   │
  │                    │ par Ed25519      │
  │                    │                  │
  │                    ├─{ecdhPub_MITM,──>│
  │                    │  ed25519Pub_MITM,│
  │                    │  sig_MITM}       │
  │                    │                  │
  │                    │  Bob verifica:   │
  │                    │  1. Assinatura ✓ │
  │                    │  2. TOFU? Não tem│
  │                    │  3. Aceita!      │
  │                    │                  │
  │                 ATAQUE SUCESSO!       │
  │   (Bob não sabe que não é Alice real) │
```

### Com Ed25519 + TOFU (Proteção Completa) ✅

```
Alice                MITM                Bob
  │                    │                  │
  │ ─ PRIMEIRA VEZ ─                     │
  ├─{ecdhPub_Alice,───>│                  │
  │  ed25519Pub_Alice, │                  │
  │  sig_Alice}        │                  │
  │                    │                  │
  │                    ├─(repassa)───────>│
  │                    │                  │
  │                    │  Bob:            │
  │                    │  1. Verifica sig ✓│
  │                    │  2. TOFU: 1ª vez │
  │                    │  3. Armazena fp  │
  │                    │  4. Aceita       │
  │                    │                  │
  │ ─ SEGUNDA VEZ (MITM tenta atacar) ─  │
  ├─{ecdhPub_Alice,───>│                  │
  │  ed25519Pub_Alice, │                  │
  │  sig_Alice}        │                  │
  │                    │                  │
  │                    │ MITM tenta trocar│
  │                    │ por suas credenc.│
  │                    │                  │
  │                    ├─{ecdhPub_MITM,──>│
  │                    │  ed25519Pub_MITM,│
  │                    │  sig_MITM}       │
  │                    │                  │
  │                    │  Bob:            │
  │                    │  1. Verifica sig ✓│
  │                    │  2. Calcula fp   │
  │                    │  3. Compara TOFU │
  │                    │  ❌ DIFERENTE!    │
  │                    │  ⚠️  ALERTA MITM! │
  │                    │  ❌ REJEITA       │
  │                    │                  │
  │                 ATAQUE BLOQUEADO!     │
  │          TOFU detectou mudança de id  │
```

---

## 📊 Comparação de Eficiência

### Tempo de Processamento

```
┌─────────────────────────────────────────────────────────────┐
│ FASE 1: Estabelecimento (Uma vez)                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ Ed25519 verify:        ~0.1 ms                              │
│ SHA-256 (fingerprint): ~0.05 ms                             │
│ ECDH compute:          ~0.5 ms                              │
│ HKDF derivation:       ~0.2 ms                              │
│ Arquivo I/O (TOFU):    ~1.0 ms                              │
│ ──────────────────────────────────────                      │
│ TOTAL:                 ~1.85 ms                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ FASE 2: Cada Mensagem                                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ AES-GCM encrypt:       ~0.05 ms                             │
│ AES-GCM decrypt:       ~0.05 ms                             │
│ GCM tag verify:        ~0.01 ms                             │
│ ──────────────────────────────────────                      │
│ TOTAL:                 ~0.11 ms                             │
│                                                             │
│ ✓ ~17x mais rápido que Fase 1                               │
│ ✓ Não precisa Ed25519 verify repetida                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘

Performance em 100 mensagens:
• COM Ed25519 toda vez: 1.85ms × 100 = 185 ms
• SEM Ed25519 (após Fase 1): 1.85ms + (0.11ms × 100) = 12.85 ms
• Ganho: 93% mais rápido! ⚡
```

---

## 💡 Resumo Final

### Camada 1: Ed25519 (Assinatura Digital)

**Chave Privada:**
- Mantida em segredo absoluto
- Armazenada em: `ed25519_keypair_${username}.json`
- Usada para: ASSINAR chaves ECDH efêmeras
- Prova: "Eu, Alice, criei essa chave ECDH"

**Chave Pública:**
- Compartilhada livremente
- Enviada para: Servidor e outros usuários
- Usada para: VERIFICAR assinaturas
- Valida: "Essa chave ECDH foi criada por Alice"

### Camada 2: TOFU (Trust On First Use)

**Primeira Vez:**
- Armazena fingerprint da chave pública Ed25519
- Salva em: `pinned_keys_${username}.json`
- Pensa: "Agora conheço Alice com essa identidade"

**Próximas Vezes:**
- Compara fingerprint atual com armazenado
- Se igual: "É a mesma Alice" → Aceita
- Se diferente: "Identidade mudou!" → Alerta de MITM

### Juntos (Ed25519 + TOFU)

**Proteção Dupla:**
1. **Ed25519**: Autentica chaves ECDH efêmeras a cada sessão
2. **TOFU**: Garante consistência de identidade entre sessões
3. **Resultado**: Detecta MITM + Troca de identidade + Forward secrecy

### Analogia Final

- **Ed25519**: Carteira de identidade (prova quem você é)
- **TOFU**: Memória de Bob ("Eu lembro do seu rosto")
- **Fase 1**: Mostrar identidade ao entrar
- **Fase 2**: Conversar sem mostrar identidade toda vez
- **Juntos**: Segurança + Eficiência

---

## 🎯 Quando Cada Camada É Usada

```
┌─────────────────────────────────────────────────────────────┐
│ CONEXÃO / INÍCIO DE CHAT                                    │
├─────────────────────────────────────────────────────────────┤
│ ✓ Ed25519: Assina chave ECDH                                │
│ ✓ Ed25519: Verifica assinatura                              │
│ ✓ TOFU: Armazena/valida fingerprint                         │
│ ✓ ECDH: Deriva chave compartilhada                          │
│ ✓ HKDF: Deriva encKey                                       │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ TROCA DE MENSAGENS                                          │
├─────────────────────────────────────────────────────────────┤
│ ❌ Ed25519: NÃO usado (já validado na conexão)              │
│ ❌ TOFU: NÃO usado (já validado na conexão)                 │
│ ✓ GCM: Valida tag de autenticação                           │
│ ✓ AES: Criptografa/descriptografa                           │
│ ✓ encKey: Usa chave pré-estabelecida                        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ RECONEXÃO                                                   │
├─────────────────────────────────────────────────────────────┤
│ ✓ Ed25519: Carrega MESMA identidade do disco                │
│ ✓ ECDH: Gera NOVO par efêmero                               │
│ ✓ Ed25519: Assina NOVA chave ECDH                           │
│ ✓ TOFU: Valida que identidade não mudou                     │
│ ✓ HKDF: Deriva NOVA encKey                                  │
└─────────────────────────────────────────────────────────────┘
```

---

## 📚 Referências

- **Ed25519**: [RFC 8032](https://tools.ietf.org/html/rfc8032)
- **Curve25519**: [RFC 7748](https://tools.ietf.org/html/rfc7748)
- **TOFU**: Inspirado em SSH known_hosts
- **Signal Protocol**: Usa conceitos similares de identidade persistente
- **HKDF**: [RFC 5869](https://tools.ietf.org/html/rfc5869)

---

## 🔬 Testes Sugeridos

### Teste 1: TOFU Primeira Vez

```
1. Deletar pinned_keys_Alice.json
2. Alice conecta
3. Alice fala com Bob (/chat Bob)
4. Verificar que pinned_keys_Alice.json foi criado
5. Verificar que contém fingerprint de Bob
```

### Teste 2: TOFU Validação

```
1. Alice fala com Bob (TOFU armazena)
2. Bob desconecta
3. Alice desconecta
4. Ambos reconectam
5. Alice fala com Bob novamente
6. Debug deve mostrar "TOFU validado" (sem alerta)
```

### Teste 3: TOFU Detecção de Mudança

```
1. Alice fala com Bob (TOFU armazena)
2. Bob desconecta
3. Bob deleta ed25519_keypair_Bob.json
4. Bob reconecta (novo Ed25519 gerado)
5. Alice tenta falar com Bob
6. Sistema deve ALERTAR mudança de fingerprint
```

### Teste 4: Performance

```
1. Alice conecta com debug
2. Medir tempo da Fase 1 (primeiro /chat Bob)
3. Enviar 100 mensagens
4. Medir tempo médio por mensagem
5. Verificar que mensagens são ~10-20x mais rápidas que conexão
```
