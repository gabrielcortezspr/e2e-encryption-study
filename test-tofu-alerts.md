# 🧪 Testes de Validação TOFU

## ✅ Confirmação: TOFU está implementado corretamente!

### Alertas Implementados:

1. **🔔 Primeira Conexão** - Aviso visual ao registrar nova identidade
2. **⚠️  Identidade Mudou** - Alerta crítico quando fingerprint não bate + rejeição automática

---

## 📋 Testes Práticos

### Teste 1: Primeira Conexão (Alerta TOFU)

**Objetivo**: Validar que o sistema exibe alerta ao conhecer uma nova identidade

```bash
# 1. Limpar histórico TOFU de Alice
rm client/cli/pinned_keys_Alice.json

# 2. Iniciar servidor
./start-test.sh

# 3. Em outro terminal, conectar Alice
./start-test.sh

# 4. Em outro terminal, conectar Bob
./start-test.sh

# 5. Alice inicia chat com Bob
/chat Bob
```

**Resultado Esperado**:
```
┌─────────────────────────────────────────────────────────────┐
│         🔔 PRIMEIRA CONEXÃO COM Bob                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ Trust On First Use (TOFU) - Identidade registrada          │
│                                                             │
│ Fingerprint: 6d1f3f3eb46a330806b21cf5e08a...               │
│                                                             │
│ Esta identidade será verificada em futuros contatos.       │
│ Se mudar, será emitido um alerta de segurança.             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Validação**:
- ✅ Arquivo `pinned_keys_Alice.json` foi criado
- ✅ Contém fingerprint de Bob
- ✅ Chat funciona normalmente

---

### Teste 2: Reconexão Normal (Sem Alerta)

**Objetivo**: Validar que reconexões não geram alertas

```bash
# 1. Bob desconecta (Ctrl+C)

# 2. Bob reconecta
./start-test.sh

# 3. Alice envia mensagem para Bob
Olá Bob!
```

**Resultado Esperado**:
```
✓ Identidade de Bob confirmada
[Bob]: Olá Bob!
```

**Validação**:
- ✅ Sem alertas visuais (identidade já conhecida)
- ✅ Mensagem enviada normalmente
- ✅ Log discreto: "✓ Identidade de Bob confirmada"

---

### Teste 3: Mudança de Identidade (⚠️ ALERTA CRÍTICO)

**Objetivo**: Validar detecção de mudança de fingerprint

```bash
# 1. Bob desconecta (Ctrl+C)

# 2. Bob deleta sua chave Ed25519 (simula reinstalação)
rm client/cli/ed25519_keypair_Bob.json

# 3. Bob reconecta (novo par Ed25519 será gerado)
./start-test.sh

# 4. Alice tenta falar com Bob
/chat Bob
```

**Resultado Esperado**:
```
┌─────────────────────────────────────────────────────────────┐
│         ⚠️  ALERTA DE SEGURANÇA - IDENTIDADE MUDOU         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ Usuário: Bob                                                │
│                                                             │
│ Fingerprint Esperado (armazenado):                          │
│   6d1f3f3eb46a330806b21cf5e08a...                           │
│                                                             │
│ Fingerprint Recebido (novo):                                │
│   x9y8z7w6v5u4t3s2r1q0p9o8...                               │
│                                                             │
│ Possíveis causas:                                           │
│   • Ataque Man-in-the-Middle (MITM)                         │
│   • Bob reinstalou o sistema                                │
│   • Bob deletou arquivo ed25519_keypair                     │
│                                                             │
│ ❌ CONEXÃO REJEITADA POR SEGURANÇA                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘

❌ Erro ao estabelecer chave compartilhada: TOFU: Identidade de Bob mudou!
```

**Validação**:
- ✅ Alerta visual crítico exibido
- ✅ Mostra ambos os fingerprints (esperado vs recebido)
- ✅ Conexão automaticamente rejeitada
- ✅ Chat não estabelecido (segurança garantida)

---

## 🔍 Como Verificar os Arquivos

### Ver fingerprints armazenados:
```bash
cat client/cli/pinned_keys_Alice.json
```

Saída esperada:
```json
{
  "Bob": {
    "fingerprint": "6d1f3f3eb46a330806b21cf5e08a86cc96b7966fdf1d6d533e552f42e714cffb",
    "ed25519PubHex": "302a300506032b65700321005682b7fd9815ecab00e2efe155bcd3537dcbe43aeef2425fa8614225135e5b77",
    "firstSeen": "2025-11-24T06:04:10.139Z"
  }
}
```

### Ver fingerprint da própria chave:
```bash
node -e "
const crypto = require('crypto');
const fs = require('fs');
const data = JSON.parse(fs.readFileSync('client/cli/ed25519_keypair_Bob.json', 'utf8'));
const fp = crypto.createHash('sha256').update(data.publicKey, 'hex').digest('hex');
console.log('Fingerprint de Bob:', fp);
"
```

---

## 📊 Resumo dos Comportamentos

| Situação | Alerta Visual | Comportamento |
|----------|---------------|---------------|
| **Primeira vez** | 🔔 TOFU | Aceita + Armazena fingerprint |
| **Reconexão normal** | Nenhum | Aceita (fingerprint bate) |
| **Identidade mudou** | ⚠️ CRÍTICO | Rejeita conexão |

---

## ✅ Confirmações Finais

### 1. TOFU detecta mudança de identidade? 
**✅ SIM** - Implementado em `verifyAndPinPeer()` com comparação de fingerprints

### 2. Exibe alerta quando fingerprint não bate?
**✅ SIM** - Alerta visual detalhado + exceção lançada + conexão rejeitada

### 3. Exibe alerta na primeira conexão?
**✅ SIM** - Alerta informativo visual ao registrar nova identidade TOFU

### 4. Código localizado em:
- `client/crypto/ed25519-tofu.js` - Função `verifyAndPinPeer()`
- Linhas ~107-145 (primeira conexão)
- Linhas ~147-172 (mudança detectada)

---

## 🎯 Próximos Passos

Para testar agora mesmo:
```bash
# Terminal 1 - Servidor
./start-test.sh

# Terminal 2 - Alice
./start-test.sh
# Digite: Alice

# Terminal 3 - Bob  
./start-test.sh
# Digite: Bob

# Em Alice, execute:
/chat Bob
# → Deve aparecer o alerta 🔔 PRIMEIRA CONEXÃO

# Desconecte Bob (Ctrl+C)
# Delete a chave: rm client/cli/ed25519_keypair_Bob.json
# Reconecte Bob
# Em Alice, execute: /chat Bob
# → Deve aparecer o alerta ⚠️ IDENTIDADE MUDOU
```
