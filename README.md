- **Criptografia IDEA**: Algoritmo de criptografia simétrica com chaves de 128 bits derivadas via HKDF
- **Troca de Chaves ECDH**: Implementação manual educativa com curva secp256k1, autenticada por assinatura Ed25519
- **Autenticação de Chaves**: Assinatura digital Ed25519 + TOFU (Trust On First Use) para prevenir ataques MITM
- **Derivação de Chaves**: HKDF-SHA256 para gerar chaves de sessão a partir do segredo compartilhado ECDH
- **Integridade de Mensagens**: Envelope v1 com AES-128-GCM (AEAD) garantindo confidencialidade + autenticidade
- **Proteção contra Replay**: Validação de timestamp e nonce único em cada mensagem
- **Chat 1:1**: Conversas privadas criptografadas com autenticação mútua entre dois usuários
- **Chat em Grupo**: Conversas em grupo com chave compartilhada e re-key automático
- **Recriação de Secret Share**: Quando alguém sai do grupo, o secret share é automaticamente recriado para garantir segurança forward
- **Interface CLI**: Terminal interativo com comandos intuitivos
- **Arquitetura JavaScript Nativa**: Node.js completo, sem dependências externas
- **Modo Debug**: Análise detalhada do processo ECDH, envelope e chaves
- **End-to-End Encryption**: Chaves privadas ficam apenas no cliente, servidor apenas roteia mensagens criptografadas

## 🏗️ Arquitetura

```
┌─────────────────┐    ┌─────────────────┐
│   Cliente CLI   │    │  Servidor Node  │
│   (Terminal)    │◄──►│   (WebSocket)   │
└─────────────────┘    └─────────────────┘
         │                       │
         │                       │
    ┌────▼────┐            ┌─────▼─────┐
    │  ECDH   │            │  Gerenci. │
    │ Manual  │            │ Usuários  │
    └─────────┘            │  + IDEA   │
                           │  (JS)     │
                           └───────────┘

message-idea/
├── server/                # Servidor Node.js
│   ├── src/
│   │   ├── crypto/        # Implementação IDEA + ECDH (JavaScript)
│   │   ├── models/        # Modelos de dados
│   │   └── websocket/     # Gerenciador WebSocket
│   └── server.js          # Servidor principal
├── client/                # Cliente CLI
│   ├── cli/              # Interface de linha de comando
│   └── shared/           # Código compartilhado
├── setup.sh              # Script de instalação
├── start-servers.sh      # Script para iniciar apenas o servidor
├── start-test.sh         # Script de automação (servidor + clientes)
└── README.md             # Este arquivo

## 🚀 Início Rápido

### Opção 1: Automação Completa (Recomendado)

O script `start-test.sh` inicia automaticamente o servidor e dois clientes (Alice e Bob) em terminais separados:

```bash
./start-test.sh
```

Este script:
- ✅ Inicia o servidor em um terminal separado
- ✅ Inicia o cliente Alice em outro terminal
- ✅ Inicia o cliente Bob em outro terminal
- ✅ Detecta automaticamente o gerenciador de terminais disponível (gnome-terminal, xterm, tmux, screen)
- ✅ Instala dependências automaticamente se necessário

### Opção 2: Início Manual

**Terminal 1 - Servidor:**
```bash
node server/server.js
```

**Terminal 2 - Cliente Alice:**
```bash
node client/cli/main.js --username Alice
```

**Terminal 3 - Cliente Bob:**
```bash
node client/cli/main.js --username Bob
```

### 2. Comandos Disponíveis

| Comando         | Descrição                |
| --------------- | ------------------------ |
| `/help`         | Mostra ajuda completa    |
| `/users`        | Lista usuários online    |
| `/chat <user>`  | Inicia chat 1:1          |
| `/group <nome>` | Cria/entra em grupo      |
| `/groups`       | Lista grupos disponíveis |
| `/leave`        | Sai do chat/grupo atual  |
| `/status`       | Status da conexão        |
| `/debug`        | Toggle modo debug ECDH   |
| `/quit`         | Sair do sistema          |

### 3. Exemplo de Uso

```bash
# Alice conecta
node client/cli/main.js --username Alice

# Bob conecta
node client/cli/main.js --username Bob

# Alice inicia chat com Bob
/chat Bob

# Bob aceita e troca chaves
# (Processo automático de ECDH)

# Ambos podem conversar com segurança
Olá Bob! Esta mensagem está criptografada com IDEA
Oi Alice! Recebi sua mensagem descriptografada
```

## 🔐 Fluxo de Segurança

### Chat 1:1

1. **Conexão**: Usuários se conectam ao servidor
2. **Geração de Chaves**: Cada usuário gera:
   - Par Ed25519 persistente (autenticação, armazenado em `client/cli/ed25519_keypair.json`)
   - Par ECDH efêmero (troca de chave, curva secp256k1)
3. **Assinatura**: Chave pública ECDH é assinada com chave privada Ed25519
4. **Troca de Chaves**: Chaves públicas ECDH + Ed25519 + assinatura são trocadas via servidor
5. **Verificação TOFU**: Cada cliente:
   - Verifica assinatura Ed25519 da chave ECDH recebida
   - Armazena fingerprint (hash SHA-256) da chave Ed25519 do peer (`client/cli/pinned_keys.json`)
   - Em conexões futuras, rejeita se fingerprint mudar (alerta de possível MITM)
6. **Chave Compartilhada**: Cada usuário calcula segredo compartilhado via ECDH
7. **Derivação HKDF**: Segredo é processado por HKDF-SHA256 gerando:
   - `encKey` (16 bytes para AES-128-GCM)
   - `authKey` (32 bytes reservado para uso futuro)
8. **Envelope de Mensagem**: Cada mensagem é encapsulada em estrutura v1:
   - `v`: Versão do protocolo (1)
   - `ts`: Timestamp (validação de janela de 5 minutos)
   - `from`: Remetente
   - `to`: Destinatário
   - `nonce`: Nonce único de 96 bits (GCM)
   - `ct`: Ciphertext (AES-128-GCM)
   - `tag`: Authentication tag (16 bytes, GCM)
9. **Criptografia**: Mensagens são criptografadas com IDEA (AES-128-GCM) usando `encKey`
10. **Validação na Recepção**: Destinatário:
    - Valida timestamp (janela aceitável)
    - Detecta replay (verifica nonce não repetido)
    - Verifica tag GCM (integridade + autenticidade)
    - Só então descriptografa

### Chat em Grupo

1. **Criação do Grupo**: Primeiro membro cria grupo
2. **Entrada de Membros**: Novos membros entram no grupo
3. **ECDH Múltiplo Autenticado**: Cada membro executa ECDH + verificação Ed25519 com todos os outros
4. **Chave de Grupo**: Criador gera chave aleatória de 16 bytes e distribui:
   - Para cada membro: cifra chave de grupo usando chave de sessão derivada (HKDF) daquele par
   - Envia envelope criptografado individual
5. **Criptografia**: Mensagens de grupo são criptografadas com chave de grupo usando envelope v1
6. **Saída de Membros**: Quando alguém sai do grupo:
   - Todas as chaves relacionadas ao membro que saiu são limpas
   - Chaves ECDH são reestabelecidas entre os membros restantes (com re-verificação Ed25519)
   - Nova chave de grupo é gerada e redistribuída
   - O membro que saiu não consegue mais descriptografar mensagens futuras (forward secrecy)

## 🔍 Modo Debug

Para análise detalhada do processo criptográfico (ECDH, Ed25519, envelopes):

```bash
# Conectar com modo debug
node client/cli/main.js --username Alice --debug

# Ou ativar durante uso
/debug
```

No modo debug você pode visualizar:
- Chaves públicas ECDH e Ed25519 trocadas
- Fingerprints TOFU estabelecidos
- Estrutura completa dos envelopes v1 (versão, timestamp, nonce, tag)
- Chaves de sessão derivadas via HKDF

## 🔒 Segurança End-to-End com Integridade

Este sistema implementa criptografia end-to-end verdadeira com garantias de integridade:

### Confidencialidade
- ✅ **Chaves privadas**: Ficam apenas no cliente, nunca são enviadas ao servidor
- ✅ **Chaves públicas**: Apenas chaves públicas são trocadas via servidor
- ✅ **Cálculo de chaves compartilhadas**: Feito localmente em cada cliente usando ECDH
- ✅ **Criptografia/Descriptografia**: Toda criptografia é feita no cliente usando IDEA (AES-128-GCM)
- ✅ **Servidor**: Apenas roteia envelopes já criptografados (não descriptografa)

### Integridade e Autenticidade
- ✅ **Assinatura de Chaves**: Chaves públicas ECDH assinadas com Ed25519 previnem substituição por MITM
- ✅ **TOFU Pinning**: Primeira chave Ed25519 de cada peer é armazenada; mudanças futuras são rejeitadas
- ✅ **Derivação Segura**: HKDF-SHA256 separa chaves de cifra e autenticação do segredo ECDH
- ✅ **Envelope AEAD**: AES-GCM fornece autenticação integrada (tag verifica integridade do ciphertext + metadados)
- ✅ **Proteção contra Replay**: Timestamp com janela de 5 minutos + nonce único detectam mensagens repetidas ou antigas
- ✅ **Validação Rigorosa**: Falha em qualquer verificação aborta descriptografia imediatamente

### Forward Secrecy
- ✅ **Chaves Efêmeras ECDH**: Regeneradas a cada sessão
- ✅ **Recriação de Secret Share**: Quando alguém sai do grupo, chaves são recriadas para impedir acesso futuro

### Arquivos de Persistência Local
- `client/cli/ed25519_keypair.json`: Par Ed25519 persistente (identidade de longo prazo)
- `client/cli/pinned_keys.json`: Fingerprints TOFU de peers conhecidos (detecção de mudança de chave)

## 🧪 Testando a Recriação do Secret Share

Para testar a funcionalidade de recriação do secret share quando alguém sai do grupo:

1. Inicie o sistema com `./start-test.sh`
2. No terminal da Alice, crie um grupo: `/group Equipe`
3. No terminal do Bob, entre no grupo: `/group Equipe`
4. Envie algumas mensagens no grupo
5. No terminal do Bob, saia do grupo: `/leave`
6. Observe que:
   - O servidor recria automaticamente as chaves entre os membros restantes
   - O Bob não consegue mais descriptografar mensagens futuras do grupo
   - As chaves antigas são limpas automaticamente

## 🛠️ Scripts Disponíveis

- **`setup.sh`**: Instala todas as dependências necessárias
- **`start-servers.sh`**: Inicia apenas o servidor
- **`start-test.sh`**: Inicia servidor + clientes em terminais separados (recomendado para testes)
- **`test-integrity.js`**: Teste automatizado das camadas de integridade (Ed25519, HKDF, envelope AEAD)

### Teste de Integridade

Para validar todas as camadas de segurança implementadas:

```bash
node test-integrity.js
```

Este teste valida:
- ✅ Geração e persistência de chaves Ed25519
- ✅ Assinatura digital de chaves ECDH
- ✅ Verificação TOFU e pinning
- ✅ Cálculo de segredo compartilhado via ECDH
- ✅ Derivação de chaves via HKDF-SHA256
- ✅ Criação de envelope v1 com AES-128-GCM
- ✅ Validação de integridade (detecção de adulteração)
- ✅ Proteção contra replay (timestamp + nonce)
