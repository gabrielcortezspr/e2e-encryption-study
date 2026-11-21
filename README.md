# 🔐 Chat E2E no terminal: ECDH + Ed25519 + AES-GCM

Chat de terminal (Node.js) com **criptografia ponta a ponta**, feito como projeto
de estudo de criptografia aplicada. O servidor só faz **relay**: ele nunca vê
chaves privadas nem texto claro.

| Camada | O que usa | Onde está |
|---|---|---|
| Acordo de chaves | ECDH efêmero, curva secp256k1 | `client/crypto/ecdh-manual.js` |
| Autenticação das chaves | Assinatura Ed25519 + TOFU (*Trust On First Use*) | `client/crypto/ed25519-tofu.js` |
| Derivação de chaves | HKDF-SHA256 (RFC 5869) | `client/crypto/hkdf.js` |
| Cifra + integridade | AES-128-GCM (AEAD) em um "envelope v1" | `client/crypto/envelope.js` |
| Anti-replay | Janela de timestamp (5 min) + cache de nonces | `client/crypto/envelope.js` |
| Grupos | Chave aleatória do grupo distribuída por canais pairwise, com re-key quando alguém entra ou sai | `client/shared/websocket-client.js` |

> **Sobre o IDEA:** o projeto nasceu como "message-idea" e a ideia inicial era
> cifrar as mensagens com IDEA. A versão final usa **AES-128-GCM**. A
> implementação do IDEA ficou em [`experiments/idea/`](experiments/idea/) como
> material de estudo e é validada contra o vetor de teste oficial, mas o chat
> **não** a usa.

---

## 🚀 Como rodar

Requisitos: Node.js 18+.

```bash
npm run install:all        # instala dependências de server/ e client/
```

**Manual (um terminal para cada):**

```bash
npm run server                                   # servidor na porta 6666
node client/cli/main.js --username Alice
node client/cli/main.js --username Bob --debug   # --debug mostra cada etapa criptográfica
```

**Automático:** `./start-test.sh` (ou `./start-test.sh --debug`) abre o servidor e
3 clientes (Alice, Bob, Charlie) com gnome-terminal, xterm, tmux ou screen.

A porta e a URL ficam em [`config.env`](config.env) (`NODE_PORT`, `NODE_URL`).

### Comandos no cliente

| Comando | Descrição |
|---|---|
| `/users` | Lista usuários online |
| `/chat <user>` | Inicia chat 1:1 (troca de chaves autenticada) |
| `/group <nome>` | Cria ou entra em um grupo |
| `/groups` | Lista grupos |
| `/leave` | Sai do chat ou do grupo atual (sair do grupo dispara re-key) |
| `/status` | Status da conexão |
| `/keys` | Mostra suas chaves (Ed25519, ECDH, chaves de sessão e pins TOFU) |
| `/debug` | Liga/desliga logs detalhados |
| `/newprofile` | Apaga sua identidade Ed25519 (simula reinstalação) |
| `/delete @user` | Esquece o pin TOFU de alguém (para aceitar uma nova identidade) |
| `/quit` | Sai |

Qualquer texto que não comece com `/` é enviado ao chat atual.

---

## 🧪 Testes

```bash
npm test
```

- `tests/test-integrity.js`: Ed25519, TOFU (incluindo o alerta de identidade
  trocada), ECDH, HKDF (com o vetor 1 da RFC 5869) e o envelope AES-GCM
  (adulteração de ciphertext e de metadados, replay, remetente errado,
  timestamp vencido)
- `experiments/idea/test-idea.js`: IDEA contra o vetor oficial + ida e volta aleatória

Roteiros de teste manual: [`docs/testes-manuais/`](docs/testes-manuais/).

Para abrir um envelope capturado no modo debug:

```bash
node tools/decrypt-envelope.js <chave_hex> '<envelope_json>'
```

---

## 📁 Estrutura

```
├── client/
│   ├── cli/            # interface de terminal (main, comandos, exibição)
│   ├── crypto/         # ECDH, Ed25519/TOFU, HKDF, envelope AES-GCM
│   ├── shared/         # WebSocketClient: protocolo + toda a criptografia
│   └── .keys/          # (gerado, fora do git) identidade Ed25519 e pins TOFU
├── server/
│   ├── server.js       # Express + Socket.IO (rotas /status e /info)
│   └── src/
│       ├── models/     # User, Group
│       └── websocket/  # WebSocketHandler: roteamento de chaves e envelopes
├── experiments/idea/   # IDEA educativo (não usado pelo chat) + testes
├── tests/              # testes automatizados
├── tools/              # utilitário para descriptografar envelopes
├── docs/               # documentação detalhada
├── config.env          # porta/URL do servidor
└── start-test.sh       # sobe servidor + 3 clientes
```

## 📚 Documentação

- [`docs/ARQUITETURA.md`](docs/ARQUITETURA.md): protocolo, eventos, formato do envelope e **limitações conhecidas**
- [`docs/FLUXO_COMPLETO.md`](docs/FLUXO_COMPLETO.md): passo a passo detalhado (1:1, grupo, entrada/saída, saída do debug)
- [`docs/INTEGRIDADE.md`](docs/INTEGRIDADE.md): Ed25519 + TOFU explicados, com cenários de MITM
- [`docs/historico/`](docs/historico/): documentos da versão antiga (IDEA), mantidos como registro

## ⚠️ Aviso

Projeto **educacional**. Ele mostra as ideias de um protocolo E2E, mas não foi
auditado e tem limitações conhecidas (veja
[ARQUITETURA.md](docs/ARQUITETURA.md#limitações-conhecidas)). Não use para
comunicação que realmente precise ser sigilosa: para isso, prefira o Signal
Protocol ou o MLS.

## Licença

MIT
