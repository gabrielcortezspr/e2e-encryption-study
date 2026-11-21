# Arquitetura e protocolo

Este documento descreve o que o código **faz hoje**. Para um passo a passo com a
saída do modo debug, veja [`FLUXO_COMPLETO.md`](FLUXO_COMPLETO.md).

## Visão geral

```
 Cliente (Alice)                    Servidor (relay)                 Cliente (Bob)
 ───────────────                    ────────────────                 ─────────────
 Ed25519 (disco)                    guarda só chaves PÚBLICAS        Ed25519 (disco)
 ECDH efêmero (RAM)   ── pub ──►    roteia pub+assinatura   ── ►     verifica + TOFU
 HKDF → chave AES                                                    HKDF → chave AES
 AES-GCM(envelope)    ── env ──►    encaminha o envelope    ── ►     valida + decifra
```

- **Servidor** (`server/`): Express + Socket.IO. Mantém usuários e grupos **em
  memória**, roteia chaves públicas e envelopes e escolhe quem gera a chave do
  grupo (o criador). Ele não executa nenhuma operação criptográfica sobre as
  mensagens.
- **Cliente** (`client/`): toda a criptografia fica em
  `client/shared/websocket-client.js`, que usa os módulos de `client/crypto/`.
  A CLI (`client/cli/`) só cuida da interface.

## Chaves

| Chave | Tipo | Vida útil | Onde fica |
|---|---|---|---|
| Identidade | Ed25519 | Longa (persistente) | `client/.keys/ed25519_keypair_<user>.json` (permissão 600) |
| Pins TOFU | SHA-256 da chave Ed25519 dos peers | Persistente | `client/.keys/pinned_keys_<user>.json` |
| Troca de chaves | ECDH secp256k1 | Uma por conexão | RAM |
| Sessão 1:1 | 16 bytes = HKDF(segredo ECDH, info = `"userA:userB"` ordenado) | Enquanto durar a conexão | RAM (`sharedKeys`) |
| Grupo | 16 bytes aleatórios gerados pelo criador | Até o próximo re-key | RAM (`groupKeys`) |

O diretório de chaves pode ser trocado com a variável de ambiente `KEYS_DIR`.

## Fluxo 1:1

1. **Conexão:** o cliente carrega (ou gera) o par Ed25519, gera um par ECDH novo
   e assina a chave pública ECDH com Ed25519. Ele envia
   `user_connect { username, publicKey, ed25519Pub, signature }`.
2. **`/chat Bob`:** o servidor envia a cada lado um
   `exchange_public_key { targetUser, publicKey, ed25519Pub, signature }` com os
   dados do outro.
3. **Verificação:** cada cliente confere a assinatura Ed25519 sobre a chave
   ECDH e aplica TOFU:
   - no primeiro contato, guarda o fingerprint;
   - se o fingerprint mudar depois, **rejeita** a conexão (alerta de MITM).
4. **Derivação:** segredo = ECDH(priv, pubPeer); `encKey` = HKDF-SHA256(segredo,
   info = nomes ordenados, 48 bytes)[0..16]. Os 32 bytes restantes (`authKey`)
   estão reservados e hoje não são usados.
5. **Mensagens:** cada mensagem vira um envelope v1 (abaixo), enviado com
   `send_message` e entregue ao destinatário como `message_received`.

## Envelope v1

```json
{ "v": 1, "ts": 1732420000000, "from": "Alice", "to": "Bob", "isGroup": false,
  "nonce": "<12 bytes hex>", "ct": "<ciphertext hex>", "tag": "<16 bytes hex>" }
```

- AES-128-GCM com nonce aleatório de 96 bits.
- **AAD** = `v ‖ ts ‖ from ‖ to ‖ nonce`, então adulterar qualquer metadado
  invalida a tag.
- Na recepção, o cliente verifica, nesta ordem:
  1. os campos obrigatórios e a versão;
  2. `|agora − ts| ≤ 5 min`;
  3. se `from` é o remetente esperado;
  4. se o nonce ainda não foi visto;
  5. a tag GCM.

  O nonce só entra no cache **depois** que a tag é verificada.

## Fluxo de grupo

1. `/group G`: se o grupo não existe, quem entrou é o **criador**.
2. Quando alguém entra, o servidor roteia `exchange_public_key` (com
   `isGroup: true` e `groupName`) entre o novo membro e cada membro existente.
   Cada par deriva uma chave pairwise como no 1:1.
3. Cerca de 1 s depois, o servidor manda `generate_and_distribute_group_key` ao
   criador. Ele gera 16 bytes aleatórios e cifra essa chave para cada membro
   com um envelope usando a chave pairwise. Depois envia
   `distribute_group_key { encryptedKeys: [{ member, encryptedKey }] }`.
4. O servidor entrega cada envelope (`group_key_received`). Ele não consegue
   abri-los.
5. Mensagens de grupo usam o mesmo envelope com `to = nome do grupo` e chegam a
   todos os membros online (`group_message_received`).
6. **Saída** (`/leave` ou desconexão): o membro que saiu apaga a chave do
   grupo. Se o criador saiu, outro membro assume, e uma **nova** chave é gerada
   e distribuída para quem ficou, de modo que o ex-membro não lê mensagens
   futuras. Se só sobra 1 membro, a chave é descartada.

## Eventos Socket.IO

| Cliente → servidor | Servidor → cliente |
|---|---|
| `user_connect`, `start_chat`, `send_message`, `join_group`, `leave_group`, `distribute_group_key`, `leave_chat`, `list_users`, `list_groups` | `user_connected`, `user_joined`, `user_left`, `chat_started`, `chat_ready`, `chat_left`, `exchange_public_key`, `message_sent`, `message_received`, `group_message_received`, `group_joined`, `group_left`, `member_joined_group`, `member_left_group`, `generate_and_distribute_group_key`, `group_key_received`, `clear_group_key`, `users_list`, `groups_list`, `error` |

Rotas HTTP: `GET /`, `GET /status`, `GET /info`.

## Limitações conhecidas

Estas são as fraquezas de um protocolo didático. Elas valem para estudo e são
os pontos que um sistema real (Signal, MLS) resolve.

1. **O primeiro contato confia no servidor.** TOFU só detecta uma troca de
   identidade *depois* do primeiro contato. Um servidor malicioso pode entregar
   uma chave Ed25519 falsa já na primeira vez, e não existe verificação fora do
   canal (comparar o fingerprint pessoalmente ou por QR code).
2. **Não há autenticação no servidor.** Qualquer cliente pode se registrar com
   qualquer nome que esteja livre.
3. **AAD sem delimitadores.** Os campos são concatenados sem separador nem
   tamanho, então `from="ab", to="c"` e `from="a", to="bc"` geram a mesma AAD.
   O impacto prático é pequeno porque a chave já amarra o par, mas o certo
   seria serializar com tamanho (TLV) ou JSON canônico.
4. **O destinatário não confere `to`.** A proteção vem só do fato de a chave
   ser exclusiva do par ou do grupo.
5. **O anti-replay fica só em memória.** Se o cliente reiniciar, um envelope
   de até 5 minutos atrás pode ser aceito de novo.
6. **Não há ratchet.** A chave de sessão vale pela conexão inteira. O sigilo
   futuro (*forward secrecy*) existe só entre conexões, porque o ECDH é
   regenerado a cada `connect`, e não mensagem a mensagem como no Double
   Ratchet.
7. **O criador do grupo é um ponto de confiança.** Ele escolhe a chave, e o
   servidor decide quem é o criador.
8. **Há corridas por tempo fixo.** `chat_ready` (500 ms) e a geração da chave
   do grupo (1 s) dependem de `setTimeout`, não de confirmação dos clientes.
9. **Escolhas didáticas:** `/keys` e `--debug` imprimem chaves privadas e de
   sessão, e o CORS do servidor está aberto (`*`).
10. **A curva é secp256k1.** Ela funciona, mas X25519 é a escolha padrão
    atual para ECDH.
