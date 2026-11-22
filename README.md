# E2E Encryption Study

![Node.js](https://img.shields.io/badge/Node.js-18+-339933?logo=nodedotjs&logoColor=white)
![Socket.IO](https://img.shields.io/badge/Socket.IO-relay-010101?logo=socketdotio&logoColor=white)
[![tests](https://github.com/gabrielcortezspr/e2e-encryption-study/actions/workflows/tests.yml/badge.svg)](https://github.com/gabrielcortezspr/e2e-encryption-study/actions/workflows/tests.yml)
![License](https://img.shields.io/badge/license-MIT-green)

A study project: an **end-to-end encrypted terminal chat** written in Node.js,
built to learn applied cryptography by implementing the pieces of a secure
messaging protocol one by one. The server is only a **relay**: it never sees
private keys or plaintext.

| Layer | What it uses | Where |
|---|---|---|
| Key agreement | Ephemeral ECDH, secp256k1 curve | [`client/crypto/ecdh-manual.js`](client/crypto/ecdh-manual.js) |
| Key authentication | Ed25519 signatures + TOFU (*Trust On First Use*) | [`client/crypto/ed25519-tofu.js`](client/crypto/ed25519-tofu.js) |
| Key derivation | HKDF-SHA256 (RFC 5869) | [`client/crypto/hkdf.js`](client/crypto/hkdf.js) |
| Encryption + integrity | AES-128-GCM (AEAD) inside a "v1 envelope" | [`client/crypto/envelope.js`](client/crypto/envelope.js) |
| Anti-replay | Timestamp window (5 min) + nonce cache | [`client/crypto/envelope.js`](client/crypto/envelope.js) |
| Groups | Random group key distributed over pairwise channels, re-keyed when members join or leave | [`client/shared/websocket-client.js`](client/shared/websocket-client.js) |

> **About IDEA:** the project started as `idea-message`, with the plan of
> encrypting messages with the IDEA block cipher. The final protocol uses
> **AES-128-GCM** instead. The IDEA implementation lives in
> [`experiments/idea/`](experiments/idea/) as study material and is checked
> against the official test vector, but the chat does **not** use it.

---

## 🚀 Getting started

Requirements: Node.js 18+.

```bash
npm run install:all        # installs server/ and client/ dependencies
```

**Manually (one terminal each):**

```bash
npm run server                                   # server on port 6666
node client/cli/main.js --username Alice
node client/cli/main.js --username Bob --debug   # --debug prints every crypto step
```

**Automatically:** `./start-test.sh` (or `./start-test.sh --debug`) opens the
server and three clients (Alice, Bob, Charlie) using gnome-terminal, xterm,
tmux or screen.

The port and URL are set in [`config.env`](config.env) (`NODE_PORT`, `NODE_URL`).

### Client commands

| Command | Description |
|---|---|
| `/users` | List online users |
| `/chat <user>` | Start a 1:1 chat (authenticated key exchange) |
| `/group <name>` | Create or join a group |
| `/groups` | List groups |
| `/leave` | Leave the current chat or group (leaving a group triggers a re-key) |
| `/status` | Connection status |
| `/keys` | Show your keys (Ed25519, ECDH, session keys and TOFU pins) |
| `/debug` | Toggle detailed logs |
| `/newprofile` | Delete your Ed25519 identity (simulates a reinstall) |
| `/delete @user` | Forget someone's TOFU pin (to accept a new identity) |
| `/quit` | Exit |

Any text that does not start with `/` is sent to the current chat.

---

## 🧪 Tests

```bash
npm test
```

The suite runs on every push through GitHub Actions.

- [`tests/test-integrity.js`](tests/test-integrity.js): Ed25519, TOFU
  (including the changed-identity alert), ECDH, HKDF (with RFC 5869 test
  vector 1) and the AES-GCM envelope (tampered ciphertext and metadata,
  replay, wrong sender, expired timestamp)
- [`experiments/idea/test-idea.js`](experiments/idea/test-idea.js): IDEA
  against the official test vector, plus random round trips

Manual test scenarios (TOFU alerts, `/newprofile`, groups):
[`docs/MANUAL_TESTS.md`](docs/MANUAL_TESTS.md).

To open an envelope captured in debug mode:

```bash
node tools/decrypt-envelope.js <key_hex> '<envelope_json>'
```

---

## 📁 Project layout

```
├── client/
│   ├── cli/            # terminal UI (entry point, commands, message display)
│   ├── crypto/         # ECDH, Ed25519/TOFU, HKDF, AES-GCM envelope
│   ├── shared/         # WebSocketClient: protocol + all client-side crypto
│   └── .keys/          # (generated, git-ignored) Ed25519 identity and TOFU pins
├── server/
│   ├── server.js       # Express + Socket.IO (/status and /info routes)
│   └── src/
│       ├── models/     # User, Group
│       └── websocket/  # WebSocketHandler: routes keys and envelopes
├── experiments/idea/   # educational IDEA cipher (not used by the chat) + tests
├── tests/              # automated tests
├── tools/              # envelope decryption utility
├── docs/               # detailed documentation
├── config.env          # server port/URL
└── start-test.sh       # starts the server + 3 clients
```

## 📚 Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): protocol, events, envelope format and **known limitations**
- [`docs/INTEGRITY.md`](docs/INTEGRITY.md): Ed25519 + TOFU explained, with MITM scenarios
- [`docs/MANUAL_TESTS.md`](docs/MANUAL_TESTS.md): step-by-step manual test scenarios

The original study notes, written in Portuguese while the project was being
built, are preserved in the git history (first commit).

## ⚠️ Disclaimer

This is a **study project**. It shows how the ideas behind an E2E protocol
fit together, but it has not been audited and has known limitations (see
[ARCHITECTURE.md](docs/ARCHITECTURE.md#known-limitations)). Do not use it for
communication that actually needs to stay private: use the Signal Protocol or
MLS for that.

## License

[MIT](LICENSE)
