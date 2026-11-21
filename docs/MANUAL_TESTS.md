# Manual test scenarios

Automated tests live in `npm test`. The scenarios below exercise the
interactive parts of the CLI. Start the server with `npm run server`, then open
one terminal per user with `node client/cli/main.js --username <Name>` (or use
`./start-test.sh`). Add `--debug` to see every cryptographic step.

Key files live in `client/.keys/` (see [INTEGRITY.md](INTEGRITY.md#local-storage)).

---

## 1. First connection (TOFU pin)

```bash
rm -f client/.keys/pinned_keys_Alice.json client/.keys/pinned_keys_Bob.json
```

1. Connect Alice and Bob.
2. In Alice's terminal: `/chat Bob`.

**Expected:** both terminals show a `🔔 FIRST CONNECTION WITH ...` box with
the peer's fingerprint, followed by `✓ Session key established with ...` and
`🔒 Secure chat established ...`. `/keys` now lists the peer under *TOFU -
Known identities*.

## 2. Reconnecting with the same identity

1. Bob quits (`/quit`) and reconnects with the same username.
2. Alice runs `/chat Bob` again.

**Expected:** no alert, just `✓ Identity of Bob confirmed`. The ECDH key is
new (it is ephemeral), but it is signed by the same pinned Ed25519 key.

## 3. Changed identity (⚠️ security alert)

1. Bob quits and deletes his identity, simulating a reinstall:
   ```bash
   rm client/.keys/ed25519_keypair_Bob.json
   ```
   (or run `/newprofile` inside Bob's client before quitting)
2. Bob reconnects, and a new Ed25519 key pair is generated.
3. Alice runs `/chat Bob`.

**Expected:** Alice sees `⚠️ SECURITY ALERT - IDENTITY CHANGED` with the
expected and received fingerprints, and the key exchange is **rejected**.
Sending a message fails with `No key found for user Bob`.

## 4. Accepting the new identity (`/delete`)

1. Continuing from scenario 3, Alice runs `/delete @Bob`.
2. Alice runs `/chat Bob` again.

**Expected:** this time it is treated as a first connection (🔔 box) and the
chat works normally.

Edge cases:

| Command | Expected output |
|---|---|
| `/delete` (no argument) | `❌ Usage: /delete @user` |
| `/delete @Alice` (yourself) | `❌ You cannot delete your own profile this way` |
| `/delete @Charlie` (never talked) | `⚠️  You have no TOFU record for Charlie` |
| `/delete @Bob` with no TOFU file | `⚠️  You have no TOFU records yet` |

## 5. Group chat and re-keying

1. Alice: `/group Team` (Alice is now the creator).
2. Bob: `/group Team`, then Charlie: `/group Team`.
3. Anyone sends a message. Everyone in the group receives it.
4. Bob: `/leave`.
5. Alice sends another message.

**Expected:** after step 4 the server re-keys the group: the creator logs
`Key for group Team generated and sent to 1 member(s)`, and Bob's `/keys` no
longer shows a key for `Team`. Bob does not receive the message from step 5.

## 6. Disconnecting frees the username

1. Charlie presses Ctrl+C while in a group.
2. Charlie reconnects with the same username.

**Expected:** the reconnection succeeds (no `Username is already in use`), and
the remaining group members get a new group key.

## 7. Decrypting a captured envelope

1. Connect Alice with `--debug`, start a chat and send a message.
2. Copy the *Full envelope* JSON and the *Session key* printed after
   `🔍 Debug - envelope sent`.
3. Run:
   ```bash
   node tools/decrypt-envelope.js <session_key_hex> '<envelope_json>'
   ```

**Expected:** the plaintext is printed together with `✓ GCM tag is valid`.
If you change a single character of `ct`, `to` or `ts`, the tool reports
`Invalid GCM tag`.
