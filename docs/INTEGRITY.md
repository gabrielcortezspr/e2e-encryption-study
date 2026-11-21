# Integrity: Ed25519 + TOFU

ECDH by itself gives two parties a shared secret, but it does not tell either of
them **who** is on the other side. If the server (or anyone in the middle)
swaps the ECDH public keys, each client happily agrees on a key with the
attacker. This layer closes that gap with two mechanisms that only work well
**together**:

- **Ed25519** signatures: they prove that an ECDH public key really comes from
  a given identity key;
- **TOFU** (*Trust On First Use*): it remembers which identity key belongs to
  each user, so a different identity later on is detected.

Code: [`client/crypto/ed25519-tofu.js`](../client/crypto/ed25519-tofu.js).

---

## Ed25519 in one paragraph

Ed25519 is EdDSA over Curve25519: a digital signature scheme with 32-byte
public keys, 64-byte signatures and roughly 128-bit security (comparable to
RSA-3072), and it is much faster than RSA or ECDSA. The **private key** signs
and never leaves the machine. The **public key** verifies and is shared
freely.

**Analogy: a wax seal.** You press your ring (private key) into the wax on a
letter. Anyone who knows what your seal looks like (public key) can confirm
that you sealed it and that nobody opened it. They cannot forge the seal
without the ring.

```javascript
// Signing (Alice): what she signs is her ephemeral ECDH public key
const signature = crypto.sign(null, ecdhPublicKey, ed25519PrivateKey);   // 64 bytes

// Verifying (Bob)
const ok = crypto.verify(null, ecdhPublicKey, aliceEd25519PublicKey, signature);
```

The signature only proves "whoever owns *this* Ed25519 key signed *this* ECDH
key". It does not prove that this Ed25519 key belongs to Alice. That is TOFU's
job.

## TOFU in one paragraph

TOFU is the model SSH uses: the first time you talk to someone, you accept
their identity key and **pin** it (store its SHA-256 fingerprint). From then
on, every connection must present the same key. If it changes, the client
shows a security alert and refuses the connection.

```
First contact with Bob   → store fingerprint(Bob)        🔔 "FIRST CONNECTION"
Same key next time       → accept                        ✓ "Identity confirmed"
Different key            → reject                        ⚠️ "IDENTITY CHANGED"
```

A legitimate change (Bob reinstalled, or ran `/newprofile`) looks exactly like
an attack. The user decides: `/delete @Bob` forgets the pin, and the next
contact is treated as a first connection again.

## How they work together

```
Alice                                   Server                       Bob
─────                                   ──────                       ───
ECDH_A (new each connection)
sig_A = Sign(Ed25519_A_priv, ECDH_A)
user_connect {ECDH_A, Ed25519_A, sig_A} ──►  stores public data
                                         ──► exchange_public_key {ECDH_A, Ed25519_A, sig_A}
                                                                     1. Verify(Ed25519_A, ECDH_A, sig_A)
                                                                     2. TOFU: fingerprint(Ed25519_A)
                                                                        matches the pin for "Alice"?
                                                                     3. Only then: ECDH + HKDF
```

| Step | Failure | Meaning |
|---|---|---|
| Signature check | `Invalid signature for peer X` | The ECDH key was swapped or corrupted in transit |
| TOFU check | `TOFU: identity of X changed!` | A different identity claims to be X (MITM, or a reinstall) |

## Why both are needed

| Setup | What an attacker in the middle can do |
|---|---|
| ECDH only | Swap both ECDH keys and read everything. Nobody notices. |
| Ed25519 without TOFU | Generate their own Ed25519 key, sign their own ECDH key and send that. The signature is valid, because the client has no idea which Ed25519 key is "Alice's". |
| TOFU without Ed25519 | Pin the ECDH key? It changes on every connection, so there is nothing stable to pin. |
| **Ed25519 + TOFU** | A long-term key gets pinned, and every ephemeral ECDH key must be signed by it. Swapping keys after the first contact is detected. |

## Attack scenario: MITM after the first contact

1. Alice and Bob talked yesterday, so each has pinned the other's fingerprint.
2. Today, a malicious server replaces Bob's credentials with its own
   (`ECDH_M`, `Ed25519_M`, `sig_M`).
3. The signature is valid (Mallory signed her own key), but Alice's TOFU
   check finds `fingerprint(Ed25519_M) ≠ pin(Bob)`, and the connection is
   **rejected** with the security alert.

**Remaining gap:** if Mallory is in the middle on the *very first* contact,
her key is the one that gets pinned. Real messengers close this with
out-of-band verification (Signal's "safety numbers", QR codes). This project
does not implement that; see
[ARCHITECTURE.md → Known limitations](ARCHITECTURE.md#known-limitations).

## Local storage

Both files live in `client/.keys/` (git-ignored; override with `KEYS_DIR`):

```jsonc
// ed25519_keypair_Alice.json (mode 600: it contains the PRIVATE key)
{ "publicKey": "302a3005...", "privateKey": "302e0201..." }   // DER (SPKI / PKCS#8), hex

// pinned_keys_Alice.json
{ "Bob": { "fingerprint": "9612...", "ed25519PubHex": "302a...", "firstSeen": "2025-11-24T16:46:47.407Z" } }
```

| Action | Effect |
|---|---|
| First connection | `ed25519_keypair_<user>.json` is created |
| First chat with someone | Their entry is added to `pinned_keys_<user>.json` |
| `/newprofile` | Deletes both files, so others get the TOFU alert next time |
| `/delete @user` | Removes one entry from `pinned_keys_<user>.json` |

## Cost

The signature work happens **once per key exchange**, not per message:
signing and verifying with Ed25519 take microseconds. After the exchange,
messages only pay for AES-GCM, whose tag provides per-message integrity (see
the envelope in [ARCHITECTURE.md](ARCHITECTURE.md#v1-envelope)).
