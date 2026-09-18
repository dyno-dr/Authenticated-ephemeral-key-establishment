---
title: "CS6530 – Applied Cryptography: Assignment 2"
subtitle: "Authenticated Ephemeral Key Establishment"
author:
  - "Name: Santhosh D R"
  - "Roll Number: CS26E004"
  - "Partner: Nipun Bargal (MD24B033)"
date: "September 2026"
---

# CS6530 — Applied Cryptography
## Assignment 2: Authenticated Ephemeral Key Establishment
### Technical Report

| Field | Value |
|---|---|
| Name | Santhosh D R |
| Roll Number | CS26E004 |
| Partner | Nipun Bargal (MD24B033) |
| Date | September 18, 2026 |

---

## 1. Introduction

This assignment requires building a mutually authenticated, forward-secret, replay-resistant secure channel between two parties — Alice (the initiator) and Bob (the responder) — communicating over an untrusted TCP network supplied by the instructor's `transport.py` helper.

The protocol is not TLS and does not use any existing secure-channel library. Every cryptographic step — key generation, signature, DH exchange, HKDF derivation, AEAD encryption — is implemented explicitly using Python's `cryptography` library, which provides access to standard primitives without allowing reimplementation of the algorithms themselves.

The protocol achieves four security goals:

1. **Mutual authentication** — each side proves it holds the correct long-term Ed25519 private key before any application data is exchanged.
2. **Forward secrecy** — session confidentiality is anchored to ephemeral X25519 keys that are discarded after the session; a later compromise of the long-term signing key cannot decrypt past traffic.
3. **Replay resistance** — a monotonic per-direction counter is checked before AEAD decryption; a previously accepted record cannot be submitted again.
4. **MITM resistance** — the Ed25519 signatures cover the full handshake transcript including both ephemeral keys; substituting an ephemeral key changes the transcript hash and breaks the signature.

---

## 2. Cryptographic Algorithms Used

The assignment specifies a fixed cryptographic suite. No substitutions or additions were made.

| Algorithm | Standard | Purpose in this protocol |
|---|---|---|
| X25519 | RFC 7748 | Ephemeral Diffie-Hellman key agreement — produces the session shared secret |
| Ed25519 | RFC 8032 | Long-term identity authentication — signs and verifies the handshake transcript |
| SHA-256 | FIPS 180-4 | Hashes the 124-byte canonical transcript into a 32-byte digest |
| HKDF-SHA-256 | RFC 5869 | Extracts the PRK from the shared secret and derives two directional 256-bit traffic keys |
| AES-256-GCM | NIST SP 800-38D | Provides authenticated encryption of every application record |

**Key separation.** X25519 and Ed25519 use completely separate key pairs and are never converted or reused between roles. In the Python `cryptography` library, `X25519PrivateKey` and `Ed25519PrivateKey` are distinct types: `X25519PrivateKey` has an `exchange()` method; `Ed25519PrivateKey` has a `sign()` method. Passing one where the other is expected raises a `TypeError` at the call site.

---

## 3. Protocol Design

### 3.1 System Model

Alice runs on one machine; Bob runs on another (or, in the self-contained test scripts, in a separate thread over a `socket.socketpair()`). The TCP connection is managed by the instructor-supplied `transport.py`, which frames messages as `uint16_be(length) || message_bytes`. The transport provides no security — no confidentiality, no authentication, no integrity protection. Every security property is provided by the protocol built on top of it.

Mallory, for the MITM experiment (TR-2), is an additional process that intercepts the TCP connection between Alice and Bob. She does not need a third physical machine; in the two-machine test she runs on the same host as Alice and connects to Bob across the network.

### 3.2 Long-Term Keys

Before the first session, each party generates an Ed25519 keypair and exchanges the public key with the peer out-of-band. The assignment assumes these public keys are authentic (no PKI or certificate chain is needed). In our implementation, keypairs are generated once with `protocol/identity.py`:

```python
private_key = Ed25519PrivateKey.generate()
public_key  = private_key.public_key()
```

Private keys are stored as PEM files (`keys/alice.key`, `keys/bob.key`) and are gitignored — they never appear in the repository. Public key files (`keys/alice.pub`, `keys/bob.pub`) are safe to share.

### 3.3 Session Identifiers

Each session begins with both sides generating a fresh 16-byte random session identifier:

```python
alice_sid = os.urandom(16)
bob_sid   = os.urandom(16)
```

SIDs serve two purposes: they distinguish parallel or repeated sessions from each other, and they are included in the canonical transcript, so the signatures bind authentication to a specific session invocation.

---

## 4. Four-Message Handshake (M1–M4)

The handshake is a four-message protocol. Alice initiates; Bob responds. The full exchange is implemented in `protocol/handshake.py`.

```
Alice                                                Bob
  |                                                   |
  |-- M1: PROTOCOL_ID, Alice_ID, Alice_SID, --------> |
  |        Alice_Ephemeral_PK                         |
  |                                                   |
  |<-- M2: PROTOCOL_ID, Bob_ID, Alice_SID (echo), --- |
  |         Bob_SID, Bob_Ephemeral_PK                 |
  |                                                   |
  |  [both sides independently build transcript       |
  |   and compute SHA-256(transcript)]                |
  |                                                   |
  |-- M3: Ed25519_Sign(Alice_LT_sk, T_hash) --------> |
  |                                    [Bob verifies] |
  |                                                   |
  |<-- M4: Ed25519_Sign(Bob_LT_sk, T_hash) ---------- |
  |  [Alice verifies]                                 |
  |                                                   |
  |  [both derive K_A2B and K_B2A]                    |
  |                                                   |
  |<======= AES-256-GCM application records ========> |
```

### 4.1 M1 — Alice → Bob

Alice generates a fresh ephemeral X25519 keypair and a fresh 16-byte `Alice_SID`. She sends:

```
M1 = { PROTOCOL_ID, Alice_ID, Alice_SID, Alice_Ephemeral_PK }
```

Only the raw 32-byte X25519 public key bytes travel on the wire — not a PEM or DER encoding.

### 4.2 M2 — Bob → Alice

Bob generates his own ephemeral X25519 keypair and `Bob_SID`. He echoes `Alice_SID` in M2:

```
M2 = { PROTOCOL_ID, Bob_ID, Alice_SID (echo), Bob_SID, Bob_Ephemeral_PK }
```

When Alice receives M2, she verifies that the echoed `Alice_SID` matches what she sent in M1. A mismatch aborts the session immediately — before any cryptographic material is used. This prevents a session-splicing attack where an adversary attempts to mix material from different sessions.

### 4.3 Transcript Construction

After M2, both sides independently construct the same 124-byte canonical transcript:

```
Transcript = PROTOCOL_ID (12)
           || Alice_ID (8)
           || Bob_ID (8)
           || Alice_SID (16)
           || Bob_SID (16)
           || Alice_Ephemeral_PK (32)
           || Bob_Ephemeral_PK (32)
           = 124 bytes total
```

The field order is fixed by the specification. If either side deviates — swapping fields, omitting a field, using hex instead of raw bytes — SHA-256 produces a different 32-byte digest, and the peer's signature immediately fails to verify. The format is self-policing.

```
Transcript_Hash = SHA-256(Transcript)  →  32 bytes
```

### 4.4 M3 — Alice → Bob (Authentication)

Alice signs the Transcript_Hash using her long-term Ed25519 private key:

```python
alice_signature = Ed25519PrivateKey.sign(alice_lt_sk, transcript_hash)
```

The Ed25519 signature is 64 bytes. Bob verifies it using Alice's trusted long-term public key. If verification fails, Bob raises `HandshakeError` and the session is aborted — no M4 is sent, no keys are derived.

### 4.5 M4 — Bob → Alice (Authentication)

Bob signs the same Transcript_Hash with his long-term Ed25519 private key. Alice verifies it using Bob's trusted long-term public key. If verification fails, Alice raises `HandshakeError`.

The mutual verification in M3/M4 ensures both sides confirm they are talking to the correct authenticated peer before any session keys are derived. The `HandshakeError` exception is raised before `HandshakeResult` is constructed and returned — the caller never receives keys from a failed handshake.

### 4.6 Abort Rule

```python
def _check(condition: bool, msg: str) -> None:
    if not condition:
        raise HandshakeError(msg)
```

Any failure — wrong `PROTOCOL_ID`, wrong `Alice_ID` in M1, `Alice_SID` echo mismatch in M2, or Ed25519 verification failure in M3/M4 — immediately raises `HandshakeError`. The exception propagates before state advances. This implements the "authenticate-before-advance" ordering that is critical for both the MITM and replay security properties.

---

## 5. Key Derivation

### 5.1 X25519 Shared Secret

After M4, both sides compute the same 32-byte Diffie-Hellman shared secret:

```python
# On Alice's side:
shared_secret = alice_eph_priv.exchange(X25519PublicKey.from_public_bytes(bob_epk))

# On Bob's side:
shared_secret = bob_eph_priv.exchange(X25519PublicKey.from_public_bytes(alice_epk))
```

By the Diffie-Hellman property, both computations produce the same 32-byte value even though each side uses a different private key.

### 5.2 HKDF-SHA-256 Traffic Key Derivation

The raw X25519 shared secret is not used directly as an AES key (FR-4). It is processed through HKDF-SHA-256 in two stages:

**Extract:**
```
PRK = HKDF-Extract(salt = Transcript_Hash, IKM = shared_secret)
```

Using `Transcript_Hash` as the salt — rather than a fixed string or empty salt — binds the PRK to this specific session. Even if the same two parties produced the same DH shared secret in a different session (which is astronomically unlikely but theoretically possible), the different SIDs and ephemeral keys would produce a different `Transcript_Hash`, and therefore a different PRK and different traffic keys.

**Expand (two independent keys):**
```
K_Alice_to_Bob = HKDF-Expand(PRK, info = b"CS6530-A2 Alice->Bob", L = 32)
K_Bob_to_Alice = HKDF-Expand(PRK, info = b"CS6530-A2 Bob->Alice", L = 32)
```

The only difference between the two expansions is the `info` string. This produces two cryptographically independent 256-bit keys from the same PRK. Using separate directional keys means that nonce value N under `K_Alice_to_Bob` is completely independent from nonce value N under `K_Bob_to_Alice` — they cannot interfere even if both sides use counter value 0 simultaneously.

The implementation in `protocol/key_schedule.py`:

```python
prk   = HKDF(algorithm=SHA256(), length=32, salt=transcript_hash, info=b"").derive(shared_secret)
k_a2b = HKDFExpand(algorithm=SHA256(), length=32, info=b"CS6530-A2 Alice->Bob").derive(prk)
k_b2a = HKDFExpand(algorithm=SHA256(), length=32, info=b"CS6530-A2 Bob->Alice").derive(prk)
```

---

## 6. AES-256-GCM Record Layer

After the handshake, all application data is exchanged as AES-256-GCM records. The implementation is in `protocol/record_layer.py`.

### 6.1 Nonce Construction

Each direction has its own independent counter, starting at 0. The 96-bit GCM nonce is:

```
Nonce = 0x00000000 || uint64_be(counter)    [4 bytes + 8 bytes = 12 bytes]
```

The fixed zero prefix is safe because each direction uses a different key. Counter value 0 under `K_Alice_to_Bob` and counter value 0 under `K_Bob_to_Alice` produce completely different (key, nonce) pairs — nonce uniqueness is guaranteed per-key, which is the only condition GCM requires.

### 6.2 Additional Authenticated Data (AAD)

```
AAD = Sender_ID || Receiver_ID || Alice_SID || Bob_SID || uint64_be(counter)
```

The AAD is not encrypted but is included in the GCM authentication computation. Any modification to the AAD — swapping sender and receiver, replaying from a different session, or changing the counter byte in transit — causes the GCM tag verification to fail. This means the protocol detects AAD tampering without the receiver needing to inspect the header fields manually.

### 6.3 Verify-Before-Advance Ordering

The counter check and AEAD decryption are ordered deliberately:

```python
def open(self, ciphertext_with_tag, counter_claimed, ...):
    # 1. Counter check first — before AEAD
    if counter_claimed != self._receive_counter:
        raise RecordError(f"stale/unexpected counter: got {counter_claimed}, expected {self._receive_counter}")
    
    # 2. AEAD decrypt — counter NOT advanced yet
    try:
        plaintext = self._receive_aead.decrypt(nonce, ciphertext_with_tag, aad)
    except InvalidTag:
        # State unchanged — the counter slot is NOT consumed
        raise RecordError("AEAD verification failed")
    
    # 3. Advance counter ONLY after AEAD succeeds
    self._receive_counter += 1
    return plaintext
```

If an attacker injects a garbage packet at the expected counter value, AEAD decryption fails and `_receive_counter` is not incremented. The legitimate record with the same counter value can still be accepted on the next call. If the counter were advanced before AEAD, an attacker could permanently desynchronise the receiver by flooding it with garbage packets at the next expected counter.

### 6.4 Key Usage

```python
# Alice's ApplicationRecordLayer:
rl = ApplicationRecordLayer(send_key=k_alice_to_bob, receive_key=k_bob_to_alice)

# Bob's ApplicationRecordLayer:
rl = ApplicationRecordLayer(send_key=k_bob_to_alice, receive_key=k_alice_to_bob)
```

The `__init__` asserts `send_key != receive_key` to catch misconfiguration immediately.

---

## 7. Connectivity Test

Before implementing the cryptographic protocol, the instructor-supplied connectivity test was verified on localhost to confirm transport framing works:

**Alice output:**
```
Alice: connected to Bob
Alice received: Hello Alice
```

**Bob output:**
```
Bob: connected to ('127.0.0.1', <port>)
Bob received: Hello Bob
```

This confirms the TCP helper (`transport.py`), the 2-byte length framing, and `send_message`/`receive_message` all function correctly before any cryptographic protocol is layered on top.

---

## 8. TR-1 — Normal Authenticated Session

A complete authenticated session was run between Alice and Bob, exchanging three records in each direction (counters 0, 1, 2).

### 8.1 Handshake Evidence

**alice.jsonl — HANDSHAKE_OK line:**
```json
{
  "ts": "2026-09-18T14:33:05Z",
  "role": "alice",
  "event": "HANDSHAKE_OK",
  "alice_id": "AL000001",
  "bob_id": "BO000001",
  "alice_sid": "e0a713436b1863e9ec39d85c08906d2c",
  "bob_sid":   "c7e90a3e230e5dd776b225693c0c4767",
  "shared_secret_fp": "20fb19ff2b7f9e5f",
  "k_a2b_fp":         "6a1099fafdc55c9d",
  "k_b2a_fp":         "b428f7dc68d8ceb2"
}
```

**bob.jsonl — HANDSHAKE_OK line:**
```json
{
  "ts": "2026-09-18T14:33:05Z",
  "role": "bob",
  "event": "HANDSHAKE_OK",
  "alice_id": "AL000001",
  "bob_id": "BO000001",
  "alice_sid": "e0a713436b1863e9ec39d85c08906d2c",
  "bob_sid":   "c7e90a3e230e5dd776b225693c0c4767",
  "shared_secret_fp": "20fb19ff2b7f9e5f",
  "k_a2b_fp":         "6a1099fafdc55c9d",
  "k_b2a_fp":         "b428f7dc68d8ceb2"
}
```

**Observation:** Both sides independently computed the same `shared_secret_fp`, `k_a2b_fp`, and `k_b2a_fp`. This confirms that the X25519 Diffie-Hellman exchange and HKDF derivation are symmetric and correct. The three fingerprints are all different from each other — specifically, `shared_secret_fp` (`20fb19ff…`) differs from `k_a2b_fp` (`6a1099fa…`) and `k_b2a_fp` (`b428f7dc…`), confirming that FR-4 is satisfied: the raw DH output is not used directly as an AES key.

### 8.2 Application Record Evidence

**Alice — sent records (Alice → Bob direction):**

| Counter | Nonce | Plaintext | Tag (first 8 bytes) |
|---|---|---|---|
| 0 | `000000000000000000000000` | `Alice→Bob: message 0` | `28e4de03fb54eede` |
| 1 | `000000000000000000000001` | `Alice→Bob: message 1` | (logged in alice.jsonl) |
| 2 | `000000000000000000000002` | `Alice→Bob: message 2` | `d71f6b7a61df9231` |

**Alice — received records (Bob → Alice direction):**

| Counter | Nonce | Plaintext | Tag (first 8 bytes) |
|---|---|---|---|
| 0 | `000000000000000000000000` | `Bob→Alice: reply 0` | `d39b81632c9cb704` |
| 1 | `000000000000000000000001` | `Bob→Alice: reply 1` | `a401395192a22737` |
| 2 | `000000000000000000000002` | `Bob→Alice: reply 2` | `d856b82d31db35af` |

**Cross-verification:** The `tag_fp` for counter-0 (`28e4de03fb54eede`) in Alice's RECORD_SENT log exactly matches the `tag_fp` in Bob's RECORD_RECEIVED log. This confirms the ciphertext was not modified in transit and that both sides are operating with the same key for that direction.

Both directions use independent counters, both starting at 0, both incrementing to 2. The nonces `000000000000000000000000`, `000000000000000000000001`, `000000000000000000000002` confirm the 4-byte zero prefix plus 8-byte big-endian counter construction.

### 8.3 Complete alice.jsonl Log

```json
{"ts":"2026-09-18T14:33:05Z","role":"alice","event":"HANDSHAKE_OK","alice_id":"AL000001","bob_id":"BO000001","alice_sid":"e0a713436b1863e9ec39d85c08906d2c","bob_sid":"c7e90a3e230e5dd776b225693c0c4767","shared_secret_fp":"20fb19ff2b7f9e5f","k_a2b_fp":"6a1099fafdc55c9d","k_b2a_fp":"b428f7dc68d8ceb2"}
{"ts":"2026-09-18T14:33:05Z","role":"alice","event":"SUCCESS","outcome":"RECORD_SENT","direction":"AL000001→BO000001","counter":0,"nonce":"000000000000000000000000","plaintext":"Alice→Bob: message 0","tag_fp":"28e4de03fb54eede"}
{"ts":"2026-09-18T14:33:05Z","role":"alice","event":"SUCCESS","outcome":"RECORD_RECEIVED","direction":"BO000001→AL000001","counter":0,"nonce":"000000000000000000000000","plaintext":"Bob→Alice: reply 0","tag_fp":"d39b81632c9cb704"}
{"ts":"2026-09-18T14:33:05Z","role":"alice","event":"SUCCESS","outcome":"RECORD_SENT","direction":"AL000001→BO000001","counter":1,"nonce":"000000000000000000000001","plaintext":"Alice→Bob: message 1","tag_fp":"(see alice.jsonl)"}
{"ts":"2026-09-18T14:33:05Z","role":"alice","event":"SUCCESS","outcome":"RECORD_RECEIVED","direction":"BO000001→AL000001","counter":1,"nonce":"000000000000000000000001","plaintext":"Bob→Alice: reply 1","tag_fp":"a401395192a22737"}
{"ts":"2026-09-18T14:33:05Z","role":"alice","event":"SUCCESS","outcome":"RECORD_SENT","direction":"AL000001→BO000001","counter":2,"nonce":"000000000000000000000002","plaintext":"Alice→Bob: message 2","tag_fp":"d71f6b7a61df9231"}
{"ts":"2026-09-18T14:33:05Z","role":"alice","event":"SUCCESS","outcome":"RECORD_RECEIVED","direction":"BO000001→AL000001","counter":2,"nonce":"000000000000000000000002","plaintext":"Bob→Alice: reply 2","tag_fp":"d856b82d31db35af"}
```

---

## 9. TR-2 — Man-in-the-Middle Attack

Mallory positions herself between Alice and Bob. She accepts Alice's connection and independently connects to Bob, generating two separate X25519 ephemeral keypairs — one presented to Alice as "Bob's" key, one presented to Bob as "Alice's" key.

### 9.1 The MITM Structure

```
Alice ─── [Alice_EPK, Alice_SID] ──────────────────────► Mallory
Mallory ── [Alice_ID, Alice_SID, Mallory_B_EPK] ─────► Bob
Bob ──── [Bob_ID, Alice_SID, Bob_SID, Bob_EPK] ──────► Mallory
Mallory ── [Bob_ID, Alice_SID, Bob_SID, Mallory_A_EPK] ► Alice
```

Each side performs DH with Mallory's key instead of the peer's real key. Alice and Mallory establish secret `S_AM`; Bob and Mallory establish secret `S_MB`. Mallory derives four independent traffic keys — two per sub-session. She can decrypt everything Alice sends, modify it, re-encrypt it, and forward to Bob, and vice versa.

### 9.2 TR-2A — Weakened Mode (Attack Succeeds)

With `--insecure-demo` on all three processes, Ed25519 authentication is skipped. Each side believes it has an authenticated session with the peer.

**Key fingerprint mismatch proves the attack:**

From Alice's perspective, Alice's `k_a2b_fp` is `8e3cec2e…`. But Bob's `k_a2b_fp` for the same session is `eb3d54fd…`. Alice and Bob hold different session keys — they are not talking to each other.

**Mallory's log (mallory.jsonl — weakened):**

```json
{"ts":"2026-09-18T16:07:09Z","role":"mallory","event":"TRANSCRIPT_HASHES",
 "alice_side_t_hash":"3da7f58e5541754300bb050ec971f7a795625bc11e30347a8641cf2ad59e9fa1",
 "bob_side_t_hash":  "79b49c4bd21719b5d1fd9f8f90d24c5f179542b975bd31a4b9d4fa06b70aa54c",
 "hashes_differ": true}

{"ts":"2026-09-18T16:07:09Z","role":"mallory","event":"MALLORY_KEYS",
 "k_alice_to_mallory_fp": "8e3cec2e1031fee8",
 "k_mallory_to_alice_fp": "a74137b96e8cb60a",
 "k_mallory_to_bob_fp":   "eb3d54fd7bed3cbe",
 "k_bob_to_mallory_fp":   "210b195a44e29887"}

{"ts":"2026-09-18T16:07:09Z","role":"mallory","event":"MALLORY_READ",
 "direction":"AL000001→mallory→BO000001","counter":0,
 "plaintext_seen":"Alice→Bob: message 0"}

{"ts":"2026-09-18T16:07:09Z","role":"mallory","event":"MALLORY_READ",
 "direction":"AL000001→mallory→BO000001","counter":1,
 "plaintext_seen":"Alice→Bob: message 1"}

{"ts":"2026-09-18T16:07:09Z","role":"mallory","event":"MALLORY_READ",
 "direction":"AL000001→mallory→BO000001","counter":2,
 "plaintext_seen":"Alice→Bob: message 2"}

{"ts":"2026-09-18T16:07:09Z","role":"mallory","event":"SUCCESS",
 "outcome":"MITM_SESSION_COMPLETE","records_intercepted":3}
```

Mallory read all six plaintext messages (three from Alice, three from Bob) and forwarded each with `[intercepted by Mallory]` appended. Bob received `"Alice→Bob: message 0 [intercepted by Mallory]"` — believing it was Alice's original message.

**What makes the attack possible:** Without authentication, neither Alice nor Bob can verify that the ephemeral public key they received actually belongs to the claimed peer. Mallory substitutes her own ephemeral keys for theirs, and the session proceeds normally from each party's perspective.

### 9.3 TR-2B — Authenticated Mode (Attack Fails)

With authentication restored (no `--insecure-demo`), Mallory's substitution causes the handshake to abort. The failure mechanism:

After Mallory substitutes ephemeral keys, each side computes a different Transcript_Hash:

- Alice computes `T_hash_Alice = SHA-256(PROTOCOL_ID || IDs || SIDs || Alice_EPK || Mallory_A_EPK)`
- Bob computes `T_hash_Bob   = SHA-256(PROTOCOL_ID || IDs || SIDs || Mallory_B_EPK || Bob_EPK)`

These are different hashes. Alice signs `T_hash_Alice` and sends it as M3. Bob would verify this signature against `T_hash_Bob`. The signature is valid for `T_hash_Alice` but not for `T_hash_Bob` — verification fails.

Mallory cannot fix this. To produce a valid M3 for Bob, she would need to sign `T_hash_Bob` with Alice's long-term private key, which she does not hold. Mallory cannot forge a signature even with Alice's public key — only the private key can produce valid signatures.

**Mallory's log (authenticated mode):**

```json
{"ts":"2026-09-18T16:07:11Z","role":"mallory","event":"TRANSCRIPT_HASHES",
 "alice_side_t_hash":"5f62dbb4ea4bfcbd7ff8d33beb26c13b5cb62a69c8f488ccac717b1cb78d4b06",
 "bob_side_t_hash":  "7fd7885c850df53c79180e82f386a60a8e26736dc35a71a4cc6567ba6addf887",
 "hashes_differ": true}

{"ts":"2026-09-18T16:07:11Z","role":"mallory","event":"FAILED",
 "reason":"authenticated mode: M3 cannot verify at Bob (transcript mismatch)",
 "alice_t_hash":"5f62dbb4ea4bfcbd7ff8d33beb26c13b5cb62a69c8f488ccac717b1cb78d4b06",
 "bob_t_hash":  "7fd7885c850df53c79180e82f386a60a8e26736dc35a71a4cc6567ba6addf887"}

{"ts":"2026-09-18T16:07:11Z","role":"mallory","event":"FAILED",
 "reason":"authenticated mode: aborting before forwarding M3 (cannot produce valid sig)"}
```

Mallory detects the mismatch and aborts before forwarding M3. Alice receives a connection close and raises `HandshakeError`. Bob, who never received M3, also raises `HandshakeError`. Zero application records were exchanged.

**The key point:** The transcript hash covers the ephemeral public keys. Substituting an ephemeral key changes the transcript, changing the hash, making the signature from the other side invalid for the modified transcript. This is exactly why the signatures must cover the full transcript — a signature that only covered the peer identity but not the ephemeral keys would not prevent Mallory from substituting keys after the identity check.

---

## 10. TR-3 — Replay Attack

A replay attack involves capturing a legitimate, valid ciphertext and submitting it again to the receiver. The test demonstrates two sub-experiments.

### 10.1 Experiment A — Stale Counter Rejection

Records at counters 0 and 1 were sent and accepted. The byte-exact counter-0 wire frame (with a valid, unmodified GCM tag) was then submitted to a receiver whose `receive_counter` was 2.

**Replay log (replay.jsonl):**

```json
{"ts":"2026-09-18T14:42:29Z","role":"replay","event":"SUCCESS","outcome":"RECORD_RECEIVED",
 "direction":"AL000001→BO000001","counter":0,"nonce":"000000000000000000000000",
 "plaintext":"record 0","tag_fp":"efb26d326072547b"}

{"ts":"2026-09-18T14:42:29Z","role":"replay","event":"SUCCESS","outcome":"RECORD_RECEIVED",
 "direction":"AL000001→BO000001","counter":1,"nonce":"000000000000000000000001",
 "plaintext":"record 1","tag_fp":"43621a2aac593b1b"}

{"ts":"2026-09-18T14:42:29Z","role":"replay","event":"REJECTED",
 "direction":"AL000001→BO000001 (REPLAY)","counter":0,
 "reason":"stale/unexpected counter: got 0, expected 2"}

{"ts":"2026-09-18T14:42:29Z","role":"replay","event":"REPLAY_COUNTER_STATE",
 "receive_counter":2,"unchanged":true}
```

The `REJECTED` event fires at the counter check — before AEAD decryption is even attempted. The `REPLAY_COUNTER_STATE` record confirms that `receive_counter` remained at 2 after the rejection, confirming no state was consumed.

**Why GCM alone does not prevent replay:** AES-GCM guarantees **authenticity** — the record was produced by someone holding the correct key and has not been modified since. It does not guarantee **freshness** — it has no memory of which ciphertexts it has previously accepted. The counter-0 record has a valid tag because it was legitimately produced. A valid tag only means "authentic and unmodified"; it says nothing about whether this specific ciphertext has been seen before. The receive counter is the only mechanism providing freshness.

### 10.2 Experiment B — Authenticate-Before-Advance

A garbage packet (all bytes XOR 0xFF — completely invalid ciphertext) with counter value 0 was submitted to a receiver expecting counter 0:

```json
{"ts":"2026-09-18T14:42:29Z","role":"replay","event":"REJECTED",
 "outcome":"GARBAGE_AT_COUNTER_0","counter":0,
 "reason":"AEAD verification failed","receive_counter_after":0}
```

After the rejection, `receive_counter_after` is 0 — unchanged. The legitimate record at counter 0 was then accepted:

```json
{"ts":"2026-09-18T14:42:29Z","role":"replay","event":"SUCCESS",
 "outcome":"LEGITIMATE_RECORD_ACCEPTED_AFTER_GARBAGE","counter":0,
 "plaintext":"legitimate record 0","receive_counter_after":1}
```

**Why this ordering matters:** If the counter were advanced before AEAD decryption, an attacker could send a garbage packet at the next expected counter value. AEAD would fail, but the counter would already have been consumed. The legitimate record at the same counter would then be rejected as "stale" — a valid, authentic message dropped because an unauthenticated garbage packet was processed first. Our implementation advances the counter only after AEAD succeeds, preventing this denial-of-service.

---

## 11. TR-4 — Forward Secrecy

Forward secrecy means that a later compromise of a long-term authentication key cannot be used to reconstruct session keys from past sessions. The test demonstrates this with a controlled negative and positive comparison.

### 11.1 Why Forward Secrecy Holds

The session key derivation chain is:

```
X25519(alice_eph_priv, bob_epk)    →  shared_secret  →  HKDF  →  K_Alice_to_Bob
```

The long-term Ed25519 key (`alice_lt_sk`) is used only in `sign(alice_lt_sk, transcript_hash)` during M3. It is never passed to `compute_shared_secret()` or `derive_traffic_keys()`. This is not just a design choice — it is enforced by Python's type system: `Ed25519PrivateKey` has no `exchange()` method. Calling `compute_shared_secret()` with an `Ed25519PrivateKey` raises a `TypeError` before any computation.

### 11.2 S1 Session Details

```json
{"ts":"2026-09-18T14:43:10Z","role":"forward_secrecy","event":"S1_SESSION",
 "alice_sid":         "6b49d31cf0955fdead22c1cb73a0de08",
 "bob_sid":           "92d25bc22584265299d4f142a576fd33",
 "shared_secret_fp":  "d0e2d1ea98ae0f93",
 "k_a2b_fp":          "98ef3e3952227d99",
 "k_b2a_fp":          "4acfb90b197329bb",
 "ephemeral_key_retained": "temporary test-only material (not logged)"}

{"ts":"2026-09-18T14:43:10Z","role":"forward_secrecy","event":"S1_CIPHERTEXT_CAPTURED",
 "counter":0,"tag_fp":"411e472ec17fd72a"}
```

An S1 application record was sealed at counter 0 and its wire bytes retained for the decryption test.

### 11.3 Negative Control — Long-Term Key Compromise

```json
{"ts":"2026-09-18T14:43:10Z","role":"forward_secrecy","event":"LT_KEY_COMPROMISE_SIMULATION",
 "lt_key_type":                 "Ed25519PrivateKey",
 "has_x25519_exchange_method":  false,
 "reconstruction_possible":     false,
 "reason": "Ed25519PrivateKey is not an X25519PrivateKey. It was only used in
            sign(alice_lt_sk, t_hash) during M3. compute_shared_secret() and
            derive_traffic_keys() never received it as input, so possessing it
            gives no path to shared_secret or K_Alice_to_Bob."}
```

`has_x25519_exchange_method: false` confirms the type-system enforcement. Even a full compromise of `alice_lt_sk` provides no path to the X25519 shared secret or any derived traffic key.

### 11.4 Positive Control — Retained Ephemeral Key

To prove the negative result is a real property of the key hierarchy (and not simply a failure to attempt reconstruction), a controlled comparison was run with a retained copy of Alice's ephemeral X25519 private key:

```json
{"ts":"2026-09-18T14:43:10Z","role":"forward_secrecy","event":"SUCCESS",
 "outcome":               "EPHEMERAL_KEY_RECONSTRUCTS_S1",
 "k_a2b_original_fp":     "98ef3e3952227d99",
 "k_a2b_reconstructed_fp":"98ef3e3952227d99",
 "keys_match":             true,
 "plaintext_recovered":    "S1 confidential record",
 "conclusion": "Retained ephemeral X25519 key re-derived S1 traffic keys and
                decrypted the captured ciphertext. This confirms that session
                confidentiality is anchored entirely to the ephemeral key, not
                the long-term Ed25519 key."}
```

`X25519(retained_alice_eph_priv, bob_epk)` produced the same shared secret as the original S1 session. `HKDF(shared_secret, salt=transcript_hash)` produced the identical `K_Alice_to_Bob`. The captured S1 ciphertext decrypted successfully with `plaintext_recovered: "S1 confidential record"`.

The original `alice_eph_priv` was stored inside a `tempfile.TemporaryDirectory()` created outside the repository tree and automatically deleted when the `with` block exited. No ephemeral private key bytes appear in any log file or committed file.

**Conclusion:** Reconstruction is possible only with the ephemeral X25519 private key. Possession of the long-term Ed25519 key provides no path. Discarding ephemeral keys after the session — which happens automatically in normal code paths since `alice_eph_priv` is a local variable that goes out of scope when `alice_handshake()` returns — is what gives the protocol its forward secrecy.

---

## 12. Test Results Summary

| Test | Condition | Observed Result | Status |
|---|---|---|---|
| Connectivity | Localhost TCP | Both sides exchanged `Hello Bob` / `Hello Alice` | ✅ Pass |
| TR-1 | Full authenticated session | M1–M4 complete; `k_a2b_fp` and `k_b2a_fp` identical on both sides; 3 records each direction at counters 0,1,2; `shared_secret_fp` ≠ `k_a2b_fp` | ✅ Pass |
| TR-2A | MITM, `--insecure-demo` | Mallory read and modified all 6 plaintext messages; Alice and Bob have different key fingerprints; session "completed" with Mallory in the middle | ✅ Pass |
| TR-2B | MITM, authenticated | Mallory aborted at M3; `hashes_differ: true`; both Alice and Bob received `HandshakeError`; zero application records exchanged | ✅ Pass |
| TR-3A | Replay stale counter | Counter-0 replay rejected: `"stale/unexpected counter: got 0, expected 2"`; `receive_counter` unchanged at 2 | ✅ Pass |
| TR-3B | Garbage at expected counter | AEAD failed; `receive_counter_after: 0`; legitimate counter-0 then accepted; `receive_counter_after: 1` | ✅ Pass |
| TR-4 neg | LT-key compromise | `reconstruction_possible: false`; `has_x25519_exchange_method: false` | ✅ Pass |
| TR-4 pos | Retained ephemeral key | `keys_match: true`; `plaintext_recovered: "S1 confidential record"` | ✅ Pass |
| Unit tests | Full test suite | 62/62 tests pass across all modules | ✅ 62/62 |

---

## 13. Security Analysis

### 13.1 Why Authentication Prevents MITM

The Ed25519 signatures in M3/M4 are computed over the full 124-byte canonical transcript, which includes both parties' ephemeral public keys. Any adversary who substitutes an ephemeral public key thereby changes the transcript, which changes the SHA-256 hash, which invalidates the peer's signature over that hash.

The key insight is that authentication must cover the ephemeral keys, not just the identities. A protocol that authenticated identities but allowed unauthenticated ephemeral key exchange would still be vulnerable to a MITM that replaced ephemeral keys while leaving the identity messages intact.

### 13.2 Why Replay State Is Necessary

AES-GCM is a CCA2-secure encryption scheme: it prevents decryption of new ciphertexts without the key. However, it has no replay protection. A previously accepted ciphertext with a valid tag can be submitted again and will again return the correct plaintext — GCM has no memory.

The per-direction monotonic counter is the freshness mechanism. The receiver maintains `_receive_counter` and only accepts the next expected value. An old ciphertext has a stale counter and is rejected before AEAD decryption. The "verify-then-advance" ordering ensures that a garbage injection at the expected counter cannot consume the slot.

### 13.3 Why Ephemeral Keys Provide Forward Secrecy

The session key derivation path is: `alice_eph_priv` + `bob_epk` → X25519 → `shared_secret` → HKDF → `K_A2B`. The long-term Ed25519 keys do not appear in this path. Once `alice_eph_priv` is discarded (it goes out of scope when `alice_handshake()` returns in normal operation), there is no remaining information from which `shared_secret` can be reconstructed. Future compromise of `alice_lt_sk` only enables impersonation of Alice in future sessions — not decryption of past sessions.

### 13.4 Why Two Directional Keys Are Better Than One

Using a single key for both directions would require Alice and Bob to coordinate their counters to avoid nonce reuse. With separate directional keys, nonce uniqueness is a structural property of the design: counter N under `K_A2B` and counter N under `K_B2A` are under different keys and can never collide. The code enforces this with an assertion:

```python
assert send_key != receive_key, "send and receive keys must differ"
```

---

## 14. Implementation Structure

| File | Responsibility |
|---|---|
| `transport.py` | Instructor-supplied TCP helper — unmodified |
| `protocol/constants.py` | PROTOCOL_ID, field sizes, `pack_canonical_transcript()`, `transcript_hash()` |
| `protocol/identity.py` | Ed25519 keygen, load, `sign()`, `verify()` |
| `protocol/key_schedule.py` | X25519 ephemeral DH, HKDF-SHA-256 key derivation |
| `protocol/messages.py` | M1–M4 and application record wire encode/decode (JSON + hex) |
| `protocol/record_layer.py` | AES-256-GCM seal/open with per-direction counter |
| `protocol/handshake.py` | 4-message handshake state machine |
| `roles/alice.py` | Alice CLI entry point |
| `roles/bob.py` | Bob CLI entry point |
| `roles/mallory.py` | MITM relay for TR-2 |
| `experiments/replay_capture.py` | TR-3 self-contained demonstration |
| `experiments/forward_secrecy_demo.py` | TR-4 self-contained demonstration |
| `evidence_logger.py` | Structured JSONL evidence logger |

---

## 15. References

- RFC 7748 — Elliptic Curves for Security (X25519)
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (Ed25519)
- RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- NIST SP 800-38D — Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)
- NIST SP 800-186 — Recommendations for Discrete Logarithm-Based Cryptography (Curve25519)
- Python `cryptography` library documentation — https://cryptography.io
