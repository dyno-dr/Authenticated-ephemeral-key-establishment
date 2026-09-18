# CS6530 Assignment 2 — Technical Report

## 1. Protocol overview

The protocol establishes a mutually authenticated, forward-secret, replay-resistant secure channel between two parties, Alice (initiator) and Bob (responder), using four messages over a TCP connection provided by `transport.py`.

**Message flow:**

```
Alice                                          Bob
  |                                             |
  |-- M1: PROTOCOL_ID, Alice_ID, Alice_SID, --->|
  |        Alice_Ephemeral_PK                   |
  |                                             |
  |<-- M2: PROTOCOL_ID, Bob_ID, Alice_SID,  ----|
  |         Bob_SID, Bob_Ephemeral_PK           |
  |                                             |
  |  [both sides compute Transcript_Hash]       |
  |                                             |
  |-- M3: Ed25519_Sign(Alice_LT_sk, T_hash) --->|  [Bob verifies]
  |                                             |
  |<-- M4: Ed25519_Sign(Bob_LT_sk, T_hash)  ----|  [Alice verifies]
  |                                             |
  |  [both sides derive K_A2B and K_B2A]        |
  |                                             |
  |<======= AES-256-GCM application data ======>|
```

**What each message achieves:**
- M1 and M2 establish ephemeral public keys and session identifiers (SIDs). SIDs are fresh random 16-byte values generated per session; Alice's SID is echoed by Bob in M2 so Alice can confirm she is talking to the same entity that received M1.
- M3 and M4 provide mutual authentication: each side signs the Transcript_Hash using its long-term Ed25519 private key. Because the hash covers both ephemeral keys, the signatures bind authentication to the specific key material exchanged in this session.
- No traffic key is ever derived until both M3 and M4 have been verified. Any failure before that point raises `HandshakeError` without returning keys to the caller.

---

## 2. Transcript construction

The canonical transcript is a fixed-layout 124-byte concatenation:

```
PROTOCOL_ID (12) || Alice_ID (8) || Bob_ID (8)
|| Alice_SID (16) || Bob_SID (16)
|| Alice_Ephemeral_PK (32) || Bob_Ephemeral_PK (32)
= 124 bytes total
```

The field order is fixed; if either side deviates, SHA-256 produces a different hash and the peer's signature fails to verify — making the format self-policing.

SHA-256 of this transcript gives the 32-byte `Transcript_Hash`, used both as the message signed/verified in M3/M4 and as the HKDF salt for key derivation. Binding the salt to the transcript means traffic keys are session-specific: even if the same DH shared secret were somehow reused, the different transcript (different SIDs, different ephemeral keys) would produce different traffic keys.

---

## 3. X25519 and HKDF key derivation

After the handshake, both sides compute:

```
shared_secret = X25519(alice_eph_priv, bob_epk)
             = X25519(bob_eph_priv,   alice_epk)   # same value by DH commutativity
```

The raw X25519 output is not used directly as an AES key (FR-4). It is passed through HKDF-SHA-256:

```
PRK       = HKDF-Extract(salt=Transcript_Hash, IKM=shared_secret)
K_A2B     = HKDF-Expand(PRK, info=b"CS6530-A2 Alice->Bob", L=32)
K_B2A     = HKDF-Expand(PRK, info=b"CS6530-A2 Bob->Alice", L=32)
```

The two `info` strings are the only difference between the two key derivations. This is what makes `K_A2B ≠ K_B2A` deterministically, without requiring any additional randomness. Using the transcript hash as the HKDF salt instead of a fixed string means the PRK is session-specific and cannot be precomputed before the handshake is complete.

**TR-1 evidence — three distinct values from the same session:**

| Value | First 8 bytes |
|---|---|
| raw shared_secret | `5d36795e4d3049d6` |
| K_Alice_to_Bob | `094022f0d2efad2b` |
| K_Bob_to_Alice | `957565e6ba2309f1` |

All three are visibly different, confirming the raw DH output is not used directly as a traffic key.

---

## 4. AES-256-GCM record layer

Each application record is sealed with:

```
nonce = 0x00000000 || counter.to_bytes(8, 'big')   # 12 bytes
aad   = sender_id || receiver_id || alice_sid || bob_sid || counter.to_bytes(8, 'big')
ct    = AES-256-GCM.encrypt(key=K_send, nonce, plaintext, aad)
```

**Why the counter works as a nonce:** each direction has its own key (`K_A2B` for Alice→Bob, `K_B2A` for Bob→Alice) and its own counter starting at 0. Because the key is direction-specific, counter value 0 on the Alice→Bob key never produces the same (key, nonce) pair as counter 0 on the Bob→Alice key. The fixed zero prefix is safe precisely because this per-direction key separation exists.

**Why AAD matters:** the sender/receiver IDs, SIDs, and counter are included in the AAD but not encrypted. This means any tampering with these header fields is detected by the GCM tag — an adversary cannot swap the sender and receiver fields or replay from a different session without the tag failing.

**Verify-then-advance ordering:** the receive counter is checked *before* AEAD decryption, and only advanced *after* AEAD succeeds. This prevents an attacker from burning a legitimate counter slot by sending a garbage packet with the correct counter value — the slot is never consumed unless AEAD authentication passes.

**TR-1 evidence — independent counters per direction:**

| Direction | Counter 0 nonce | Counter 1 nonce | Counter 2 nonce |
|---|---|---|---|
| AL000001→BO000001 | `000000000000000000000000` | `000000000000000000000001` | `000000000000000000000002` |
| BO000001→AL000001 | `000000000000000000000000` | `000000000000000000000001` | `000000000000000000000002` |

Both directions start at 0 independently — confirming the per-direction counter design.

---

## 5. TR-1: Normal session evidence

A full authenticated session was run on localhost with no flags. Both sides independently derived matching keys and exchanged 3 records in each direction (counters 0, 1, 2). The handshake completed without any `--insecure-demo` flag, confirming the secure default.

Key observations from `evidence/tr1_normal_session/`:

- `shared_secret_fp`, `k_a2b_fp`, `k_b2a_fp` are identical in alice.jsonl and bob.jsonl — both sides computed the same X25519 result and the same HKDF expansion.
- The three fingerprints are distinct from each other (see §3 table), confirming FR-4 and directional key separation.
- Nonces increment monotonically per direction, starting from `000000000000000000000000`.
- Tag fingerprints for the same record match across alice.jsonl and bob.jsonl (e.g., counter-0 tag `85faf925…` appears in both files), confirming the ciphertext was not modified in transit.

---

## 6. TR-2: MITM demonstration

### 6.1 Attack structure

Mallory positions herself between Alice and Bob by accepting Alice's connection and independently connecting to Bob. She generates two separate X25519 ephemeral keypairs:

- `mallory_to_alice_priv/pub` — presented to Alice as "Bob's" ephemeral key
- `mallory_to_bob_priv/pub` — presented to Bob as "Alice's" ephemeral key

After substituting the ephemeral keys in M1 and M2, Alice and Bob each compute a different Transcript_Hash from each other, because the ephemeral key each received (Mallory's) differs from the one the other side sent. Mallory computes the corresponding hash for each leg and derives four independent traffic keys — two per sub-session.

### 6.2 Weakened mode (authentication disabled)

With `--insecure-demo` on all three processes, signature verification is skipped. Both Alice and Bob believe they have an authenticated session with each other, but their `K_Alice_to_Bob` fingerprints are different (`af437973…` on Alice's side, `01af3faa…` on Bob's side), revealing that they are actually talking to Mallory.

Mallory's log shows `plaintext_seen: "Alice→Bob: message 0"` — she decrypted the plaintext using `K_alice_to_mallory`, modified it (appending `[intercepted by Mallory]`), and re-encrypted it to Bob using `K_mallory_to_bob`. Bob received the modified version without any indication of tampering.

### 6.3 Authenticated mode (attack fails)

Without `--insecure-demo`, Mallory detects the transcript mismatch before forwarding M3:

```json
{
  "event": "FAILED",
  "reason": "authenticated mode: M3 cannot verify at Bob (transcript mismatch)",
  "alice_t_hash": "1ec8e948…",
  "bob_t_hash":   "102ab534…"
}
```

**Why the check fails — the primary mechanism:** Alice signs `alice_t_hash`, which is the hash of the transcript she computed using `mallory_to_alice_pub` as "Bob's" key. Bob would verify this signature against `bob_t_hash`, which he computed from `mallory_to_bob_pub` as "Alice's" key. These are different hashes — the signature is valid for one but not the other. No cryptographic forgery is needed to make the check fail; it fails because Alice's real, correctly-produced signature is over a hash that Bob simply did not compute.

**The reinforcing reason:** even if Mallory wanted to replace Alice's signature with one that verifies against `bob_t_hash`, she cannot — she holds neither `Alice_LT_sk` nor `Bob_LT_sk`.

Zero application records were exchanged before the abort. Alice and Bob both saw `FAILED: Connection closed` and exited non-zero.

---

## 7. TR-3: Replay demonstration

### 7.1 Experiment A — replay rejected on stale counter

Records at counters 0 and 1 were accepted. The captured counter-0 wire frame (with valid GCM tag) was then replayed to a receiver whose `receive_counter` was already 2:

```json
{"event": "REJECTED", "counter": 0, "reason": "stale/unexpected counter: got 0, expected 2"}
{"event": "REPLAY_COUNTER_STATE", "receive_counter": 2, "unchanged": true}
```

The rejection fires at the counter check, before AEAD is attempted. The GCM tag is still cryptographically valid at the time of rejection — it has not been modified. This is the key point: AES-GCM guarantees *authenticity* (the data came from the keyed sender unmodified) but has no concept of *freshness* (whether this specific ciphertext has been seen before). The counter-based replay state is a necessary addition, not a redundant check.

### 7.2 Experiment B — authenticate-before-advance ordering

A garbage frame (bit-flipped ciphertext) at counter 0 was presented to a receiver expecting counter 0. AEAD failed, and `receive_counter` remained at 0:

```json
{"event": "REJECTED", "outcome": "GARBAGE_AT_COUNTER_0", "counter": 0,
 "reason": "AEAD verification failed", "receive_counter_after": 0}
```

The legitimate counter-0 record was then accepted:

```json
{"event": "SUCCESS", "outcome": "LEGITIMATE_RECORD_ACCEPTED_AFTER_GARBAGE",
 "counter": 0, "receive_counter_after": 1}
```

This demonstrates the ordering rule: the counter slot is not consumed by a failed AEAD. If the counter had been advanced eagerly on receipt (check-then-advance-then-decrypt), the garbage packet would have burned slot 0 and the legitimate message would have been rejected as a replay — a genuine, authenticated message dropped due to an unauthenticated garbage packet.

---

## 8. TR-4: Forward secrecy

### 8.1 Key hierarchy

The session's confidentiality is anchored entirely to the ephemeral X25519 keypairs. The long-term Ed25519 keys serve only one role: signing/verifying the Transcript_Hash in M3/M4. They are never passed to `compute_shared_secret()` or `derive_traffic_keys()`.

This separation is enforced at the type level in Python's `cryptography` library: `Ed25519PrivateKey` has no `exchange()` method; `compute_shared_secret()` requires an `X25519PrivateKey`. Attempting to use Alice's long-term key in the DH computation would raise a `TypeError` at the call site.

### 8.2 Negative control — long-term key compromise

```json
{
  "lt_key_type": "Ed25519PrivateKey",
  "has_x25519_exchange_method": false,
  "reconstruction_possible": false,
  "reason": "Ed25519PrivateKey is not an X25519PrivateKey. It was only used in
             sign(alice_lt_sk, t_hash) during M3. compute_shared_secret() and
             derive_traffic_keys() never received it as input..."
}
```

An attacker who later obtains Alice's long-term signing key gains the ability to impersonate Alice in *future* sessions (by signing transcripts), but cannot reconstruct the shared secret or traffic keys for *past* sessions.

### 8.3 Positive control — retained ephemeral key

To confirm the negative result is a genuine property of the key hierarchy (not a failure to attempt reconstruction), a controlled comparison was performed using a retained copy of Alice's ephemeral X25519 private key, stored in a `tempfile.TemporaryDirectory()` during the experiment and discarded automatically on exit.

```json
{
  "outcome": "EPHEMERAL_KEY_RECONSTRUCTS_S1",
  "k_a2b_original_fp":      "881b8957b0e4a63b",
  "k_a2b_reconstructed_fp": "881b8957b0e4a63b",
  "keys_match": true,
  "plaintext_recovered": "S1 confidential record"
}
```

`X25519(retained_alice_eph_priv, bob_epk)` produced the same shared secret as the original session. `HKDF-Extract(salt=Transcript_Hash, IKM=reconstructed_shared)` followed by `HKDF-Expand` produced the same `K_Alice_to_Bob`. The captured S1 ciphertext decrypted successfully.

This confirms: reconstruction is possible only with the ephemeral private key, not the long-term key — which is precisely what forward secrecy means.

### 8.4 Lifecycle note

In the normal code path (no `retain_ephemeral=True` flag), `alice_eph_priv` is a local variable inside `alice_handshake()` that goes out of scope and becomes eligible for garbage collection once the function returns. References to `shared_secret` and the traffic keys are held only by the `HandshakeResult` object and the `ApplicationRecordLayer` instances; when these are no longer referenced after the session, Python's GC reclaims them. No module-level dict or long-lived structure retains them. This satisfies the assignment's architectural lifecycle requirement, though it does not constitute a guaranteed low-level memory scrub (Python GC offers no such guarantee).

---

## 9. Design decisions

- **Directional keys over a single shared key:** a single shared key requires both sides to carefully offset their counters to avoid nonce collisions. Separate keys derived from distinct `info` strings make nonce uniqueness a structural property of the design rather than a discipline the application must maintain.
- **HKDF over raw X25519 output:** X25519 output has known distribution properties; HKDF whitening produces uniform keys and binds them to the session transcript via the salt.
- **Strict expected-next counter over a sliding window:** a sliding window is appropriate for lossy/reordering transports. Over TCP (via `transport.py`), in-order delivery is guaranteed, so strict expected-next is simpler, fully deterministic, and the correct choice.
- **Single `--insecure-demo` toggle, not a second codebase:** removing exactly one property (signature verification) is what flips the MITM outcome. A separate insecure implementation would obscure that causality and risk silent divergence in other areas.
- **`tempfile.TemporaryDirectory()` for retained ephemeral key:** created outside the repo tree by construction; auto-deleted on context exit; eliminates the risk of accidentally committing key material via `git add .`.

---

## 10. References

- RFC 7748 — Elliptic Curves for Security (X25519)
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (Ed25519)
- RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- NIST SP 800-38D — Recommendation for Block Cipher Modes of Operation: GCM
- NIST SP 800-186 — Recommendations for Discrete Logarithm-Based Cryptography (Curve25519)
