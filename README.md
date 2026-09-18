# CS6530 Assignment 2 — Authenticated Ephemeral Key Establishment

Implementation of a mutually authenticated, forward-secret, replay-resistant secure channel using X25519, Ed25519, SHA-256, HKDF-SHA-256, and AES-256-GCM.

---

## Repository structure

```
.
├── transport.py             # Instructor-supplied TCP helper (unmodified)
├── Alice_Test.py            # Instructor-supplied connectivity test (unmodified)
├── Bob_Test.py              # Instructor-supplied connectivity test (unmodified)
├── evidence_logger.py       # Structured JSONL evidence logger (shared by all roles)
├── protocol/
│   ├── constants.py         # PROTOCOL_ID, field sizes, transcript packing
│   ├── identity.py          # Ed25519 keygen / load / sign / verify
│   ├── key_schedule.py      # X25519 DH + HKDF-SHA-256 key derivation
│   ├── messages.py          # M1–M4 wire serialisation/deserialisation
│   ├── record_layer.py      # AES-256-GCM seal/open with per-direction counters
│   └── handshake.py         # M1–M4 handshake state machine
├── roles/
│   ├── alice.py             # Alice CLI (initiator)
│   ├── bob.py               # Bob CLI (responder)
│   └── mallory.py           # Mallory MITM relay (TR-2 only)
├── experiments/
│   ├── replay_capture.py    # TR-3: replay rejection demonstration
│   └── forward_secrecy_demo.py  # TR-4: forward secrecy demonstration
├── tests/
│   ├── test_constants.py
│   ├── test_identity.py
│   ├── test_key_schedule.py
│   ├── test_messages.py
│   ├── test_record_layer.py
│   └── test_handshake_loopback.py
├── evidence/
│   ├── tr1_normal_session/  # alice.jsonl, bob.jsonl
│   ├── tr2_mitm/            # alice.jsonl, bob.jsonl, mallory.jsonl
│   ├── tr3_replay/          # replay.jsonl
│   └── tr4_forward_secrecy/ # forward_secrecy.jsonl
├── keys/                    # Long-term keypairs (*.key gitignored)
├── requirements.txt
└── .gitignore
```

---

## Setup

```bash
pip install -r requirements.txt
```

### Generate long-term keypairs (run once per machine, exchange .pub files only)

```bash
# On Alice's machine
python -c "from protocol.identity import generate_and_save_keypair; generate_and_save_keypair('keys/alice')"

# On Bob's machine
python -c "from protocol.identity import generate_and_save_keypair; generate_and_save_keypair('keys/bob')"
```

Copy `keys/alice.pub` to Bob's machine and `keys/bob.pub` to Alice's machine. Never transfer `.key` files.

---

## Running the protocol (two-machine setup)

Replace `<BOB_IP>` and `<MALLORY_IP>` with actual IP addresses. All commands are run from the repo root.

### Step 0 — Verify connectivity (run instructor test scripts first)

```bash
# Bob's machine
python Bob_Test.py

# Alice's machine
python Alice_Test.py <BOB_IP>
```

### TR-1 — Normal authenticated session

```bash
# Bob's machine
python roles/bob.py \
    --port 6530 \
    --alice-id AL000001 --bob-id BO000001 \
    --key-stem keys/bob \
    --alice-pub keys/alice.pub \
    --trial-dir evidence/tr1_normal_session

# Alice's machine
python roles/alice.py <BOB_IP> \
    --port 6530 \
    --alice-id AL000001 --bob-id BO000001 \
    --key-stem keys/alice \
    --bob-pub keys/bob.pub \
    --trial-dir evidence/tr1_normal_session
```

### TR-2 — MITM demonstration

`EvidenceLogger` opens in write mode, so run the two variants into separate directories.

**Part A: weakened mode (attack succeeds)**

Start in order: Bob → Mallory → Alice. Allow ~1 second between each.

```bash
# Bob's machine
python roles/bob.py \
    --port 6540 \
    --alice-id AL000001 --bob-id BO000001 \
    --key-stem keys/bob --alice-pub keys/alice.pub \
    --trial-dir evidence/tr2_mitm/weakened \
    --insecure-demo

# Mallory's machine (or any intermediate host)
python roles/mallory.py \
    --listen-port 6541 \
    --bob-host <BOB_IP> --bob-port 6540 \
    --alice-id AL000001 --bob-id BO000001 \
    --trial-dir evidence/tr2_mitm/weakened \
    --insecure-demo

# Alice's machine (connect to Mallory, not Bob)
python roles/alice.py <MALLORY_IP> \
    --port 6541 \
    --alice-id AL000001 --bob-id BO000001 \
    --key-stem keys/alice --bob-pub keys/bob.pub \
    --trial-dir evidence/tr2_mitm/weakened \
    --insecure-demo
```

**Part B: authenticated mode (attack fails)**

Same commands without `--insecure-demo`, using a different `--trial-dir`. Mallory aborts
before forwarding M3; all three processes exit with a handshake failure.

```bash
# Bob's machine
python roles/bob.py \
    --port 6542 \
    --alice-id AL000001 --bob-id BO000001 \
    --key-stem keys/bob --alice-pub keys/alice.pub \
    --trial-dir evidence/tr2_mitm/authenticated

# Mallory's machine
python roles/mallory.py \
    --listen-port 6543 \
    --bob-host <BOB_IP> --bob-port 6542 \
    --alice-id AL000001 --bob-id BO000001 \
    --trial-dir evidence/tr2_mitm/authenticated

# Alice's machine
python roles/alice.py <MALLORY_IP> \
    --port 6543 \
    --alice-id AL000001 --bob-id BO000001 \
    --key-stem keys/alice --bob-pub keys/bob.pub \
    --trial-dir evidence/tr2_mitm/authenticated
```

### TR-3 — Replay demonstration (self-contained, no network)

```bash
python experiments/replay_capture.py
```

### TR-4 — Forward secrecy demonstration (self-contained, no network)

```bash
python experiments/forward_secrecy_demo.py
```

---

## Running the unit tests

```bash
python -m pytest tests/ -v
```

62 tests, all passing.

---

## Security properties demonstrated

| Property | Mechanism | Evidence |
|---|---|---|
| Mutual authentication | Ed25519 signatures over Transcript_Hash in M3/M4 | TR-1, TR-2B |
| Forward secrecy | Ephemeral X25519 keys discarded after session | TR-4 |
| Replay resistance | Monotonic per-direction counter, verify-before-advance | TR-3 |
| MITM resistance | Signatures bind to the exact ephemeral keys in the transcript | TR-2 |
| Key separation | HKDF Expand with distinct `info` strings for each direction | TR-1 |
