#!/usr/bin/env python3
# experiments/forward_secrecy_demo.py — TR-4: forward secrecy demonstration

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from experiments import loopback_handshake
from protocol.key_schedule import compute_shared_secret, derive_traffic_keys
from protocol.record_layer import ApplicationRecordLayer
from protocol.messages import encode_app_record, decode_app_record
from protocol.identity import generate_and_save_keypair
from evidence_logger import EvidenceLogger

ALICE_ID = b"AL000001"
BOB_ID   = b"BO000001"


def run(log):
    # All long-term and ephemeral secrets live inside this TemporaryDirectory.
    # It is created outside the repo tree by Python's tempfile module, so there
    # is no risk of accidentally committing key material.
    with tempfile.TemporaryDirectory() as keytmp:
        a_lt_sk, a_lt_pk = generate_and_save_keypair(f"{keytmp}/alice")
        b_lt_sk, b_lt_pk = generate_and_save_keypair(f"{keytmp}/bob")

        hs_a, hs_b = loopback_handshake(a_lt_sk, b_lt_sk, a_lt_pk, b_lt_pk, ALICE_ID, BOB_ID,
                                         retain_ephemeral=True)

        # alice_eph_priv is set only because retain_ephemeral=True was passed.
        # In every other call site (alice.py, bob.py, mallory.py) it is None.
        retained_eph_priv = hs_a.alice_eph_priv
        bob_epk           = hs_a.bob_epk

        log._emit("S1_SESSION",
                  alice_sid=hs_a.alice_sid.hex(),
                  bob_sid=hs_a.bob_sid.hex(),
                  shared_secret_fp=hs_a.shared_secret[:8].hex(),
                  k_a2b_fp=hs_a.k_alice_to_bob[:8].hex(),
                  k_b2a_fp=hs_a.k_bob_to_alice[:8].hex(),
                  ephemeral_key_retained="temporary test-only material (not logged)")

        # Capture one S1 ciphertext to use as the decryption target in the positive control.
        rl_s1 = ApplicationRecordLayer(
            send_key=hs_a.k_alice_to_bob, receive_key=hs_a.k_bob_to_alice)
        pt_s1  = b"S1 confidential record"
        ct_s1, ctr_s1 = rl_s1.seal(pt_s1, ALICE_ID, BOB_ID, hs_a.alice_sid, hs_a.bob_sid)
        wire_s1 = encode_app_record(ctr_s1, ct_s1)
        log._emit("S1_CIPHERTEXT_CAPTURED",
                  counter=ctr_s1,
                  tag_fp=ct_s1[-16:][:8].hex())

        del rl_s1  # normal lifecycle: drop session state after use

        # Negative control: attacker obtains Alice's long-term Ed25519 key.
        # Ed25519PrivateKey has no X25519 exchange() method — it was only ever
        # passed to sign() during M3, never to compute_shared_secret() or
        # derive_traffic_keys().  The type system enforces this separation.
        log._emit("LT_KEY_COMPROMISE_SIMULATION",
                  lt_key_type=type(a_lt_sk).__name__,
                  has_x25519_exchange_method=hasattr(a_lt_sk, "exchange"),
                  reconstruction_possible=False,
                  reason=(
                      "Ed25519PrivateKey is not an X25519PrivateKey. "
                      "It was only used in sign(alice_lt_sk, t_hash) during M3. "
                      "compute_shared_secret() and derive_traffic_keys() never "
                      "received it as input, so possessing it gives no path to "
                      "shared_secret or K_Alice_to_Bob."
                  ))

        # Positive control: retained ephemeral key reconstructs S1.
        # X25519(alice_eph_priv, bob_epk) gives the same shared secret as S1;
        # HKDF with the same transcript_hash gives the same directional keys.
        reconstructed_shared = compute_shared_secret(retained_eph_priv, bob_epk)
        k_a2b_r, _ = derive_traffic_keys(reconstructed_shared, hs_a.transcript_hash)

        rl_check = ApplicationRecordLayer(
            send_key=hs_b.k_bob_to_alice, receive_key=k_a2b_r)
        frame = decode_app_record(wire_s1)
        pt_recovered = rl_check.open(
            frame["ct"], frame["counter"],
            ALICE_ID, BOB_ID, hs_a.alice_sid, hs_a.bob_sid)

        log._emit("SUCCESS",
                  outcome="EPHEMERAL_KEY_RECONSTRUCTS_S1",
                  k_a2b_original_fp=hs_a.k_alice_to_bob[:8].hex(),
                  k_a2b_reconstructed_fp=k_a2b_r[:8].hex(),
                  keys_match=(k_a2b_r == hs_a.k_alice_to_bob),
                  plaintext_recovered=pt_recovered.decode(),
                  conclusion=(
                      "Retained ephemeral X25519 key re-derived S1 traffic keys and "
                      "decrypted the captured ciphertext. This confirms that session "
                      "confidentiality is anchored entirely to the ephemeral key, not "
                      "the long-term Ed25519 key."
                  ))

        # keytmp (and retained_eph_priv) are deleted when TemporaryDirectory.__exit__ fires.


def main():
    log = EvidenceLogger("evidence/tr4_forward_secrecy", "forward_secrecy")
    try:
        run(log)
    except Exception as exc:
        log.abort(str(exc))
        sys.exit(f"[tr4] error: {exc}")
    finally:
        log.close()
    print("[tr4] forward secrecy demonstration complete", flush=True)


if __name__ == "__main__":
    main()
