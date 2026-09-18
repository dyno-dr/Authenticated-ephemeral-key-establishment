#!/usr/bin/env python3
# roles/mallory.py — MITM relay: ephemeral-key substitution with two independent sub-sessions

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import argparse

from transport import accept_peer, connect_to_peer, send_message, receive_message
from protocol.constants import PROTOCOL_ID, pack_canonical_transcript, transcript_hash
from protocol.key_schedule import generate_ephemeral_keypair, compute_shared_secret, derive_traffic_keys
from protocol.messages import (
    decode_m1, encode_m1,
    decode_m2, encode_m2,
    decode_m3, encode_m3,
    decode_m4, encode_m4,
    decode_app_record, encode_app_record,
    MessageError,
)
from protocol.record_layer import ApplicationRecordLayer, RecordError
from evidence_logger import EvidenceLogger


def run(args):
    alice_id = args.alice_id.encode()
    bob_id   = args.bob_id.encode()

    log = EvidenceLogger(args.trial_dir, "mallory")

    if args.insecure_demo:
        print("WARNING: Ed25519 authentication is intentionally disabled — "
              "this mode is for TR-2 only.", flush=True)

    print(f"[mallory] listening for Alice on port {args.listen_port}…", flush=True)
    sock_a, peer_a = accept_peer(args.listen_port)
    print(f"[mallory] Alice connected from {peer_a}", flush=True)

    print(f"[mallory] connecting to Bob at {args.bob_host}:{args.bob_port}…", flush=True)
    sock_b = connect_to_peer(args.bob_host, args.bob_port)
    print("[mallory] connected to Bob", flush=True)

    try:
        _relay(sock_a, sock_b, alice_id, bob_id, args, log)
    except Exception as exc:
        log.abort(str(exc))
        print(f"[mallory] abort: {exc}", flush=True)
    finally:
        log.close()
        for s in (sock_a, sock_b):
            try:
                s.close()
            except Exception:
                pass


def _relay(sock_a, sock_b, alice_id, bob_id, args, log):
    # Two independent ephemeral keypairs — one presented to Alice as "Bob's" key,
    # one presented to Bob as "Alice's" key.  Using a single keypair would conflate
    # the two sub-sessions and give both sides the same shared secret, which is wrong.
    m2a_priv, m2a_pub = generate_ephemeral_keypair()   # Mallory's alice-facing key
    m2b_priv, m2b_pub = generate_ephemeral_keypair()   # Mallory's bob-facing key

    m1_raw = receive_message(sock_a)
    m1     = decode_m1(m1_raw)
    if m1["protocol_id"] != PROTOCOL_ID:
        raise ValueError("M1: wrong protocol_id")
    if m1["alice_id"] != alice_id:
        raise ValueError("M1: unexpected alice_id")
    alice_epk = m1["alice_epk"]
    alice_sid = m1["alice_sid"]

    send_message(sock_b, encode_m1(PROTOCOL_ID, alice_id, alice_sid, m2b_pub))

    m2_raw = receive_message(sock_b)
    m2     = decode_m2(m2_raw)
    if m2["protocol_id"] != PROTOCOL_ID:
        raise ValueError("M2: wrong protocol_id")
    if m2["bob_id"] != bob_id:
        raise ValueError("M2: unexpected bob_id")
    bob_epk = m2["bob_epk"]
    bob_sid = m2["bob_sid"]

    send_message(sock_a, encode_m2(PROTOCOL_ID, bob_id, alice_sid, bob_sid, m2a_pub))

    # Each side computes a different transcript because each received Mallory's key,
    # not the peer's real ephemeral key.
    alice_t_hash = transcript_hash(
        pack_canonical_transcript(alice_id, bob_id, alice_sid, bob_sid, alice_epk, m2a_pub))
    bob_t_hash = transcript_hash(
        pack_canonical_transcript(alice_id, bob_id, alice_sid, bob_sid, m2b_pub, bob_epk))

    log._emit("TRANSCRIPT_HASHES",
              alice_side_t_hash=alice_t_hash.hex(),
              bob_side_t_hash=bob_t_hash.hex(),
              hashes_differ=(alice_t_hash != bob_t_hash))

    m3_raw = receive_message(sock_a)
    m3     = decode_m3(m3_raw)

    if not args.insecure_demo:
        # Alice's M3 signature is valid over alice_t_hash, but Bob will check it against
        # bob_t_hash — a different hash.  Even with Alice's public key, we cannot produce
        # a signature that verifies on Bob's side, because we hold neither long-term key.
        log._emit("FAILED",
                  reason="authenticated mode: M3 cannot verify at Bob (transcript mismatch)",
                  alice_t_hash=alice_t_hash.hex(),
                  bob_t_hash=bob_t_hash.hex())
        raise ValueError("authenticated mode: aborting before forwarding M3 (cannot produce valid sig)")

    send_message(sock_b, encode_m3(m3["signature"]))

    m4_raw = receive_message(sock_b)
    m4     = decode_m4(m4_raw)
    send_message(sock_a, encode_m4(m4["signature"]))

    # Derive four independent keys — two per leg.  k_a2m/k_m2a key the Alice↔Mallory
    # leg; k_m2b/k_b2m key the Mallory↔Bob leg.  Each leg needs its own record layer
    # with its own counters; sharing a single layer across legs would reuse nonces.
    secret_a = compute_shared_secret(m2a_priv, alice_epk)
    secret_b = compute_shared_secret(m2b_priv, bob_epk)
    k_a2m, k_m2a = derive_traffic_keys(secret_a, alice_t_hash)
    k_m2b, k_b2m = derive_traffic_keys(secret_b, bob_t_hash)

    log._emit("MALLORY_KEYS",
              k_alice_to_mallory_fp=k_a2m[:8].hex(),
              k_mallory_to_alice_fp=k_m2a[:8].hex(),
              k_mallory_to_bob_fp=k_m2b[:8].hex(),
              k_bob_to_mallory_fp=k_b2m[:8].hex())

    rl_alice = ApplicationRecordLayer(send_key=k_m2a, receive_key=k_a2m)
    rl_bob   = ApplicationRecordLayer(send_key=k_m2b, receive_key=k_b2m)

    for i in range(3):
        raw   = receive_message(sock_a)
        frame = decode_app_record(raw)
        try:
            pt = rl_alice.open(frame["ct"], frame["counter"],
                               alice_id, bob_id, alice_sid, bob_sid)
        except RecordError as exc:
            log.record_rejected(f"{alice_id.decode()}→mallory", frame["counter"], str(exc))
            raise

        log._emit("MALLORY_READ",
                  direction=f"{alice_id.decode()}→mallory→{bob_id.decode()}",
                  counter=frame["counter"],
                  plaintext_seen=pt.decode(errors="replace"))

        modified = pt + b" [intercepted by Mallory]"
        ct_out, ctr_out = rl_bob.seal(modified, alice_id, bob_id, alice_sid, bob_sid)
        send_message(sock_b, encode_app_record(ctr_out, ct_out))

        raw   = receive_message(sock_b)
        frame = decode_app_record(raw)
        try:
            pt_b = rl_bob.open(frame["ct"], frame["counter"],
                               bob_id, alice_id, alice_sid, bob_sid)
        except RecordError as exc:
            log.record_rejected(f"{bob_id.decode()}→mallory", frame["counter"], str(exc))
            raise

        log._emit("MALLORY_READ",
                  direction=f"{bob_id.decode()}→mallory→{alice_id.decode()}",
                  counter=frame["counter"],
                  plaintext_seen=pt_b.decode(errors="replace"))

        ct_out2, ctr_out2 = rl_alice.seal(pt_b, bob_id, alice_id, alice_sid, bob_sid)
        send_message(sock_a, encode_app_record(ctr_out2, ct_out2))

    log._emit("SUCCESS", outcome="MITM_SESSION_COMPLETE", records_intercepted=3)


def main():
    ap = argparse.ArgumentParser(description="Mallory — MITM relay (TR-2 only)")
    ap.add_argument("--listen-port", type=int, default=6531,
                    help="Port Alice connects to (Mallory listens here)")
    ap.add_argument("--bob-host",    default="127.0.0.1")
    ap.add_argument("--bob-port",    type=int, default=6530)
    ap.add_argument("--alice-id",    required=True)
    ap.add_argument("--bob-id",      required=True)
    ap.add_argument("--trial-dir",   default="evidence/tr2_mitm")
    ap.add_argument("--insecure-demo", action="store_true")
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
