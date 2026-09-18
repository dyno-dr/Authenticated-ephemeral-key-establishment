#!/usr/bin/env python3
# roles/bob.py — Bob CLI: handshake + 3-record request-response session

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from transport import accept_peer, send_message, receive_message
from protocol.handshake import bob_handshake, HandshakeError
from protocol.identity import (
    generate_and_save_keypair, load_private_key, load_public_key,
)
from protocol.record_layer import ApplicationRecordLayer, RecordError
from protocol.messages import encode_app_record, decode_app_record
from evidence_logger import EvidenceLogger


def main():
    ap = argparse.ArgumentParser(description="Bob — authenticated session responder")
    ap.add_argument("--port",      type=int, default=6530)
    ap.add_argument("--alice-id",  required=True, help="8-char roll number")
    ap.add_argument("--bob-id",    required=True, help="8-char roll number")
    ap.add_argument("--key-stem",  required=True, help="path stem for Bob's keypair")
    ap.add_argument("--alice-pub", required=True, help="path to Alice's public key (.pub)")
    ap.add_argument("--trial-dir", default="evidence/tr1_normal_session")
    ap.add_argument("--insecure-demo", action="store_true")
    args = ap.parse_args()

    alice_id = args.alice_id.encode()
    bob_id   = args.bob_id.encode()
    if len(alice_id) != 8 or len(bob_id) != 8:
        sys.exit("alice-id and bob-id must each be exactly 8 ASCII characters")

    key_path = Path(args.key_stem)
    if not key_path.with_suffix(".key").exists():
        print(f"[bob] generating keypair at {args.key_stem}.*", flush=True)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        bob_lt_sk, _ = generate_and_save_keypair(args.key_stem)
    else:
        bob_lt_sk = load_private_key(str(key_path.with_suffix(".key")))

    alice_lt_pk = load_public_key(args.alice_pub)

    log = EvidenceLogger(args.trial_dir, "bob")
    direction_send = f"{args.bob_id}→{args.alice_id}"
    direction_recv = f"{args.alice_id}→{args.bob_id}"

    print(f"[bob] listening on port {args.port}…", flush=True)
    sock, peer = accept_peer(args.port)
    print(f"[bob] connected from {peer}", flush=True)

    try:
        hs = bob_handshake(sock, alice_id, bob_id, bob_lt_sk, alice_lt_pk,
                           insecure_demo=args.insecure_demo)

        log.handshake_ok(alice_id, bob_id, hs.alice_sid, hs.bob_sid,
                         hs.shared_secret, hs.k_alice_to_bob, hs.k_bob_to_alice)

        rl = ApplicationRecordLayer(
            send_key=hs.k_bob_to_alice,
            receive_key=hs.k_alice_to_bob,
        )

        for i in range(3):
            raw   = receive_message(sock)
            frame = decode_app_record(raw)
            try:
                rpt = rl.open(frame["ct"], frame["counter"],
                              alice_id, bob_id, hs.alice_sid, hs.bob_sid)
                log.record_received(direction_recv, frame["counter"], rpt, frame["ct"])
            except RecordError as exc:
                log.record_rejected(direction_recv, frame["counter"], str(exc))
                raise

            pt  = f"Bob→Alice: reply {i}".encode()
            ct, ctr = rl.seal(pt, bob_id, alice_id, hs.alice_sid, hs.bob_sid)
            send_message(sock, encode_app_record(ctr, ct))
            log.record_sent(direction_send, ctr, pt, ct)

    except HandshakeError as exc:
        log.abort(str(exc))
        sys.exit(f"[bob] handshake failed: {exc}")
    except Exception as exc:
        log.abort(str(exc))
        sys.exit(f"[bob] error: {exc}")
    finally:
        log.close()
        try:
            sock.close()
        except Exception:
            pass

    print("[bob] session complete", flush=True)


if __name__ == "__main__":
    main()
