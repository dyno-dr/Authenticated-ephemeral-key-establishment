#!/usr/bin/env python3
# roles/alice.py — Alice CLI: handshake + 3-record request-response session

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from transport import connect_to_peer, send_message, receive_message
from protocol.handshake import alice_handshake, HandshakeError
from protocol.identity import (
    generate_and_save_keypair, load_private_key, load_public_key,
)
from protocol.record_layer import ApplicationRecordLayer, RecordError
from protocol.messages import encode_app_record, decode_app_record
from evidence_logger import EvidenceLogger


def main():
    ap = argparse.ArgumentParser(description="Alice — authenticated session initiator")
    ap.add_argument("host",                                 help="Bob's IP address")
    ap.add_argument("--port",       type=int, default=6530)
    ap.add_argument("--alice-id",   required=True,         help="8-char roll number")
    ap.add_argument("--bob-id",     required=True,         help="8-char roll number")
    ap.add_argument("--key-stem",   required=True,         help="path stem for Alice's keypair")
    ap.add_argument("--bob-pub",    required=True,         help="path to Bob's public key (.pub)")
    ap.add_argument("--trial-dir",  default="evidence/tr1_normal_session")
    ap.add_argument("--insecure-demo", action="store_true")
    args = ap.parse_args()

    alice_id = args.alice_id.encode()
    bob_id   = args.bob_id.encode()
    if len(alice_id) != 8 or len(bob_id) != 8:
        sys.exit("alice-id and bob-id must each be exactly 8 ASCII characters")

    key_path = Path(args.key_stem)
    if not key_path.with_suffix(".key").exists():
        print(f"[alice] generating keypair at {args.key_stem}.*", flush=True)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        alice_lt_sk, _ = generate_and_save_keypair(args.key_stem)
    else:
        alice_lt_sk = load_private_key(str(key_path.with_suffix(".key")))

    bob_lt_pk = load_public_key(args.bob_pub)

    log = EvidenceLogger(args.trial_dir, "alice")
    direction_send = f"{args.alice_id}→{args.bob_id}"
    direction_recv = f"{args.bob_id}→{args.alice_id}"

    try:
        sock = connect_to_peer(args.host, args.port)
        print(f"[alice] connected to {args.host}:{args.port}", flush=True)

        hs = alice_handshake(sock, alice_id, bob_id, alice_lt_sk, bob_lt_pk,
                             insecure_demo=args.insecure_demo)

        log.handshake_ok(alice_id, bob_id, hs.alice_sid, hs.bob_sid,
                         hs.shared_secret, hs.k_alice_to_bob, hs.k_bob_to_alice)

        rl = ApplicationRecordLayer(
            send_key=hs.k_alice_to_bob,
            receive_key=hs.k_bob_to_alice,
        )

        for i in range(3):
            pt  = f"Alice→Bob: message {i}".encode()
            ct, ctr = rl.seal(pt, alice_id, bob_id, hs.alice_sid, hs.bob_sid)
            send_message(sock, encode_app_record(ctr, ct))
            log.record_sent(direction_send, ctr, pt, ct)

            raw   = receive_message(sock)
            frame = decode_app_record(raw)
            try:
                rpt = rl.open(frame["ct"], frame["counter"],
                              bob_id, alice_id, hs.alice_sid, hs.bob_sid)
                log.record_received(direction_recv, frame["counter"], rpt, frame["ct"])
            except RecordError as exc:
                log.record_rejected(direction_recv, frame["counter"], str(exc))
                raise

    except HandshakeError as exc:
        log.abort(str(exc))
        sys.exit(f"[alice] handshake failed: {exc}")
    except Exception as exc:
        log.abort(str(exc))
        sys.exit(f"[alice] error: {exc}")
    finally:
        log.close()
        try:
            sock.close()
        except Exception:
            pass

    print("[alice] session complete", flush=True)


if __name__ == "__main__":
    main()
