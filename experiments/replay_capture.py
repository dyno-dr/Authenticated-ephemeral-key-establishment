#!/usr/bin/env python3
# experiments/replay_capture.py — TR-3: replay rejection and authenticate-before-advance

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from experiments import loopback_handshake
from protocol.record_layer import ApplicationRecordLayer, RecordError
from protocol.messages import encode_app_record, decode_app_record
from protocol.identity import generate_and_save_keypair
from evidence_logger import EvidenceLogger

ALICE_ID = b"AL000001"
BOB_ID   = b"BO000001"


def run(log):
    with tempfile.TemporaryDirectory() as d:
        a_lt_sk, a_lt_pk = generate_and_save_keypair(f"{d}/alice")
        b_lt_sk, b_lt_pk = generate_and_save_keypair(f"{d}/bob")

    hs_a, hs_b = loopback_handshake(a_lt_sk, b_lt_sk, a_lt_pk, b_lt_pk, ALICE_ID, BOB_ID)
    alice_sid = hs_a.alice_sid
    bob_sid   = hs_a.bob_sid
    direction = f"{ALICE_ID.decode()}→{BOB_ID.decode()}"

    log._emit("SESSION",
              alice_sid=alice_sid.hex(),
              bob_sid=bob_sid.hex(),
              k_a2b_fp=hs_a.k_alice_to_bob[:8].hex(),
              k_b2a_fp=hs_a.k_bob_to_alice[:8].hex())

    rl_a = ApplicationRecordLayer(send_key=hs_a.k_alice_to_bob, receive_key=hs_a.k_bob_to_alice)
    rl_b = ApplicationRecordLayer(send_key=hs_b.k_bob_to_alice, receive_key=hs_b.k_alice_to_bob)

    # Experiment A: replay rejected on stale counter

    # Send and accept records at counters 0 and 1; capture counter-0 wire frame.
    captured_wire = None
    for i in range(2):
        pt  = f"record {i}".encode()
        ct, ctr = rl_a.seal(pt, ALICE_ID, BOB_ID, alice_sid, bob_sid)
        wire = encode_app_record(ctr, ct)
        if i == 0:
            captured_wire = wire   # byte-exact copy; tag is valid and untouched
        frame = decode_app_record(wire)
        rpt = rl_b.open(frame["ct"], frame["counter"], ALICE_ID, BOB_ID, alice_sid, bob_sid)
        log.record_received(direction, frame["counter"], rpt, frame["ct"])

    # Bob's receive_counter is now 2. Replay counter-0 — the GCM tag is still
    # cryptographically valid, but the counter check fires first.
    frame0 = decode_app_record(captured_wire)
    try:
        rl_b.open(frame0["ct"], frame0["counter"], ALICE_ID, BOB_ID, alice_sid, bob_sid)
        log._emit("UNEXPECTED_SUCCESS", counter=frame0["counter"])
    except RecordError as exc:
        log.record_rejected(f"{direction} (REPLAY)", frame0["counter"], str(exc))
        # receive_counter must be unchanged — replay consumed no state
        log._emit("REPLAY_COUNTER_STATE",
                  receive_counter=rl_b.receive_counter,
                  unchanged=(rl_b.receive_counter == 2))

    # Experiment B: authenticate-before-advance

    # Fresh independent keys for this sub-test so nonces from Experiment A don't repeat.
    k_send, k_recv = os.urandom(32), os.urandom(32)
    rl_x = ApplicationRecordLayer(send_key=k_send, receive_key=k_recv)
    rl_y = ApplicationRecordLayer(send_key=k_recv, receive_key=k_send)

    pt_real = b"legitimate record 0"
    ct_real, _ = rl_x.seal(pt_real, ALICE_ID, BOB_ID, alice_sid, bob_sid)
    ct_garbage  = bytes(b ^ 0xff for b in ct_real)   # flip all bits; counter value unchanged

    # Garbage at counter 0: AEAD fails, counter must NOT advance.
    try:
        rl_y.open(ct_garbage, 0, ALICE_ID, BOB_ID, alice_sid, bob_sid)
        log._emit("UNEXPECTED_SUCCESS", outcome="garbage_accepted")
    except RecordError as exc:
        log._emit("REJECTED",
                  outcome="GARBAGE_AT_COUNTER_0",
                  counter=0,
                  reason=str(exc),
                  receive_counter_after=rl_y.receive_counter)

    assert rl_y.receive_counter == 0, "BUG: counter advanced on AEAD failure"

    # Real record at counter 0 now succeeds — slot was not consumed by the garbage.
    pt_got = rl_y.open(ct_real, 0, ALICE_ID, BOB_ID, alice_sid, bob_sid)
    log._emit("SUCCESS",
              outcome="LEGITIMATE_RECORD_ACCEPTED_AFTER_GARBAGE",
              counter=0,
              plaintext=pt_got.decode(),
              receive_counter_after=rl_y.receive_counter)


def main():
    log = EvidenceLogger("evidence/tr3_replay", "replay")
    try:
        run(log)
    except Exception as exc:
        log.abort(str(exc))
        sys.exit(f"[tr3] error: {exc}")
    finally:
        log.close()
    print("[tr3] replay demonstration complete", flush=True)


if __name__ == "__main__":
    main()
