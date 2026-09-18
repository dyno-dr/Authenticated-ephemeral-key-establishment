# evidence_logger.py — structured SUCCESS/FAILED/REJECTED event log for all trial runs

import json
import time
from pathlib import Path


def _fp(b: bytes, n: int = 8) -> str:
    """First n bytes as hex — a compact fingerprint for log comparison."""
    return b[:n].hex()


def _nonce_hex(counter: int) -> str:
    return (b"\x00\x00\x00\x00" + counter.to_bytes(8, "big")).hex()


class EvidenceLogger:
    """Writes one JSONL file per role into the trial directory, and echoes to stdout."""

    def __init__(self, trial_dir: str, role: str):
        p = Path(trial_dir)
        p.mkdir(parents=True, exist_ok=True)
        self._role = role
        self._f = (p / f"{role}.jsonl").open("w")

    def _emit(self, event: str, **fields) -> None:
        rec = {
            "ts":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "role":  self._role,
            "event": event,
            **fields,
        }
        self._f.write(json.dumps(rec) + "\n")
        self._f.flush()
        print(json.dumps(rec), flush=True)

    def handshake_ok(self, alice_id: bytes, bob_id: bytes,
                     alice_sid: bytes, bob_sid: bytes,
                     shared_secret: bytes, k_a2b: bytes, k_b2a: bytes) -> None:
        self._emit("HANDSHAKE_OK",
                   alice_id=alice_id.decode(),
                   bob_id=bob_id.decode(),
                   alice_sid=alice_sid.hex(),
                   bob_sid=bob_sid.hex(),
                   shared_secret_fp=_fp(shared_secret),
                   k_a2b_fp=_fp(k_a2b),
                   k_b2a_fp=_fp(k_b2a))

    def record_sent(self, direction: str, counter: int,
                    plaintext: bytes, ciphertext_with_tag: bytes) -> None:
        self._emit("SUCCESS",
                   outcome="RECORD_SENT",
                   direction=direction,
                   counter=counter,
                   nonce=_nonce_hex(counter),
                   plaintext=plaintext.decode(errors="replace"),
                   tag_fp=_fp(ciphertext_with_tag[-16:]))

    def record_received(self, direction: str, counter: int,
                        plaintext: bytes, ciphertext_with_tag: bytes) -> None:
        self._emit("SUCCESS",
                   outcome="RECORD_RECEIVED",
                   direction=direction,
                   counter=counter,
                   nonce=_nonce_hex(counter),
                   plaintext=plaintext.decode(errors="replace"),
                   tag_fp=_fp(ciphertext_with_tag[-16:]))

    def record_rejected(self, direction: str, counter: int, reason: str) -> None:
        self._emit("REJECTED",
                   direction=direction,
                   counter=counter,
                   reason=reason)

    def abort(self, reason: str) -> None:
        self._emit("FAILED", reason=reason)

    def close(self) -> None:
        self._f.close()
