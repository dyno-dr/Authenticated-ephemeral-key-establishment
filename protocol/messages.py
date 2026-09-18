# protocol/messages.py — M1–M4 and application-record wire serialisation (JSON + hex)

import json

from .constants import (
    MSG_M1, MSG_M2, MSG_M3, MSG_M4, MSG_APP_RECORD,
    FIELD_SID, FIELD_EPHEMERAL_PK, FIELD_SIGNATURE, FIELD_PROTOCOL_ID, FIELD_PEER_ID,
)


class MessageError(Exception):
    """Raised when a received message is malformed or has the wrong type tag."""


# Every wire message is: 1-byte type tag || UTF-8 JSON payload.
# Binary fields travel as lowercase hex strings inside JSON.
# Callers are responsible for decoding hex back to raw bytes before any
# cryptographic use (hash, sign, AAD) — never feed hex strings to crypto.

def _encode(msg_type: int, fields: dict) -> bytes:
    payload = json.dumps(fields, separators=(",", ":")).encode()
    return bytes([msg_type]) + payload


def _decode(raw: bytes, expected_type: int) -> dict:
    if len(raw) < 2:
        raise MessageError("message too short")
    if raw[0] != expected_type:
        raise MessageError(f"wrong message type: got {raw[0]}, expected {expected_type}")
    try:
        return json.loads(raw[1:])
    except json.JSONDecodeError as exc:
        raise MessageError("JSON decode error") from exc


def _require_hex(d: dict, key: str, expected_len: int) -> bytes:
    if key not in d:
        raise MessageError(f"missing field '{key}'")
    try:
        value = bytes.fromhex(d[key])
    except (ValueError, TypeError) as exc:
        raise MessageError(f"field '{key}' is not valid hex") from exc
    if len(value) != expected_len:
        raise MessageError(f"field '{key}': expected {expected_len}B, got {len(value)}B")
    return value


def _require_str(d: dict, key: str) -> str:
    if key not in d:
        raise MessageError(f"missing field '{key}'")
    if not isinstance(d[key], str):
        raise MessageError(f"field '{key}' must be a string")
    return d[key]


def _require_int(d: dict, key: str) -> int:
    if key not in d:
        raise MessageError(f"missing field '{key}'")
    if not isinstance(d[key], int):
        raise MessageError(f"field '{key}' must be an integer")
    return d[key]


# M1: Alice → Bob: alice_id, alice_sid, alice_ephemeral_pk (+ protocol_id for validation)

def encode_m1(protocol_id: bytes, alice_id: bytes, alice_sid: bytes, alice_epk: bytes) -> bytes:
    return _encode(MSG_M1, {
        "protocol_id": protocol_id.hex(),
        "alice_id":    alice_id.hex(),
        "alice_sid":   alice_sid.hex(),
        "alice_epk":   alice_epk.hex(),
    })


def decode_m1(raw: bytes) -> dict:
    d = _decode(raw, MSG_M1)
    return {
        "protocol_id": _require_hex(d, "protocol_id", FIELD_PROTOCOL_ID),
        "alice_id":    _require_hex(d, "alice_id",    FIELD_PEER_ID),
        "alice_sid":   _require_hex(d, "alice_sid",   FIELD_SID),
        "alice_epk":   _require_hex(d, "alice_epk",   FIELD_EPHEMERAL_PK),
    }


# M2: Bob → Alice: bob_id, echoed alice_sid, bob_sid, bob_ephemeral_pk

def encode_m2(
    protocol_id: bytes, bob_id: bytes,
    alice_sid: bytes, bob_sid: bytes, bob_epk: bytes,
) -> bytes:
    return _encode(MSG_M2, {
        "protocol_id": protocol_id.hex(),
        "bob_id":      bob_id.hex(),
        "alice_sid":   alice_sid.hex(),
        "bob_sid":     bob_sid.hex(),
        "bob_epk":     bob_epk.hex(),
    })


def decode_m2(raw: bytes) -> dict:
    d = _decode(raw, MSG_M2)
    return {
        "protocol_id": _require_hex(d, "protocol_id", FIELD_PROTOCOL_ID),
        "bob_id":      _require_hex(d, "bob_id",      FIELD_PEER_ID),
        "alice_sid":   _require_hex(d, "alice_sid",   FIELD_SID),
        "bob_sid":     _require_hex(d, "bob_sid",     FIELD_SID),
        "bob_epk":     _require_hex(d, "bob_epk",     FIELD_EPHEMERAL_PK),
    }


# M3: Alice → Bob: Alice's Ed25519 signature over Transcript_Hash

def encode_m3(signature: bytes) -> bytes:
    return _encode(MSG_M3, {"signature": signature.hex()})


def decode_m3(raw: bytes) -> dict:
    d = _decode(raw, MSG_M3)
    return {"signature": _require_hex(d, "signature", FIELD_SIGNATURE)}


# M4: Bob → Alice: Bob's Ed25519 signature over Transcript_Hash

def encode_m4(signature: bytes) -> bytes:
    return _encode(MSG_M4, {"signature": signature.hex()})


def decode_m4(raw: bytes) -> dict:
    d = _decode(raw, MSG_M4)
    return {"signature": _require_hex(d, "signature", FIELD_SIGNATURE)}


# Application record: counter (uint64) + AES-256-GCM ciphertext+tag

def encode_app_record(counter: int, ciphertext_with_tag: bytes) -> bytes:
    return _encode(MSG_APP_RECORD, {
        "counter": counter,
        "ct":      ciphertext_with_tag.hex(),
    })


def decode_app_record(raw: bytes) -> dict:
    d = _decode(raw, MSG_APP_RECORD)
    counter = _require_int(d, "counter")
    if not (0 <= counter < 2**64):
        raise MessageError("counter out of range")
    return {
        "counter": counter,
        "ct":      bytes.fromhex(_require_str(d, "ct")),
    }
