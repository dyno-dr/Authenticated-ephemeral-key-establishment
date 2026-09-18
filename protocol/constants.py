# protocol/constants.py — field sizes, identifiers, and canonical transcript packing

import hashlib

PROTOCOL_ID = b"CS6530-A2-v1"   # 12 bytes

# Field sizes in bytes
FIELD_PROTOCOL_ID    = 12
FIELD_PEER_ID        = 8
FIELD_SID            = 16
FIELD_EPHEMERAL_PK   = 32
FIELD_SIGNATURE      = 64
FIELD_COUNTER        = 8
FIELD_NONCE_PREFIX   = 4
FIELD_NONCE          = 12   # 4-byte prefix + 8-byte counter
FIELD_TRANSCRIPT_HASH = 32

CANONICAL_TRANSCRIPT_LEN = 124  # 12+8+8+16+16+32+32

# HKDF info strings — must match exactly on both sides
HKDF_INFO_A2B = b"CS6530-A2 Alice->Bob"
HKDF_INFO_B2A = b"CS6530-A2 Bob->Alice"
HKDF_KEY_LEN  = 32

# Network defaults
DEFAULT_PORT = 6530

# Wire message type tags
MSG_M1         = 1
MSG_M2         = 2
MSG_M3         = 3
MSG_M4         = 4
MSG_APP_RECORD = 5


def pack_canonical_transcript(
    alice_id: bytes,
    bob_id: bytes,
    alice_sid: bytes,
    bob_sid: bytes,
    alice_epk: bytes,
    bob_epk: bytes,
) -> bytes:
    """Return the 124-byte canonical transcript used for hashing and signing.

    Field order is fixed by the spec; any deviation causes both sides to
    compute different hashes even without an attacker involved.
    """
    assert len(alice_id)  == FIELD_PEER_ID,      f"alice_id must be {FIELD_PEER_ID}B"
    assert len(bob_id)    == FIELD_PEER_ID,      f"bob_id must be {FIELD_PEER_ID}B"
    assert len(alice_sid) == FIELD_SID,          f"alice_sid must be {FIELD_SID}B"
    assert len(bob_sid)   == FIELD_SID,          f"bob_sid must be {FIELD_SID}B"
    assert len(alice_epk) == FIELD_EPHEMERAL_PK, f"alice_epk must be {FIELD_EPHEMERAL_PK}B"
    assert len(bob_epk)   == FIELD_EPHEMERAL_PK, f"bob_epk must be {FIELD_EPHEMERAL_PK}B"

    transcript = PROTOCOL_ID + alice_id + bob_id + alice_sid + bob_sid + alice_epk + bob_epk
    assert len(transcript) == CANONICAL_TRANSCRIPT_LEN
    return transcript


def transcript_hash(transcript: bytes) -> bytes:
    """SHA-256 of the canonical transcript."""
    return hashlib.sha256(transcript).digest()
