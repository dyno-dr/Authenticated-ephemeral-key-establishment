import pytest
from protocol.constants import (
    PROTOCOL_ID, CANONICAL_TRANSCRIPT_LEN,
    FIELD_PROTOCOL_ID, FIELD_PEER_ID, FIELD_SID, FIELD_EPHEMERAL_PK,
    FIELD_NONCE, FIELD_NONCE_PREFIX, FIELD_COUNTER,
    HKDF_INFO_A2B, HKDF_INFO_B2A, HKDF_KEY_LEN,
    MSG_M1, MSG_M2, MSG_M3, MSG_M4, MSG_APP_RECORD,
    pack_canonical_transcript, transcript_hash,
)

ALICE_ID  = b"AL000001"
BOB_ID    = b"BO000001"
ALICE_SID = b"\x01" * 16
BOB_SID   = b"\x02" * 16
ALICE_EPK = b"\x03" * 32
BOB_EPK   = b"\x04" * 32


def test_protocol_id():
    assert PROTOCOL_ID == b"CS6530-A2-v1"
    assert len(PROTOCOL_ID) == 12


def test_canonical_transcript_length():
    t = pack_canonical_transcript(ALICE_ID, BOB_ID, ALICE_SID, BOB_SID, ALICE_EPK, BOB_EPK)
    assert len(t) == CANONICAL_TRANSCRIPT_LEN == 124


def test_canonical_transcript_field_order():
    # The transcript must start with PROTOCOL_ID, then alice_id, then bob_id …
    t = pack_canonical_transcript(ALICE_ID, BOB_ID, ALICE_SID, BOB_SID, ALICE_EPK, BOB_EPK)
    assert t[:12]    == PROTOCOL_ID
    assert t[12:20]  == ALICE_ID
    assert t[20:28]  == BOB_ID
    assert t[28:44]  == ALICE_SID
    assert t[44:60]  == BOB_SID
    assert t[60:92]  == ALICE_EPK
    assert t[92:124] == BOB_EPK


def test_swapping_alice_bob_id_changes_transcript():
    t1 = pack_canonical_transcript(ALICE_ID, BOB_ID,   ALICE_SID, BOB_SID, ALICE_EPK, BOB_EPK)
    t2 = pack_canonical_transcript(BOB_ID,   ALICE_ID, ALICE_SID, BOB_SID, ALICE_EPK, BOB_EPK)
    assert t1 != t2


def test_swapping_sids_changes_transcript():
    t1 = pack_canonical_transcript(ALICE_ID, BOB_ID, ALICE_SID, BOB_SID, ALICE_EPK, BOB_EPK)
    t2 = pack_canonical_transcript(ALICE_ID, BOB_ID, BOB_SID,   ALICE_SID, ALICE_EPK, BOB_EPK)
    assert t1 != t2


def test_swapping_epks_changes_transcript():
    t1 = pack_canonical_transcript(ALICE_ID, BOB_ID, ALICE_SID, BOB_SID, ALICE_EPK, BOB_EPK)
    t2 = pack_canonical_transcript(ALICE_ID, BOB_ID, ALICE_SID, BOB_SID, BOB_EPK,   ALICE_EPK)
    assert t1 != t2


def test_transcript_hash_is_32_bytes():
    t = pack_canonical_transcript(ALICE_ID, BOB_ID, ALICE_SID, BOB_SID, ALICE_EPK, BOB_EPK)
    h = transcript_hash(t)
    assert len(h) == 32


def test_transcript_hash_deterministic():
    t = pack_canonical_transcript(ALICE_ID, BOB_ID, ALICE_SID, BOB_SID, ALICE_EPK, BOB_EPK)
    assert transcript_hash(t) == transcript_hash(t)


def test_hkdf_info_strings_distinct():
    assert HKDF_INFO_A2B != HKDF_INFO_B2A


def test_nonce_layout():
    assert FIELD_NONCE == 12
    assert FIELD_NONCE_PREFIX + FIELD_COUNTER == 12


def test_message_type_tags_unique():
    tags = [MSG_M1, MSG_M2, MSG_M3, MSG_M4, MSG_APP_RECORD]
    assert len(set(tags)) == len(tags)


def test_field_sizes():
    assert FIELD_PROTOCOL_ID    == 12
    assert FIELD_PEER_ID        == 8
    assert FIELD_SID            == 16
    assert FIELD_EPHEMERAL_PK   == 32
    assert HKDF_KEY_LEN         == 32


def test_wrong_field_length_raises():
    with pytest.raises(AssertionError):
        pack_canonical_transcript(b"SHORT", BOB_ID, ALICE_SID, BOB_SID, ALICE_EPK, BOB_EPK)
