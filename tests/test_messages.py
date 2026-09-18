import json

import pytest
from protocol.messages import (
    encode_m1, decode_m1,
    encode_m2, decode_m2,
    encode_m3, decode_m3,
    encode_m4, decode_m4,
    encode_app_record, decode_app_record,
    MessageError,
)
from protocol.constants import PROTOCOL_ID

ALICE_ID  = b"AL000001"
BOB_ID    = b"BO000001"
ALICE_SID = b"\xaa" * 16
BOB_SID   = b"\xbb" * 16
ALICE_EPK = b"\xcc" * 32
BOB_EPK   = b"\xdd" * 32
SIG       = b"\xee" * 64


def test_m1_roundtrip():
    raw = encode_m1(PROTOCOL_ID, ALICE_ID, ALICE_SID, ALICE_EPK)
    d   = decode_m1(raw)
    assert d["protocol_id"] == PROTOCOL_ID
    assert d["alice_id"]    == ALICE_ID
    assert d["alice_sid"]   == ALICE_SID
    assert d["alice_epk"]   == ALICE_EPK


def test_m1_fields_are_raw_bytes():
    d = decode_m1(encode_m1(PROTOCOL_ID, ALICE_ID, ALICE_SID, ALICE_EPK))
    for v in d.values():
        assert isinstance(v, bytes)


def test_m2_roundtrip():
    raw = encode_m2(PROTOCOL_ID, BOB_ID, ALICE_SID, BOB_SID, BOB_EPK)
    d   = decode_m2(raw)
    assert d["protocol_id"] == PROTOCOL_ID
    assert d["bob_id"]      == BOB_ID
    assert d["alice_sid"]   == ALICE_SID
    assert d["bob_sid"]     == BOB_SID
    assert d["bob_epk"]     == BOB_EPK


def test_m3_roundtrip():
    d = decode_m3(encode_m3(SIG))
    assert d["signature"] == SIG


def test_m4_roundtrip():
    d = decode_m4(encode_m4(SIG))
    assert d["signature"] == SIG


def test_app_record_roundtrip():
    ct  = b"\x12" * 48
    raw = encode_app_record(7, ct)
    d   = decode_app_record(raw)
    assert d["counter"] == 7
    assert d["ct"]      == ct


def test_wrong_type_tag_raises():
    raw = encode_m1(PROTOCOL_ID, ALICE_ID, ALICE_SID, ALICE_EPK)
    with pytest.raises(MessageError, match="wrong message type"):
        decode_m2(raw)


def test_m2_echoed_alice_sid_matches():
    d = decode_m2(encode_m2(PROTOCOL_ID, BOB_ID, ALICE_SID, BOB_SID, BOB_EPK))
    assert d["alice_sid"] == ALICE_SID


def test_decoded_binary_fields_have_correct_lengths():
    d = decode_m1(encode_m1(PROTOCOL_ID, ALICE_ID, ALICE_SID, ALICE_EPK))
    assert len(d["alice_id"])  == 8
    assert len(d["alice_epk"]) == 32
    assert len(d["alice_sid"]) == 16


def test_missing_field_raises():
    payload = json.dumps({"protocol_id": PROTOCOL_ID.hex(),
                          "alice_id":    ALICE_ID.hex(),
                          "alice_sid":   ALICE_SID.hex()}).encode()
    with pytest.raises(MessageError, match="missing field"):
        decode_m1(bytes([1]) + payload)


def test_wrong_field_length_raises():
    payload = json.dumps({"protocol_id": PROTOCOL_ID.hex(),
                          "alice_id":    ALICE_ID.hex(),
                          "alice_sid":   (b"\xaa" * 8).hex(),
                          "alice_epk":   ALICE_EPK.hex()}).encode()
    with pytest.raises(MessageError):
        decode_m1(bytes([1]) + payload)


def test_app_record_counter_preserved():
    for ctr in [0, 1, 255, 2**32, 2**64 - 1]:
        d = decode_app_record(encode_app_record(ctr, b"\x00" * 17))
        assert d["counter"] == ctr
