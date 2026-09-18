import pytest
from protocol.record_layer import ApplicationRecordLayer, RecordError

ALICE_ID  = b"AL000001"
BOB_ID    = b"BO000001"
ALICE_SID = b"\xaa" * 16
BOB_SID   = b"\xbb" * 16

# Two distinct 32-byte keys (AES-256)
KEY_A2B = b"\x01" * 32
KEY_B2A = b"\x02" * 32


def alice_layer():
    return ApplicationRecordLayer(send_key=KEY_A2B, receive_key=KEY_B2A)


def bob_layer():
    return ApplicationRecordLayer(send_key=KEY_B2A, receive_key=KEY_A2B)


def test_seal_open_roundtrip():
    a = alice_layer()
    b = bob_layer()
    pt = b"hello from Alice"
    ct, ctr = a.seal(pt, ALICE_ID, BOB_ID, ALICE_SID, BOB_SID)
    recovered = b.open(ct, ctr, ALICE_ID, BOB_ID, ALICE_SID, BOB_SID)
    assert recovered == pt


def test_multiple_records_counters_increment():
    a = alice_layer()
    b = bob_layer()
    for i in range(3):
        ct, ctr = a.seal(f"msg{i}".encode(), ALICE_ID, BOB_ID, ALICE_SID, BOB_SID)
        assert ctr == i
        b.open(ct, ctr, ALICE_ID, BOB_ID, ALICE_SID, BOB_SID)
    assert a.send_counter == 3
    assert b.receive_counter == 3


def test_bidirectional_counters_are_independent():
    a = alice_layer()
    b = bob_layer()
    # Alice sends 2, Bob sends 1 — counters don't interfere
    for _ in range(2):
        ct, ctr = a.seal(b"a->b", ALICE_ID, BOB_ID, ALICE_SID, BOB_SID)
        b.open(ct, ctr, ALICE_ID, BOB_ID, ALICE_SID, BOB_SID)
    ct, ctr = b.seal(b"b->a", BOB_ID, ALICE_ID, ALICE_SID, BOB_SID)
    a.open(ct, ctr, BOB_ID, ALICE_ID, ALICE_SID, BOB_SID)
    assert a.send_counter == 2
    assert b.send_counter == 1


def test_replay_stale_counter_rejected():
    a = alice_layer()
    b = bob_layer()
    ct, ctr = a.seal(b"record0", ALICE_ID, BOB_ID, ALICE_SID, BOB_SID)
    b.open(ct, ctr, ALICE_ID, BOB_ID, ALICE_SID, BOB_SID)
    # Replay: same ciphertext, same counter=0, but receive_counter is now 1
    with pytest.raises(RecordError, match="stale"):
        b.open(ct, ctr, ALICE_ID, BOB_ID, ALICE_SID, BOB_SID)


def test_tampered_ciphertext_rejected():
    a = alice_layer()
    b = bob_layer()
    ct, ctr = a.seal(b"secret", ALICE_ID, BOB_ID, ALICE_SID, BOB_SID)
    tampered = bytearray(ct)
    tampered[0] ^= 0xFF
    with pytest.raises(RecordError, match="AEAD"):
        b.open(bytes(tampered), ctr, ALICE_ID, BOB_ID, ALICE_SID, BOB_SID)


def test_tampered_aad_rejected():
    # Changing any AAD field (here: wrong sender_id) must cause AEAD failure
    a = alice_layer()
    b = bob_layer()
    ct, ctr = a.seal(b"secret", ALICE_ID, BOB_ID, ALICE_SID, BOB_SID)
    with pytest.raises(RecordError, match="AEAD"):
        b.open(ct, ctr, BOB_ID, ALICE_ID, ALICE_SID, BOB_SID)  # swapped IDs


def test_wrong_counter_in_open_rejected():
    a = alice_layer()
    b = bob_layer()
    ct, _ = a.seal(b"data", ALICE_ID, BOB_ID, ALICE_SID, BOB_SID)
    with pytest.raises(RecordError, match="stale"):
        b.open(ct, 99, ALICE_ID, BOB_ID, ALICE_SID, BOB_SID)


def test_send_and_receive_keys_must_differ():
    with pytest.raises(AssertionError):
        ApplicationRecordLayer(send_key=KEY_A2B, receive_key=KEY_A2B)


def test_counter_not_advanced_on_aead_failure():
    """The ordering-bug regression test (blueprint §7.3 / §13.1).

    A forged record at the expected counter must not consume that counter slot.
    The legitimate record at the same counter must still be accepted afterward.
    """
    a = alice_layer()
    b = bob_layer()

    # Alice seals a legitimate record (counter 0)
    ct_legit, ctr = a.seal(b"legitimate", ALICE_ID, BOB_ID, ALICE_SID, BOB_SID)
    assert ctr == 0

    # Attacker injects a forged record at counter 0 (right counter value, wrong tag)
    forged = bytearray(ct_legit)
    forged[-1] ^= 0xFF   # corrupt the GCM tag
    with pytest.raises(RecordError, match="AEAD"):
        b.open(bytes(forged), 0, ALICE_ID, BOB_ID, ALICE_SID, BOB_SID)

    # receive_counter must still be 0 — the forgery must not have consumed the slot
    assert b.receive_counter == 0

    # The legitimate record must now be accepted
    recovered = b.open(ct_legit, 0, ALICE_ID, BOB_ID, ALICE_SID, BOB_SID)
    assert recovered == b"legitimate"
    assert b.receive_counter == 1
