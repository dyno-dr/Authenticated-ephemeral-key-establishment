"""Handshake loopback tests — no network required, socket.socketpair() only."""

import socket
import tempfile
import threading

import pytest
from protocol.handshake import HandshakeError, alice_handshake, bob_handshake
from protocol.identity import generate_and_save_keypair


def _run_both(alice_fn, bob_fn):
    """Run alice_fn and bob_fn in two threads on a socket pair. Return (a_result, b_result).

    Exceptions propagate to the calling thread so pytest catches them normally.
    """
    a_sock, b_sock = socket.socketpair()
    results = [None, None]
    errors  = [None, None]

    def run(idx, fn, sock):
        try:
            results[idx] = fn(sock)
        except Exception as exc:
            errors[idx] = exc
        finally:
            sock.close()

    ta = threading.Thread(target=run, args=(0, alice_fn, a_sock))
    tb = threading.Thread(target=run, args=(1, bob_fn,   b_sock))
    ta.start(); tb.start()
    ta.join();  tb.join()

    if errors[0]:
        raise errors[0]
    if errors[1]:
        raise errors[1]
    return results[0], results[1]


@pytest.fixture(scope="module")
def keypairs(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("keys"))
    a_priv, a_pub = generate_and_save_keypair(f"{d}/alice")
    b_priv, b_pub = generate_and_save_keypair(f"{d}/bob")
    return a_priv, a_pub, b_priv, b_pub

ALICE_ID = b"AL000001"
BOB_ID   = b"BO000001"


def test_loopback_identical_directional_keys(keypairs):
    """Both sides must derive the exact same K_Alice_to_Bob and K_Bob_to_Alice."""
    a_priv, a_pub, b_priv, b_pub = keypairs

    a_res, b_res = _run_both(
        lambda s: alice_handshake(s, ALICE_ID, BOB_ID, a_priv, b_pub),
        lambda s: bob_handshake(  s, ALICE_ID, BOB_ID, b_priv, a_pub),
    )
    assert a_res.k_alice_to_bob == b_res.k_alice_to_bob
    assert a_res.k_bob_to_alice == b_res.k_bob_to_alice


def test_loopback_directional_keys_differ(keypairs):
    """The two traffic keys must be distinct from each other."""
    a_priv, a_pub, b_priv, b_pub = keypairs

    a_res, _ = _run_both(
        lambda s: alice_handshake(s, ALICE_ID, BOB_ID, a_priv, b_pub),
        lambda s: bob_handshake(  s, ALICE_ID, BOB_ID, b_priv, a_pub),
    )
    assert a_res.k_alice_to_bob != a_res.k_bob_to_alice


def test_loopback_transcript_hashes_match(keypairs):
    """Both sides must have computed the same transcript hash."""
    a_priv, a_pub, b_priv, b_pub = keypairs

    a_res, b_res = _run_both(
        lambda s: alice_handshake(s, ALICE_ID, BOB_ID, a_priv, b_pub),
        lambda s: bob_handshake(  s, ALICE_ID, BOB_ID, b_priv, a_pub),
    )
    assert a_res.transcript_hash == b_res.transcript_hash
    assert len(a_res.transcript_hash) == 32


def test_loopback_sids_echoed(keypairs):
    """Alice's SID as seen by Alice must match what Bob recorded, and vice versa."""
    a_priv, a_pub, b_priv, b_pub = keypairs

    a_res, b_res = _run_both(
        lambda s: alice_handshake(s, ALICE_ID, BOB_ID, a_priv, b_pub),
        lambda s: bob_handshake(  s, ALICE_ID, BOB_ID, b_priv, a_pub),
    )
    assert a_res.alice_sid == b_res.alice_sid
    assert a_res.bob_sid   == b_res.bob_sid


def test_corrupted_alice_signature_aborts(keypairs):
    """If Alice's M3 signature is wrong, Bob must raise HandshakeError."""
    a_priv, a_pub, b_priv, b_pub = keypairs

    with tempfile.TemporaryDirectory() as d:
        wrong_priv, _ = generate_and_save_keypair(f"{d}/wrong")

    # Bob aborts at M3; Alice sees the socket close, not Bob's specific message.
    with pytest.raises(HandshakeError):
        _run_both(
            lambda s: alice_handshake(s, ALICE_ID, BOB_ID, wrong_priv, b_pub),
            lambda s: bob_handshake(  s, ALICE_ID, BOB_ID, b_priv,     a_pub),
        )


def test_corrupted_bob_signature_aborts(keypairs):
    """If Bob's M4 signature is wrong, Alice must raise HandshakeError."""
    a_priv, a_pub, b_priv, b_pub = keypairs

    with tempfile.TemporaryDirectory() as d:
        wrong_priv, _ = generate_and_save_keypair(f"{d}/wrong")

    with pytest.raises(HandshakeError, match="M4"):
        _run_both(
            lambda s: alice_handshake(s, ALICE_ID, BOB_ID, a_priv,    b_pub),
            lambda s: bob_handshake(  s, ALICE_ID, BOB_ID, wrong_priv, a_pub),
        )


def test_wrong_bob_id_aborts(keypairs):
    """Alice must abort if M2 contains a bob_id she doesn't expect."""
    a_priv, a_pub, b_priv, b_pub = keypairs

    with pytest.raises(HandshakeError, match="bob_id"):
        _run_both(
            lambda s: alice_handshake(s, ALICE_ID, b"XX000001", a_priv, b_pub),
            lambda s: bob_handshake(  s, ALICE_ID, BOB_ID,      b_priv, a_pub),
        )


def test_wrong_alice_id_aborts(keypairs):
    """Bob must abort if M1 contains an alice_id he doesn't expect."""
    a_priv, a_pub, b_priv, b_pub = keypairs

    # Bob aborts at M1 identity check; Alice sees socket-closed, not Bob's message.
    with pytest.raises(HandshakeError):
        _run_both(
            lambda s: alice_handshake(s, ALICE_ID, BOB_ID,      a_priv, b_pub),
            lambda s: bob_handshake(  s, b"XX000001", BOB_ID,   b_priv, a_pub),
        )


def test_insecure_demo_skips_sig_check(keypairs):
    """With insecure_demo=True, wrong signing keys still complete the handshake."""
    a_priv, a_pub, b_priv, b_pub = keypairs

    with tempfile.TemporaryDirectory() as d:
        wrong_a, _ = generate_and_save_keypair(f"{d}/wa")
        wrong_b, _ = generate_and_save_keypair(f"{d}/wb")

    a_res, b_res = _run_both(
        lambda s: alice_handshake(s, ALICE_ID, BOB_ID, wrong_a, b_pub, insecure_demo=True),
        lambda s: bob_handshake(  s, ALICE_ID, BOB_ID, wrong_b, a_pub, insecure_demo=True),
    )
    assert a_res.k_alice_to_bob == b_res.k_alice_to_bob
