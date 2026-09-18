# protocol/handshake.py — 4-message authenticated ephemeral handshake (M1–M4)

import os

from transport import send_message, receive_message
from .constants import PROTOCOL_ID, pack_canonical_transcript, transcript_hash
from .identity import sign, verify, AuthenticationError
from .key_schedule import generate_ephemeral_keypair, compute_shared_secret, derive_traffic_keys
from .messages import (
    encode_m1, decode_m1,
    encode_m2, decode_m2,
    encode_m3, decode_m3,
    encode_m4, decode_m4,
    MessageError,
)


class HandshakeError(Exception):
    """Raised on any handshake failure. No keys are returned to the caller."""


class HandshakeResult:
    __slots__ = ("alice_sid", "bob_sid", "transcript_hash",
                 "k_alice_to_bob", "k_bob_to_alice", "shared_secret",
                 "bob_epk", "alice_eph_priv")

    def __init__(self, alice_sid, bob_sid, transcript_hash,
                 k_alice_to_bob, k_bob_to_alice, shared_secret,
                 bob_epk=None, alice_eph_priv=None):
        self.alice_sid       = alice_sid
        self.bob_sid         = bob_sid
        self.transcript_hash = transcript_hash
        self.k_alice_to_bob  = k_alice_to_bob
        self.k_bob_to_alice  = k_bob_to_alice
        self.shared_secret   = shared_secret
        self.bob_epk         = bob_epk        # bytes; always set on Alice's result
        self.alice_eph_priv  = alice_eph_priv  # X25519PrivateKey; None in normal use


def alice_handshake(sock, alice_id: bytes, bob_id: bytes,
                    alice_lt_sk, bob_lt_pk,
                    insecure_demo: bool = False,
                    retain_ephemeral: bool = False) -> HandshakeResult:
    try:
        alice_eph_priv, alice_epk = generate_ephemeral_keypair()
        alice_sid = os.urandom(16)

        send_message(sock, encode_m1(PROTOCOL_ID, alice_id, alice_sid, alice_epk))

        m2 = _recv(sock, decode_m2)
        _check(m2["protocol_id"] == PROTOCOL_ID,  "M2: wrong protocol_id")
        _check(m2["bob_id"]      == bob_id,        "M2: unexpected bob_id")
        _check(m2["alice_sid"]   == alice_sid,     "M2: alice_sid echo mismatch")
        bob_sid = m2["bob_sid"]
        bob_epk = m2["bob_epk"]

        t = pack_canonical_transcript(alice_id, bob_id, alice_sid, bob_sid, alice_epk, bob_epk)
        t_hash = transcript_hash(t)

        send_message(sock, encode_m3(sign(alice_lt_sk, t_hash)))

        m4 = _recv(sock, decode_m4)
        if not insecure_demo:
            try:
                verify(bob_lt_pk, m4["signature"], t_hash)
            except AuthenticationError as exc:
                raise HandshakeError("M4: Bob's signature verification failed") from exc

        shared = compute_shared_secret(alice_eph_priv, bob_epk)
        k_a2b, k_b2a = derive_traffic_keys(shared, t_hash)
        return HandshakeResult(
            alice_sid, bob_sid, t_hash, k_a2b, k_b2a, shared,
            bob_epk=bob_epk,
            alice_eph_priv=alice_eph_priv if retain_ephemeral else None,
        )

    except (MessageError, OSError) as exc:
        raise HandshakeError(str(exc)) from exc


def bob_handshake(sock, alice_id: bytes, bob_id: bytes,
                  bob_lt_sk, alice_lt_pk,
                  insecure_demo: bool = False) -> HandshakeResult:
    try:
        bob_eph_priv, bob_epk = generate_ephemeral_keypair()
        bob_sid = os.urandom(16)

        m1 = _recv(sock, decode_m1)
        _check(m1["protocol_id"] == PROTOCOL_ID, "M1: wrong protocol_id")
        _check(m1["alice_id"]    == alice_id,     "M1: unexpected alice_id")
        alice_sid = m1["alice_sid"]
        alice_epk = m1["alice_epk"]

        send_message(sock, encode_m2(PROTOCOL_ID, bob_id, alice_sid, bob_sid, bob_epk))

        t = pack_canonical_transcript(alice_id, bob_id, alice_sid, bob_sid, alice_epk, bob_epk)
        t_hash = transcript_hash(t)

        m3 = _recv(sock, decode_m3)
        if not insecure_demo:
            try:
                verify(alice_lt_pk, m3["signature"], t_hash)
            except AuthenticationError as exc:
                raise HandshakeError("M3: Alice's signature verification failed") from exc

        send_message(sock, encode_m4(sign(bob_lt_sk, t_hash)))

        shared = compute_shared_secret(bob_eph_priv, alice_epk)
        k_a2b, k_b2a = derive_traffic_keys(shared, t_hash)
        return HandshakeResult(alice_sid, bob_sid, t_hash, k_a2b, k_b2a, shared)

    except (MessageError, OSError) as exc:
        raise HandshakeError(str(exc)) from exc


def _recv(sock, decoder):
    return decoder(receive_message(sock))


def _check(condition: bool, msg: str) -> None:
    if not condition:
        raise HandshakeError(msg)
