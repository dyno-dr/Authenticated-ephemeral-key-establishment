import pytest
from protocol.key_schedule import (
    generate_ephemeral_keypair, compute_shared_secret, derive_traffic_keys,
)
from protocol.constants import HKDF_KEY_LEN


def test_ephemeral_pk_is_32_bytes():
    _, pub = generate_ephemeral_keypair()
    assert len(pub) == 32


def test_keypairs_are_fresh():
    _, pub1 = generate_ephemeral_keypair()
    _, pub2 = generate_ephemeral_keypair()
    assert pub1 != pub2


def test_dh_is_symmetric():
    a_priv, a_pub = generate_ephemeral_keypair()
    b_priv, b_pub = generate_ephemeral_keypair()
    assert compute_shared_secret(a_priv, b_pub) == compute_shared_secret(b_priv, a_pub)


def test_shared_secret_is_32_bytes():
    a_priv, _ = generate_ephemeral_keypair()
    b_priv, b_pub = generate_ephemeral_keypair()
    assert len(compute_shared_secret(a_priv, b_pub)) == 32


def test_traffic_keys_are_32_bytes():
    a_priv, a_pub = generate_ephemeral_keypair()
    _, b_pub = generate_ephemeral_keypair()
    secret = compute_shared_secret(a_priv, b_pub)
    k_a2b, k_b2a = derive_traffic_keys(secret, bytes(32))
    assert len(k_a2b) == HKDF_KEY_LEN == 32
    assert len(k_b2a) == HKDF_KEY_LEN == 32


def test_traffic_keys_are_directionally_distinct():
    a_priv, _ = generate_ephemeral_keypair()
    _, b_pub = generate_ephemeral_keypair()
    secret = compute_shared_secret(a_priv, b_pub)
    k_a2b, k_b2a = derive_traffic_keys(secret, bytes(32))
    assert k_a2b != k_b2a


def test_traffic_keys_differ_from_raw_shared_secret():
    a_priv, _ = generate_ephemeral_keypair()
    _, b_pub = generate_ephemeral_keypair()
    secret = compute_shared_secret(a_priv, b_pub)
    k_a2b, k_b2a = derive_traffic_keys(secret, bytes(32))
    assert secret != k_a2b
    assert secret != k_b2a


def test_both_sides_derive_identical_keys():
    a_priv, a_pub = generate_ephemeral_keypair()
    b_priv, b_pub = generate_ephemeral_keypair()
    secret_alice = compute_shared_secret(a_priv, b_pub)
    secret_bob   = compute_shared_secret(b_priv, a_pub)
    salt = b"\xab" * 32
    k_a2b_alice, k_b2a_alice = derive_traffic_keys(secret_alice, salt)
    k_a2b_bob,   k_b2a_bob   = derive_traffic_keys(secret_bob,   salt)
    assert k_a2b_alice == k_a2b_bob
    assert k_b2a_alice == k_b2a_bob


def test_different_salt_gives_different_keys():
    a_priv, _ = generate_ephemeral_keypair()
    _, b_pub = generate_ephemeral_keypair()
    secret = compute_shared_secret(a_priv, b_pub)
    k1, _ = derive_traffic_keys(secret, b"\x00" * 32)
    k2, _ = derive_traffic_keys(secret, b"\xff" * 32)
    assert k1 != k2


def test_hkdf_output_is_deterministic():
    # Same inputs must always produce the same outputs (catches any accidental randomness).
    secret = b"\x11" * 32
    salt   = b"\x22" * 32
    assert derive_traffic_keys(secret, salt) == derive_traffic_keys(secret, salt)
