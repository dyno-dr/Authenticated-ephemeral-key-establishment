import os
import tempfile

import pytest
from protocol.identity import (
    generate_and_save_keypair, load_private_key, load_public_key,
    get_public_bytes, sign, verify, AuthenticationError,
)


@pytest.fixture()
def keypair(tmp_path):
    stem = str(tmp_path / "test")
    priv, pub = generate_and_save_keypair(stem)
    return priv, pub, stem


def test_generate_creates_files(keypair):
    _, _, stem = keypair
    assert os.path.exists(f"{stem}.key")
    assert os.path.exists(f"{stem}.pub")


def test_load_roundtrip(keypair):
    _, pub, stem = keypair
    priv2 = load_private_key(f"{stem}.key")
    pub2  = load_public_key(f"{stem}.pub")
    sig = sign(priv2, b"hello")
    verify(pub2, sig, b"hello")


def test_sign_verify_roundtrip(keypair):
    priv, pub, _ = keypair
    data = b"CS6530 transcript hash (32 bytes)" + bytes(32)
    sig  = sign(priv, data)
    assert len(sig) == 64
    verify(pub, sig, data)   # must not raise


def test_verify_wrong_key_raises():
    with tempfile.TemporaryDirectory() as d:
        priv1, pub1 = generate_and_save_keypair(f"{d}/k1")[:2]
        priv2, pub2 = generate_and_save_keypair(f"{d}/k2")[:2]
        sig = sign(priv1, b"data")
        with pytest.raises(AuthenticationError):
            verify(pub2, sig, b"data")


def test_verify_tampered_data_raises(keypair):
    priv, pub, _ = keypair
    data = b"original data"
    sig  = sign(priv, data)
    with pytest.raises(AuthenticationError):
        verify(pub, sig, b"tampered data")


def test_verify_one_bit_flip_raises(keypair):
    priv, pub, _ = keypair
    data = bytes(32)
    sig  = sign(priv, data)
    flipped = bytearray(data)
    flipped[0] ^= 0x01
    with pytest.raises(AuthenticationError):
        verify(pub, sig, bytes(flipped))


def test_get_public_bytes_is_32(keypair):
    _, pub, _ = keypair
    raw = get_public_bytes(pub)
    assert len(raw) == 32


def test_two_keypairs_have_different_public_bytes():
    with tempfile.TemporaryDirectory() as d:
        _, pub1 = generate_and_save_keypair(f"{d}/k1")[:2]
        _, pub2 = generate_and_save_keypair(f"{d}/k2")[:2]
        assert get_public_bytes(pub1) != get_public_bytes(pub2)


def test_private_key_file_not_usable_as_public(keypair):
    _, _, stem = keypair
    with pytest.raises(Exception):
        load_public_key(f"{stem}.key")
