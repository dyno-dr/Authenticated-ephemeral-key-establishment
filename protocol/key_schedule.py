# protocol/key_schedule.py — X25519 ephemeral DH and HKDF-SHA-256 traffic-key derivation

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .constants import HKDF_INFO_A2B, HKDF_INFO_B2A, HKDF_KEY_LEN


def generate_ephemeral_keypair() -> tuple[X25519PrivateKey, bytes]:
    """Returns (private_key, raw_32_byte_public_key). Only the bytes go on the wire."""
    private_key = X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private_key, public_bytes


def compute_shared_secret(private_key: X25519PrivateKey, peer_public_bytes: bytes) -> bytes:
    """X25519 exchange. peer_public_bytes must be raw 32 bytes, not PEM/DER."""
    peer_pk = X25519PublicKey.from_public_bytes(peer_public_bytes)
    return private_key.exchange(peer_pk)


def derive_traffic_keys(shared_secret: bytes, transcript_hash: bytes) -> tuple[bytes, bytes]:
    """HKDF-Extract(salt=transcript_hash, IKM=shared_secret) → PRK, then Expand to two keys.

    Using transcript_hash as the salt binds the derived keys to this session's
    IDs, SIDs, and ephemeral keys — so different sessions produce different keys
    even if the same DH secret were somehow reused.
    """
    prk = HKDF(algorithm=SHA256(), length=32, salt=transcript_hash, info=b"").derive(shared_secret)
    k_a2b = HKDFExpand(algorithm=SHA256(), length=HKDF_KEY_LEN, info=HKDF_INFO_A2B).derive(prk)
    k_b2a = HKDFExpand(algorithm=SHA256(), length=HKDF_KEY_LEN, info=HKDF_INFO_B2A).derive(prk)
    return k_a2b, k_b2a
