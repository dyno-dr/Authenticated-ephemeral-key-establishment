# protocol/identity.py — Ed25519 long-term identity keys: generate, load, sign, verify

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.exceptions import InvalidSignature


class AuthenticationError(Exception):
    """Raised when Ed25519 signature verification fails."""


def generate_and_save_keypair(stem: str) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 keypair and write PEM files.

    Writes <stem>.key (private, never share) and <stem>.pub (public).
    Returns (private_key, public_key).
    """
    private_key = Ed25519PrivateKey.generate()
    public_key  = private_key.public_key()

    priv_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pub_pem  = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    Path(f"{stem}.key").write_bytes(priv_pem)
    Path(f"{stem}.pub").write_bytes(pub_pem)

    return private_key, public_key


def load_private_key(path: str) -> Ed25519PrivateKey:
    return load_pem_private_key(Path(path).read_bytes(), password=None)


def load_public_key(path: str) -> Ed25519PublicKey:
    return load_pem_public_key(Path(path).read_bytes())


def get_public_bytes(public_key: Ed25519PublicKey) -> bytes:
    """Raw 32-byte public key value (not PEM, not DER-wrapped)."""
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def sign(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    return private_key.sign(data)


def verify(public_key: Ed25519PublicKey, signature: bytes, data: bytes) -> None:
    """Verify an Ed25519 signature. Raises AuthenticationError on failure.

    Uses the library's own InvalidSignature rather than a manual comparison
    so there is no risk of a timing side-channel from hand-rolled byte equality.
    """
    try:
        public_key.verify(signature, data)
    except InvalidSignature as exc:
        raise AuthenticationError("Ed25519 signature verification failed") from exc
