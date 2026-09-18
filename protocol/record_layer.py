# protocol/record_layer.py — AES-256-GCM record layer with per-direction counters

from threading import Lock

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class RecordError(Exception):
    """Raised when a record is rejected (stale counter, bad tag, or tampered AAD)."""


class ApplicationRecordLayer:
    """Bidirectional AES-256-GCM record layer.

    send_key and receive_key must be distinct (from derive_traffic_keys).
    Each direction has its own counter starting at 0.
    """

    def __init__(self, send_key: bytes, receive_key: bytes) -> None:
        assert send_key != receive_key, "send and receive keys must differ"
        self._send_aead    = AESGCM(send_key)
        self._receive_aead = AESGCM(receive_key)
        self._send_counter    = 0
        self._receive_counter = 0
        self._send_lock    = Lock()
        self._receive_lock = Lock()

    @staticmethod
    def _nonce(counter: int) -> bytes:
        # Fixed 4-byte zero prefix || 8-byte big-endian counter = 12-byte GCM nonce.
        # The fixed prefix is safe because each direction has its own key, so
        # identical counter values in opposite directions never share a key.
        return b"\x00\x00\x00\x00" + counter.to_bytes(8, "big")

    @staticmethod
    def _aad(sender_id: bytes, receiver_id: bytes,
             alice_sid: bytes, bob_sid: bytes, counter: int) -> bytes:
        return sender_id + receiver_id + alice_sid + bob_sid + counter.to_bytes(8, "big")


    def seal(
        self,
        plaintext: bytes,
        sender_id: bytes,
        receiver_id: bytes,
        alice_sid: bytes,
        bob_sid: bytes,
    ) -> tuple[bytes, int]:
        """Encrypt plaintext. Returns (ciphertext_with_tag, counter_used)."""
        with self._send_lock:
            c     = self._send_counter
            nonce = self._nonce(c)
            aad   = self._aad(sender_id, receiver_id, alice_sid, bob_sid, c)
            ct    = self._send_aead.encrypt(nonce, plaintext, aad)
            self._send_counter += 1
            return ct, c

    def open(
        self,
        ciphertext_with_tag: bytes,
        counter_claimed: int,
        sender_id: bytes,
        receiver_id: bytes,
        alice_sid: bytes,
        bob_sid: bytes,
    ) -> bytes:
        """Decrypt and verify. Returns plaintext, or raises RecordError.

        Counter check comes before decrypt, but the counter only advances after
        AEAD succeeds — a failed verification leaves receive_counter unchanged.
        """
        with self._receive_lock:
            if counter_claimed != self._receive_counter:
                raise RecordError(
                    f"stale/unexpected counter: got {counter_claimed}, "
                    f"expected {self._receive_counter}"
                )
            nonce = self._nonce(counter_claimed)
            aad   = self._aad(sender_id, receiver_id, alice_sid, bob_sid, counter_claimed)
            try:
                plaintext = self._receive_aead.decrypt(nonce, ciphertext_with_tag, aad)
            except InvalidTag as exc:
                # State not advanced — the counter slot is NOT consumed on failure.
                raise RecordError("AEAD verification failed") from exc
            self._receive_counter += 1
            return plaintext

    @property
    def send_counter(self) -> int:
        return self._send_counter

    @property
    def receive_counter(self) -> int:
        return self._receive_counter
