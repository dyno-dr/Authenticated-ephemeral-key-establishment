# experiments/__init__.py — shared helpers for self-contained experiment scripts

import socket
import threading

from protocol.handshake import alice_handshake, bob_handshake


def loopback_handshake(a_lt_sk, b_lt_sk, a_lt_pk, b_lt_pk,
                       alice_id, bob_id, retain_ephemeral=False):
    """Run a full authenticated handshake over a socket pair.

    Returns (hs_alice, hs_bob).  Accepts retain_ephemeral so TR-4 can keep
    alice_eph_priv without duplicating the threading boilerplate.
    """
    a_sock, b_sock = socket.socketpair()
    hs_b = [None]
    err  = [None]

    def bob_side():
        try:
            hs_b[0] = bob_handshake(b_sock, alice_id, bob_id, b_lt_sk, a_lt_pk)
        except Exception as e:
            err[0] = e
        finally:
            b_sock.close()

    t = threading.Thread(target=bob_side)
    t.start()
    hs_a = alice_handshake(a_sock, alice_id, bob_id, a_lt_sk, b_lt_pk,
                           retain_ephemeral=retain_ephemeral)
    a_sock.close()
    t.join()

    if err[0]:
        raise err[0]
    return hs_a, hs_b[0]
