# transport.py
#
# CS6530 Assignment 2
# 
# Minimal TCP transport helper
#
# IMPORTANT:
# This helper provides transport only.
# It provides NO confidentiality, authentication,
# integrity protection, or replay protection.
#
#
# Wire format:
#     2-byte unsigned big-endian length || message bytes

import socket
import struct

MAX_MESSAGE_SIZE = 65535


def _recv_exact(sock, n):
    """Receive exactly n bytes from a connected socket."""
    data = bytearray()

    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError(
                "Connection closed before complete message was received."
            )
        data.extend(chunk)

    return bytes(data)


def connect_to_peer(peer_ip, peer_port):
    """
    Connect to the peer and return a connected TCP socket.
    Typically used by Alice.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((peer_ip, peer_port))
    return sock


def accept_peer(listen_port, bind_ip="0.0.0.0"):
    """
    Wait for one peer connection.

    Returns:
        connected_socket, peer_address

    Typically used by Bob.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind_ip, listen_port))
    server.listen(1)

    conn, addr = server.accept()

    # Listening socket is no longer needed for this simple assignment.
    server.close()

    return conn, addr


def send_message(sock, data):
    """
    Send one complete logical protocol message.

    Frame:
        uint16_be(length) || message
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")

    data = bytes(data)

    if len(data) == 0:
        raise ValueError("Empty messages are not permitted")

    if len(data) > MAX_MESSAGE_SIZE:
        raise ValueError("Message exceeds 65535 bytes")

    header = struct.pack("!H", len(data))
    sock.sendall(header + data)


def receive_message(sock):
    """
    Receive one complete logical protocol message.

    Returns:
        message bytes
    """
    header = _recv_exact(sock, 2)

    message_length = struct.unpack("!H", header)[0]

    if message_length == 0:
        raise ValueError("Invalid zero-length message")

    message = _recv_exact(sock, message_length)

    return message