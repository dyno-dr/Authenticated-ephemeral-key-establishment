# Bob_Test.py
#
# CS6530 Assignment 2
# 
# Minimal TCP transport helper - Bob Communicaiton Check
#
# IMPORTANT:
# This helper is to do a basic check as Bob and communication with Alice
#

from transport import accept_peer, send_message, receive_message

PORT = 5000

print(f"Bob: waiting on TCP port {PORT}...")

sock, peer = accept_peer(PORT)

print("Bob: connected to", peer)

message = receive_message(sock)
print("Bob received:", message.decode())

send_message(sock, b"Hello Alice")

sock.close()