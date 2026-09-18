# Alice_Test.py
#
# CS6530 Assignment 2
# 
# Minimal TCP transport helper - Alice Communicaiton Check
#
# IMPORTANT:
# This helper is to do a basic check as Alice and communication with Bob
#

import sys
from transport import connect_to_peer, send_message, receive_message

if len(sys.argv) != 2:
    print("Usage: python alice_test.py <Bob-IP>")
    raise SystemExit(1)

BOB_IP = sys.argv[1]
PORT = 5000

sock = connect_to_peer(BOB_IP, PORT)

print("Alice: connected to Bob")

send_message(sock, b"Hello Bob")

message = receive_message(sock)
print("Alice received:", message.decode())

sock.close()