"""Authenticated-classical-channel stand-in: newline-delimited JSON over a TCP socket.

Plain JSON is deliberate: in Wireshark, "Follow > TCP Stream" shows exactly what an
eavesdropper on the classical channel learns (bases and sampled bits, never key bits).
"""
from __future__ import annotations

import json
import socket
from typing import Any, Dict, List


class JsonChannel:
    def __init__(self, sock: socket.socket, name: str):
        self.sock = sock
        self.name = name
        self._buf = sock.makefile("r", encoding="utf-8")
        self.transcript: List[Dict[str, Any]] = []  # everything that crossed the wire

    def send(self, msg: Dict[str, Any]) -> None:
        self.sock.sendall((json.dumps(msg, separators=(",", ":")) + "\n").encode())
        self.transcript.append({"dir": "sent", "by": self.name, **msg})

    def recv(self) -> Dict[str, Any]:
        line = self._buf.readline()
        if not line:
            raise ConnectionError(f"{self.name}: peer closed the connection")
        msg = json.loads(line)
        self.transcript.append({"dir": "recv", "by": self.name, **msg})
        return msg

    def close(self) -> None:
        self._buf.close()
        self.sock.close()
