"""Alice (TCP server) and Bob (TCP client) running the classical half of BB84.

Classical message flow (all visible on the wire):
    Bob   -> Alice  hello
    Alice -> Bob    bases        Alice's measurement bases
    Bob   -> Alice  bases        Bob's measurement bases
    Alice -> Bob    sample       random subset of sifted positions to sacrifice
    Bob   -> Alice  sample_bits  Bob's bits at those positions
    Alice -> Bob    verdict      QBER + accept/abort
    Alice -> Bob    data         AES-256-GCM ciphertext   (only if accepted)
    Bob   -> Alice  data         AES-256-GCM ciphertext   (reply)
"""
from __future__ import annotations

import hashlib
import socket
from typing import Any, Dict, List, Optional

from . import protocol as P
from .channel import JsonChannel


def _key_positions(sifted: List[int], sample: List[int]) -> List[int]:
    s = set(sample)
    return [i for i in sifted if i not in s]


def run_alice(listener: socket.socket, bits: List[int], bases: List[int],
              message: str, sample_seed: Optional[int] = None) -> Dict[str, Any]:
    conn, _ = listener.accept()
    ch = JsonChannel(conn, "alice")
    out: Dict[str, Any] = {"role": "alice"}
    try:
        ch.recv()  # hello
        ch.send({"type": "bases", "bases": bases})
        bob_bases = ch.recv()["bases"]

        sifted = P.sift(bases, bob_bases)
        sample = P.choose_sample(sifted, seed=sample_seed)
        ch.send({"type": "sample", "indices": sample})
        bob_sample_bits = ch.recv()["bits"]

        error_rate = P.qber([bits[i] for i in sample], bob_sample_bits)
        accept = error_rate <= P.QBER_THRESHOLD
        ch.send({"type": "verdict", "qber": round(error_rate, 4), "accept": accept,
                 "threshold": P.QBER_THRESHOLD})

        key_pos = _key_positions(sifted, sample)
        out.update(sifted=len(sifted), sampled=len(sample), qber=error_rate, accepted=accept,
                   key_positions=key_pos, key_bits=[bits[i] for i in key_pos])
        if accept:
            key = P.derive_aes_key(out["key_bits"])
            nonce, ct = P.encrypt(key, message.encode())
            ch.send({"type": "data", "nonce": nonce.hex(), "ciphertext": ct.hex()})
            reply = ch.recv()
            out["reply"] = P.decrypt(key, bytes.fromhex(reply["nonce"]), bytes.fromhex(reply["ciphertext"])).decode()
            out["aes_key_sha256_prefix"] = hashlib.sha256(key).hexdigest()[:16]
    finally:
        out["transcript"] = ch.transcript
        ch.close()
    return out


def run_bob(host: str, port: int, bases: List[int], results: List[int], reply_text: str) -> Dict[str, Any]:
    sock = socket.create_connection((host, port))
    ch = JsonChannel(sock, "bob")
    out: Dict[str, Any] = {"role": "bob"}
    try:
        ch.send({"type": "hello", "protocol": "BB84", "n_qubits": len(bases)})
        alice_bases = ch.recv()["bases"]
        ch.send({"type": "bases", "bases": bases})

        sifted = P.sift(alice_bases, bases)
        sample = ch.recv()["indices"]
        ch.send({"type": "sample_bits", "bits": [results[i] for i in sample]})
        verdict = ch.recv()

        key_pos = _key_positions(sifted, sample)
        out.update(qber=verdict["qber"], accepted=verdict["accept"],
                   key_positions=key_pos, key_bits=[results[i] for i in key_pos])
        if verdict["accept"]:
            key = P.derive_aes_key(out["key_bits"])
            data = ch.recv()
            out["received"] = P.decrypt(key, bytes.fromhex(data["nonce"]), bytes.fromhex(data["ciphertext"])).decode()
            nonce, ct = P.encrypt(key, reply_text.encode())
            ch.send({"type": "data", "nonce": nonce.hex(), "ciphertext": ct.hex()})
    finally:
        out["transcript"] = ch.transcript
        ch.close()
    return out
