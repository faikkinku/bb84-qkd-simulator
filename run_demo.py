#!/usr/bin/env python3
"""End-to-end BB84 demo: Qiskit quantum channel, then Alice and Bob over a real TCP socket.

    python run_demo.py                 # clean channel -> key accepted, message encrypted
    python run_demo.py --eve           # intercept-resend attack -> ~25% QBER -> abort

Capture the classical channel in Wireshark on the loopback interface (lo0) with
the capture filter `tcp port 9000`.
"""
from __future__ import annotations

import argparse
import json
import socket
import threading
from pathlib import Path

from bb84.protocol import QBER_THRESHOLD
from bb84.parties import run_alice, run_bob
from bb84.quantum import run_quantum_channel


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--qubits", type=int, default=1024)
    ap.add_argument("--eve", action="store_true", help="enable intercept-resend eavesdropper")
    ap.add_argument("--intercept", type=float, default=1.0, help="fraction of qubits Eve attacks (default 1.0)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--message", default="Meet at the north gate at 0600.")
    ap.add_argument("--out", default="results/last_run.json")
    args = ap.parse_args()

    print(f"[quantum] sending {args.qubits} qubits Alice -> Bob" + (" (Eve intercepting!)" if args.eve else ""))
    run = run_quantum_channel(args.qubits, eve=args.eve, intercept_fraction=args.intercept)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen(1)
    print(f"[classical] Alice listening on {args.host}:{args.port}")

    alice_out = {}
    t = threading.Thread(target=lambda: alice_out.update(
        run_alice(listener, run.alice_bits, run.alice_bases, args.message)))
    t.start()
    bob_out = run_bob(args.host, args.port, run.bob_bases, run.bob_results, "Copy that. See you there.")
    t.join()
    listener.close()

    sifted, sampled = alice_out["sifted"], alice_out["sampled"]
    key_len = len(alice_out["key_bits"])
    keys_match = alice_out["key_bits"] == bob_out["key_bits"]
    print(f"[sift]   {sifted}/{args.qubits} bases matched ({sifted / args.qubits:.1%})")
    print(f"[qber]   compared {sampled} sacrificed bits -> QBER {alice_out['qber']:.2%} "
          f"(threshold {QBER_THRESHOLD:.0%})")
    if alice_out["accepted"]:
        print(f"[key]    {key_len} raw key bits -> HKDF-SHA256 -> AES-256 key "
              f"(sha256 prefix {alice_out['aes_key_sha256_prefix']}); Alice/Bob keys match: {keys_match}")
        print(f"[aes]    Bob decrypted:   {bob_out['received']!r}")
        print(f"[aes]    Alice decrypted: {alice_out['reply']!r}")
    else:
        print("[abort]  QBER above threshold -> eavesdropper detected, key discarded, no data sent")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "config": vars(args),
        "sifted": sifted, "sampled": sampled, "qber": alice_out["qber"], "accepted": alice_out["accepted"],
        "key_positions": alice_out["key_positions"], "key_bits": alice_out["key_bits"],
        "keys_match": keys_match,
        "transcript": alice_out["transcript"],
    }, indent=1))
    print(f"[saved]  {out}  (run verify_leakage.py next)")


if __name__ == "__main__":
    main()
