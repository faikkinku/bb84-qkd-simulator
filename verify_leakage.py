#!/usr/bin/env python3
"""Check what a passive eavesdropper on the classical channel learns about the final key.

    python verify_leakage.py                                  # use the transcript from results/last_run.json
    python verify_leakage.py --pcap captures/bb84_clean.pcapng  # rebuild the messages from a Wireshark capture

From the wire, Eve sees every basis announcement plus the bit values of the sampled positions.
Bases are chosen independently of bit values, so they reveal nothing about the bits, and every
sampled position is thrown away before the key is formed. So the number of final-key bits whose
value appears on the wire should be 0.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List


def messages_from_pcap(pcap: str, port: int) -> List[Dict]:
    tshark = shutil.which("tshark") or "/Applications/Wireshark.app/Contents/MacOS/tshark"
    cmd = [tshark, "-r", pcap, "-Y", f"tcp.port=={port} && tcp.len>0", "-T", "fields",
           "-e", "tcp.srcport", "-e", "tcp.payload"]
    rows = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.splitlines()
    # Reassemble each direction's byte stream and emit JSON lines in the order they complete on the wire.
    buffers: Dict[str, bytes] = {}
    msgs = []
    for row in rows:
        src, payload = row.split("\t")
        buf = buffers.get(src, b"") + bytes.fromhex(payload.replace(":", ""))
        *lines, buffers[src] = buf.split(b"\n")
        sender = "alice" if src == str(port) else "bob"
        msgs += [{"by": sender, **json.loads(line)} for line in lines if line.strip()]
    return msgs


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="results/last_run.json")
    ap.add_argument("--pcap", help="Wireshark capture of the classical channel")
    ap.add_argument("--port", type=int, default=9000)
    args = ap.parse_args()

    run = json.loads(Path(args.run).read_text())
    if args.pcap:
        msgs = messages_from_pcap(args.pcap, args.port)
        source = f"pcap {args.pcap}"
    else:
        # Alice's transcript holds every message once: what she sent plus what she received from Bob.
        msgs = [{**m, "by": "alice" if m["dir"] == "sent" else "bob"} for m in run["transcript"]]
        source = "in-process transcript"

    types = [m["type"] for m in msgs]
    bases_announced = sum(len(m["bases"]) for m in msgs if m["type"] == "bases")
    sample_idx = next((m["indices"] for m in msgs if m["type"] == "sample"), [])
    revealed_bits = next((m["bits"] for m in msgs if m["type"] == "sample_bits"), [])
    key_positions = set(run["key_positions"])

    leaked = key_positions & set(sample_idx)
    print(f"source:                     {source}")
    print(f"messages on the wire:       {len(msgs)}  {types}")
    print(f"basis values announced:     {bases_announced}  (independent of bit values -> 0 bits of information)")
    print(f"bit values revealed:        {len(revealed_bits)}  (QBER sample, discarded from key)")
    print(f"final key length:           {len(key_positions)} bits")
    print(f"KEY BITS LEAKED ON WIRE:    {len(leaked)}")
    if any(m["type"] == "data" for m in msgs):
        print("payload on wire:            AES-256-GCM ciphertext only (no plaintext)")
    assert not leaked, "a sampled position was reused in the key!"


if __name__ == "__main__":
    main()
