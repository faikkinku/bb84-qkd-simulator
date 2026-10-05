#!/usr/bin/env python3
"""Statistical experiments: QBER with and without Eve, and QBER vs. interception rate.

    python experiments.py --trials 20

Writes docs/qber_vs_interception.png and prints a summary table for the README.
"""
from __future__ import annotations

import argparse
import statistics
from pathlib import Path

from bb84 import protocol as P
from bb84.quantum import run_quantum_channel


def full_qber(n: int, eve: bool, frac: float = 1.0):
    """QBER over *all* sifted bits (ground truth, not just the public sample)."""
    r = run_quantum_channel(n, eve=eve, intercept_fraction=frac)
    sifted = P.sift(r.alice_bases, r.bob_bases)
    return len(sifted) / n, P.qber([r.alice_bits[i] for i in sifted], [r.bob_results[i] for i in sifted])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--qubits", type=int, default=1024)
    ap.add_argument("--trials", type=int, default=20)
    args = ap.parse_args()

    print(f"{'scenario':<22}{'sift rate':>10}{'QBER mean':>11}{'QBER sd':>9}{'aborted':>9}")
    for label, eve in (("no eavesdropper", False), ("intercept-resend", True)):
        rows = [full_qber(args.qubits, eve) for _ in range(args.trials)]
        sift_rates = [s for s, _ in rows]
        qbers = [q for _, q in rows]
        aborts = sum(q > P.QBER_THRESHOLD for q in qbers)
        print(f"{label:<22}{statistics.mean(sift_rates):>10.1%}{statistics.mean(qbers):>11.2%}"
              f"{statistics.pstdev(qbers):>9.2%}{aborts:>5}/{args.trials}")

    fracs = [i / 10 for i in range(11)]
    measured = [statistics.mean(full_qber(args.qubits, True, f)[1] for _ in range(max(3, args.trials // 4)))
                for f in fracs]
    print("\nintercept fraction -> QBER (theory = fraction / 4)")
    for f, q in zip(fracs, measured):
        flag = "ABORT" if q > P.QBER_THRESHOLD else "ok"
        print(f"  {f:4.1f}  measured {q:6.2%}  theory {f / 4:6.2%}  {flag}")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return
    fig, ax = plt.subplots(figsize=(7, 4.2))
    ax.plot(fracs, [f / 4 * 100 for f in fracs], "--", color="#888", label="theory (p / 4)")
    ax.plot(fracs, [q * 100 for q in measured], "o-", color="#2a6fdb", label="measured (Qiskit Aer)")
    ax.axhline(P.QBER_THRESHOLD * 100, color="#d33", lw=1, label="11% abort threshold")
    ax.set_xlabel("fraction of qubits intercepted by Eve")
    ax.set_ylabel("QBER (%)")
    ax.set_title(f"BB84 intercept-resend: QBER vs. interception ({args.qubits} qubits)")
    ax.legend()
    ax.grid(alpha=0.3)
    Path("docs").mkdir(exist_ok=True)
    fig.tight_layout()
    fig.savefig("docs/qber_vs_interception.png", dpi=150)
    print("\nsaved docs/qber_vs_interception.png")


if __name__ == "__main__":
    main()
