"""Quantum channel: simulates BB84 qubit preparation, transmission and measurement in Qiskit.

Encoding (basis 0 = Z / rectilinear, basis 1 = X / diagonal):
    bit 0, Z -> |0>     bit 1, Z -> |1>
    bit 0, X -> |+>     bit 1, X -> |->

The optional eavesdropper (Eve) performs an intercept-resend attack: she measures every
qubit in a random basis and re-sends the state she observed. When her basis differs from
Alice's, she disturbs the qubit, which shows up as errors in Bob's sifted key (~25% QBER).
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import List, Optional

from qiskit import ClassicalRegister, QuantumCircuit, QuantumRegister
from qiskit_aer import AerSimulator

BATCH_SIZE = 16  # qubits per circuit; each wire is an independent BB84 qubit


@dataclass
class QuantumRun:
    alice_bits: List[int]
    alice_bases: List[int]
    bob_bases: List[int]
    bob_results: List[int]
    eve_bases: Optional[List[int]] = None
    eve_results: Optional[List[int]] = None
    n_qubits: int = field(init=False)

    def __post_init__(self):
        self.n_qubits = len(self.alice_bits)


def _random_bits(n: int) -> List[int]:
    return [secrets.randbelow(2) for _ in range(n)]


def _build_batch(a_bits, a_bases, b_bases, e_bases=None, e_mask=None) -> QuantumCircuit:
    n = len(a_bits)
    q = QuantumRegister(n, "q")
    bob_c = ClassicalRegister(n, "bob")
    regs = [q, bob_c]
    eve_c = None
    if e_bases is not None:
        eve_c = ClassicalRegister(n, "eve")
        regs.append(eve_c)
    qc = QuantumCircuit(*regs)

    for i in range(n):
        # Alice prepares
        if a_bits[i]:
            qc.x(q[i])
        if a_bases[i]:
            qc.h(q[i])

        # Eve intercepts, measures in her basis, and resends what she saw.
        # After measuring in X (H then measure), applying H again re-prepares |+>/|->.
        if e_bases is not None and e_mask[i]:
            if e_bases[i]:
                qc.h(q[i])
            qc.measure(q[i], eve_c[i])
            if e_bases[i]:
                qc.h(q[i])

        # Bob measures in his randomly chosen basis
        if b_bases[i]:
            qc.h(q[i])
        qc.measure(q[i], bob_c[i])
    return qc


def _bits_from_counts(counts: dict, reg_index: int, n: int) -> List[int]:
    # One shot -> a single key like "eve_bits bob_bits"; registers appear in reverse order.
    key = next(iter(counts))
    regs = key.split(" ")[::-1]
    bits = regs[reg_index]
    return [int(b) for b in reversed(bits)][:n]


def run_quantum_channel(
    n_qubits: int = 1024, eve: bool = False, seed: Optional[int] = None, intercept_fraction: float = 1.0
) -> QuantumRun:
    """Send n_qubits from Alice to Bob (optionally through Eve) and return everyone's private data.

    intercept_fraction: share of qubits Eve attacks (1.0 = all). Expected QBER = intercept_fraction / 4.
    """
    alice_bits = _random_bits(n_qubits)
    alice_bases = _random_bits(n_qubits)
    bob_bases = _random_bits(n_qubits)
    eve_bases = _random_bits(n_qubits) if eve else None
    eve_mask = [secrets.randbelow(10**6) < intercept_fraction * 10**6 for _ in range(n_qubits)] if eve else None

    sim = AerSimulator(seed_simulator=seed)
    circuits = []
    for start in range(0, n_qubits, BATCH_SIZE):
        sl = slice(start, start + BATCH_SIZE)
        circuits.append(
            _build_batch(
                alice_bits[sl], alice_bases[sl], bob_bases[sl],
                eve_bases[sl] if eve else None, eve_mask[sl] if eve else None,
            )
        )
    result = sim.run(circuits, shots=1).result()

    bob_results: List[int] = []
    eve_results: List[int] = []
    for idx, qc in enumerate(circuits):
        counts = result.get_counts(idx)
        n = qc.num_qubits
        bob_results += _bits_from_counts(counts, 0, n)
        if eve:
            eve_results += _bits_from_counts(counts, 1, n)

    return QuantumRun(
        alice_bits=alice_bits,
        alice_bases=alice_bases,
        bob_bases=bob_bases,
        bob_results=bob_results,
        eve_bases=eve_bases,
        eve_results=eve_results if eve else None,
    )
