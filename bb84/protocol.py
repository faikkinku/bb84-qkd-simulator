"""Classical post-processing for BB84: sifting, QBER estimation, key derivation, AES-256-GCM."""
from __future__ import annotations

import os
import random
from typing import List, Sequence, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

QBER_THRESHOLD = 0.11  # abort above this error rate (standard BB84 security bound)
SAMPLE_FRACTION = 0.25  # fraction of sifted bits publicly compared to estimate QBER


def sift(bases_a: Sequence[int], bases_b: Sequence[int]) -> List[int]:
    """Indices where Alice and Bob happened to use the same basis."""
    return [i for i, (a, b) in enumerate(zip(bases_a, bases_b)) if a == b]


def choose_sample(sifted_idx: Sequence[int], fraction: float = SAMPLE_FRACTION, seed=None) -> List[int]:
    rng = random.Random(seed) if seed is not None else random.SystemRandom()
    k = max(1, int(len(sifted_idx) * fraction))
    return sorted(rng.sample(list(sifted_idx), k))


def qber(bits_a: Sequence[int], bits_b: Sequence[int]) -> float:
    if not bits_a:
        return 0.0
    return sum(a != b for a, b in zip(bits_a, bits_b)) / len(bits_a)


def bits_to_bytes(bits: Sequence[int]) -> bytes:
    padded = list(bits) + [0] * (-len(bits) % 8)
    return bytes(int("".join(map(str, padded[i:i + 8])), 2) for i in range(0, len(padded), 8))


def derive_aes_key(key_bits: Sequence[int]) -> bytes:
    """Compress the raw key bits into a 256-bit AES key (HKDF-SHA256, a stand-in for privacy amplification)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"bb84-aes256").derive(bits_to_bytes(key_bits))


def encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    nonce = os.urandom(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, None)
