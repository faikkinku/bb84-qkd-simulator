import socket
import threading

import pytest

from bb84 import protocol as P
from bb84.parties import run_alice, run_bob
from bb84.quantum import run_quantum_channel


def _sifted_qber(run):
    idx = P.sift(run.alice_bases, run.bob_bases)
    return idx, P.qber([run.alice_bits[i] for i in idx], [run.bob_results[i] for i in idx])


def test_no_eve_gives_zero_qber_and_half_sift():
    idx, q = _sifted_qber(run_quantum_channel(1024))
    assert q == 0.0
    assert 0.42 < len(idx) / 1024 < 0.58


def test_intercept_resend_gives_about_25_percent():
    _, q = _sifted_qber(run_quantum_channel(2048, eve=True))
    assert 0.19 < q < 0.31


def test_partial_interception_scales():
    _, q = _sifted_qber(run_quantum_channel(2048, eve=True, intercept_fraction=0.4))
    assert 0.05 < q < 0.15


def test_aes_roundtrip_and_key_size():
    key = P.derive_aes_key([1, 0, 1, 1] * 100)
    assert len(key) == 32
    nonce, ct = P.encrypt(key, b"hello")
    assert P.decrypt(key, nonce, ct) == b"hello"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.parametrize("eve", [False, True])
def test_end_to_end_over_tcp(eve):
    run = run_quantum_channel(1024, eve=eve)
    port = _free_port()
    listener = socket.socket()
    listener.bind(("127.0.0.1", port))
    listener.listen(1)
    alice = {}
    t = threading.Thread(target=lambda: alice.update(run_alice(listener, run.alice_bits, run.alice_bases, "hi bob")))
    t.start()
    bob = run_bob("127.0.0.1", port, run.bob_bases, run.bob_results, "hi alice")
    t.join()
    listener.close()

    if eve:
        assert not alice["accepted"] and not bob["accepted"]
        assert "received" not in bob
    else:
        assert alice["accepted"] and bob["accepted"]
        assert alice["key_bits"] == bob["key_bits"]
        assert bob["received"] == "hi bob" and alice["reply"] == "hi alice"
        # no sampled (publicly revealed) position is part of the key
        sample = next(m["indices"] for m in alice["transcript"] if m["type"] == "sample")
        assert not set(sample) & set(alice["key_positions"])
