import json

import pytest

from noticer_core.evaluation.k21_environment import environment_fingerprint


def test_thread_configuration_is_digest_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OMP_NUM_THREADS", "1")
    first, digest = environment_fingerprint()
    assert json.loads(first)["configured_thread_limits"]["OMP_NUM_THREADS"] == 1
    assert environment_fingerprint() == (first, digest)
    monkeypatch.setenv("OMP_NUM_THREADS", "2")
    _, updated = environment_fingerprint()
    assert updated != digest
