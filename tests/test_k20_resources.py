import tracemalloc

import pytest

from noticer_core.evaluation.k20_resources import measure_resources


def test_scope_and_measurement_units() -> None:
    value, metrics = measure_resources(lambda: bytearray(16_384))
    assert len(value) == 16_384
    assert min(metrics.wall_ns, metrics.cpu_ns) >= 0
    assert metrics.peak_python_bytes >= 16_384
    assert metrics.energy_proxy_cpu_ns == metrics.cpu_ns


def test_nested_work_fails_without_leaving_instrumentation_enabled() -> None:
    with pytest.raises(RuntimeError, match="nested"):
        measure_resources(lambda: measure_resources(lambda: None))
    assert not tracemalloc.is_tracing()
    assert measure_resources(lambda: 4)[0] == 4
