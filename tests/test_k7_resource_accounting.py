from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from noticer_core.evaluation.resource_accounting import (
    NOT_AVAILABLE,
    ProcessCounters,
    ProcessResourceSampler,
    ResourceAccountingError,
    ResourceMeasurement,
    build_resource_artifact,
    measure_command,
    write_resource_artifact,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "k7_resource_accounting_v1.schema.json"


class _UnavailableReader:
    def read(self, process_id: int) -> ProcessCounters:
        return ProcessCounters(None, None, None, None)


def test_direct_child_measurement_records_wall_cpu_and_peak_rss() -> None:
    measurement = measure_command(
        [sys.executable, "-c", "sum(i * i for i in range(1000000))"],
        cwd=ROOT,
        timeout_ms=10_000,
        poll_interval_ms=5,
    )
    assert measurement.exit_code == 0
    assert measurement.timed_out is False
    assert measurement.wall_time_ns > 0
    assert measurement.sample_count >= 1
    assert measurement.user_cpu_ns is None or measurement.user_cpu_ns >= 0
    assert measurement.system_cpu_ns is None or measurement.system_cpu_ns >= 0
    assert measurement.peak_rss_bytes is None or measurement.peak_rss_bytes > 0


def test_timeout_kills_child_and_remains_distinct_from_exit_failure() -> None:
    measurement = measure_command(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        cwd=ROOT,
        timeout_ms=30,
        poll_interval_ms=5,
    )
    assert measurement.timed_out is True
    assert measurement.exit_code != 0


def test_unavailable_metrics_are_explicit_and_host_identity_is_absent() -> None:
    process = subprocess.Popen(
        [sys.executable, "-c", "pass"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    measurement = ProcessResourceSampler(_UnavailableReader()).measure(
        process, timeout_ms=5_000
    )
    artifact = build_resource_artifact("k7s-reference-0123456789abcdef", measurement)
    encoded = json.dumps(artifact, sort_keys=True).lower()
    assert artifact["measurement"]["user_cpu_ns"] == NOT_AVAILABLE
    assert artifact["measurement"]["system_cpu_ns"] == NOT_AVAILABLE
    assert artifact["measurement"]["peak_rss_bytes"] == NOT_AVAILABLE
    assert all(word not in encoded for word in ("hostname", "username", '"pid"', '"command"'))


def test_artifact_is_schema_shaped_idempotent_and_conflict_safe(tmp_path: Path) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    measurement = ResourceMeasurement(1, 2, 3, 4, 0, False, 1)
    artifact = build_resource_artifact("k7s-cegis-fedcba9876543210", measurement)
    assert set(artifact) == set(schema["required"]) == set(schema["properties"])
    output = tmp_path / "resource.json"
    write_resource_artifact(output, artifact)
    original = output.read_bytes()
    write_resource_artifact(output, artifact)
    assert output.read_bytes() == original
    output.write_text("{}\n", encoding="utf-8")
    with pytest.raises(FileExistsError, match="differs"):
        write_resource_artifact(output, artifact)


@pytest.mark.parametrize("timeout_ms,poll_ms", [(0, 1), (10, 0), (10, 11)])
def test_invalid_sampling_bounds_are_rejected(timeout_ms: int, poll_ms: int) -> None:
    process = subprocess.Popen([sys.executable, "-c", "pass"], cwd=ROOT)
    try:
        with pytest.raises(ResourceAccountingError):
            ProcessResourceSampler().measure(
                process, timeout_ms=timeout_ms, poll_interval_ms=poll_ms
            )
    finally:
        process.kill()
        process.wait()

