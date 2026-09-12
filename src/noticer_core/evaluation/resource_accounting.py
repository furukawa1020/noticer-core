"""Cross-platform, direct-child resource accounting for K7 scalability runs."""

from __future__ import annotations

import ctypes
import json
import os
import re
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol

SCHEMA: Final = "noticer.k7.resource-accounting.v1"
SAMPLER_VERSION: Final = "k7-direct-child-v1"
NOT_AVAILABLE: Final = "NOT_AVAILABLE"
_CASE_ID = re.compile(r"^[a-z][a-z0-9-]{2,95}$")


class ResourceAccountingError(ValueError):
    """A process or resource artifact violated the accounting contract."""


@dataclass(frozen=True, slots=True)
class ProcessCounters:
    """One best-effort OS reading for a direct child process."""

    user_cpu_ns: int | None
    system_cpu_ns: int | None
    resident_bytes: int | None
    peak_rss_bytes: int | None


@dataclass(frozen=True, slots=True)
class ResourceMeasurement:
    """Final monotonic counters for exactly one direct child."""

    wall_time_ns: int
    user_cpu_ns: int | None
    system_cpu_ns: int | None
    peak_rss_bytes: int | None
    exit_code: int
    timed_out: bool
    sample_count: int


class CounterReader(Protocol):
    """Internal protocol allowing deterministic sampler tests."""

    def read(self, process_id: int) -> ProcessCounters:
        """Read counters or return ``None`` for unavailable metrics."""


class ProcessResourceSampler:
    """Poll direct-child resource counters without collecting host identity."""

    def __init__(self, reader: CounterReader | None = None) -> None:
        self._reader = reader or _native_reader()

    def measure(
        self,
        process: subprocess.Popen[bytes],
        *,
        timeout_ms: int,
        poll_interval_ms: int = 10,
    ) -> ResourceMeasurement:
        """Measure an already-started direct child, killing it at the timeout."""

        if timeout_ms <= 0:
            raise ResourceAccountingError("timeout_ms must be positive")
        if poll_interval_ms <= 0 or poll_interval_ms > timeout_ms:
            raise ResourceAccountingError("poll_interval_ms must be in 1..timeout_ms")

        started = time.perf_counter_ns()
        deadline = started + timeout_ms * 1_000_000
        user_cpu_ns: int | None = None
        system_cpu_ns: int | None = None
        peak_rss_bytes: int | None = None
        sample_count = 0
        timed_out = False

        while True:
            counters = self._read_safely(process.pid)
            sample_count += 1
            user_cpu_ns = _monotonic_optional(user_cpu_ns, counters.user_cpu_ns)
            system_cpu_ns = _monotonic_optional(system_cpu_ns, counters.system_cpu_ns)
            peak_rss_bytes = _maximum_optional(
                peak_rss_bytes,
                _maximum_optional(counters.resident_bytes, counters.peak_rss_bytes),
            )
            exit_code = process.poll()
            if exit_code is not None:
                break
            now = time.perf_counter_ns()
            if now >= deadline:
                timed_out = True
                process.kill()
                exit_code = process.wait()
                break
            remaining_ns = deadline - now
            time.sleep(min(poll_interval_ms / 1_000, remaining_ns / 1_000_000_000))

        wall_time_ns = max(1, time.perf_counter_ns() - started)
        return ResourceMeasurement(
            wall_time_ns=wall_time_ns,
            user_cpu_ns=user_cpu_ns,
            system_cpu_ns=system_cpu_ns,
            peak_rss_bytes=peak_rss_bytes,
            exit_code=exit_code,
            timed_out=timed_out,
            sample_count=sample_count,
        )

    def _read_safely(self, process_id: int) -> ProcessCounters:
        try:
            return self._reader.read(process_id)
        except (OSError, ValueError):
            return ProcessCounters(None, None, None, None)


def measure_command(
    command: Sequence[str],
    *,
    cwd: Path,
    timeout_ms: int,
    poll_interval_ms: int = 10,
    sampler: ProcessResourceSampler | None = None,
) -> ResourceMeasurement:
    """Run and measure one direct child without a shell or captured payload."""

    if not command or any(type(part) is not str or not part for part in command):
        raise ResourceAccountingError("command must contain non-empty strings")
    process = subprocess.Popen(
        list(command),
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
    )
    return (sampler or ProcessResourceSampler()).measure(
        process,
        timeout_ms=timeout_ms,
        poll_interval_ms=poll_interval_ms,
    )


def build_resource_artifact(
    case_id: str, measurement: ResourceMeasurement
) -> dict[str, object]:
    """Build a host-identity-free artifact with explicit unavailable values."""

    if _CASE_ID.fullmatch(case_id) is None:
        raise ResourceAccountingError("case_id must be canonical")
    artifact: dict[str, object] = {
        "schema": SCHEMA,
        "sampler_version": SAMPLER_VERSION,
        "case_id": case_id,
        "scope": "DIRECT_CHILD_ONLY",
        "units": {
            "wall_time": "nanoseconds",
            "cpu_time": "nanoseconds",
            "peak_rss": "bytes",
        },
        "measurement": {
            "wall_time_ns": measurement.wall_time_ns,
            "user_cpu_ns": _available(measurement.user_cpu_ns),
            "system_cpu_ns": _available(measurement.system_cpu_ns),
            "peak_rss_bytes": _available(measurement.peak_rss_bytes),
            "exit_code": measurement.exit_code,
            "timed_out": measurement.timed_out,
            "sample_count": measurement.sample_count,
        },
        "excluded": [
            "DESCENDANT_PROCESSES",
            "HOST_IDENTITY",
            "COMMAND_AND_PAYLOAD",
        ],
    }
    _validate_artifact(artifact)
    return artifact


def write_resource_artifact(path: Path, artifact: Mapping[str, object]) -> Path:
    """Write canonical JSON idempotently and reject conflicting replacement."""

    _validate_artifact(artifact)
    payload = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if path.exists():
        if path.read_bytes() != payload:
            raise FileExistsError("existing resource artifact differs")
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)
    return path


class _UnavailableReader:
    def read(self, process_id: int) -> ProcessCounters:
        return ProcessCounters(None, None, None, None)


class _LinuxProcReader:
    def __init__(self) -> None:
        self._clock_ticks = os.sysconf("SC_CLK_TCK")
        self._page_size = os.sysconf("SC_PAGE_SIZE")

    def read(self, process_id: int) -> ProcessCounters:
        stat = Path(f"/proc/{process_id}/stat").read_text(encoding="ascii")
        remainder = stat[stat.rfind(")") + 2 :].split()
        user_cpu_ns = int(int(remainder[11]) * 1_000_000_000 / self._clock_ticks)
        system_cpu_ns = int(int(remainder[12]) * 1_000_000_000 / self._clock_ticks)
        resident_bytes = int(remainder[21]) * self._page_size
        peak_rss_bytes = None
        status = Path(f"/proc/{process_id}/status").read_text(encoding="ascii")
        for line in status.splitlines():
            if line.startswith("VmHWM:"):
                peak_rss_bytes = int(line.split()[1]) * 1_024
                break
        return ProcessCounters(user_cpu_ns, system_cpu_ns, resident_bytes, peak_rss_bytes)


class _WindowsReader:
    _PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    _PROCESS_VM_READ = 0x0010

    class _FileTime(ctypes.Structure):
        _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]

    class _MemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_uint32),
            ("page_fault_count", ctypes.c_uint32),
            ("peak_working_set_size", ctypes.c_size_t),
            ("working_set_size", ctypes.c_size_t),
            ("quota_peak_paged_pool_usage", ctypes.c_size_t),
            ("quota_paged_pool_usage", ctypes.c_size_t),
            ("quota_peak_non_paged_pool_usage", ctypes.c_size_t),
            ("quota_non_paged_pool_usage", ctypes.c_size_t),
            ("pagefile_usage", ctypes.c_size_t),
            ("peak_pagefile_usage", ctypes.c_size_t),
            ("private_usage", ctypes.c_size_t),
        ]

    def read(self, process_id: int) -> ProcessCounters:
        kernel32 = ctypes.windll.kernel32
        psapi = ctypes.windll.psapi
        handle = kernel32.OpenProcess(
            self._PROCESS_QUERY_LIMITED_INFORMATION | self._PROCESS_VM_READ,
            False,
            process_id,
        )
        if not handle:
            raise OSError("OpenProcess failed")
        try:
            creation = self._FileTime()
            exit_time = self._FileTime()
            kernel = self._FileTime()
            user = self._FileTime()
            if not kernel32.GetProcessTimes(
                handle,
                ctypes.byref(creation),
                ctypes.byref(exit_time),
                ctypes.byref(kernel),
                ctypes.byref(user),
            ):
                raise OSError("GetProcessTimes failed")
            memory = self._MemoryCounters()
            memory.cb = ctypes.sizeof(memory)
            if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(memory), memory.cb):
                raise OSError("GetProcessMemoryInfo failed")
            return ProcessCounters(
                _filetime_ns(user),
                _filetime_ns(kernel),
                int(memory.working_set_size),
                int(memory.peak_working_set_size),
            )
        finally:
            kernel32.CloseHandle(handle)


def _native_reader() -> CounterReader:
    if os.name == "nt":
        return _WindowsReader()
    if os.name == "posix" and Path("/proc/self/stat").exists():
        return _LinuxProcReader()
    return _UnavailableReader()


def _filetime_ns(value: _WindowsReader._FileTime) -> int:
    return ((value.high << 32) | value.low) * 100


def _monotonic_optional(previous: int | None, current: int | None) -> int | None:
    if current is None:
        return previous
    if current < 0:
        raise ValueError("resource counter cannot be negative")
    return current if previous is None else max(previous, current)


def _maximum_optional(left: int | None, right: int | None) -> int | None:
    values = [value for value in (left, right) if value is not None]
    if any(value < 0 for value in values):
        raise ValueError("resource counter cannot be negative")
    return max(values) if values else None


def _available(value: int | None) -> int | str:
    return NOT_AVAILABLE if value is None else value


def _validate_artifact(artifact: Mapping[str, object]) -> None:
    forbidden = {"pid", "hostname", "username", "command", "biosignal", "subject_id"}
    stack: list[object] = [artifact]
    while stack:
        value = stack.pop()
        if isinstance(value, Mapping):
            for key, child in value.items():
                if str(key).lower() in forbidden:
                    raise ResourceAccountingError(f"forbidden artifact field: {key}")
                stack.append(child)
        elif isinstance(value, list):
            stack.extend(value)
    if artifact.get("schema") != SCHEMA or artifact.get("scope") != "DIRECT_CHILD_ONLY":
        raise ResourceAccountingError("unsupported resource artifact")

