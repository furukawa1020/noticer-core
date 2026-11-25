"""Local process resource measurement with explicitly scoped energy proxies."""

from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from time import perf_counter_ns, process_time_ns
from tracemalloc import get_traced_memory, is_tracing, start, stop
from typing import TypeVar

T = TypeVar("T")
_MEASUREMENT = Lock()


@dataclass(frozen=True, slots=True)
class ProcessResources:
    wall_ns: int
    cpu_ns: int
    peak_python_bytes: int

    @property
    def energy_proxy_cpu_ns(self) -> int:
        """CPU time as a within-host activity proxy; not joules or total-system energy."""
        return self.cpu_ns


def measure_resources(work: Callable[[], T]) -> tuple[T, ProcessResources]:
    """Measure a synchronous workload on a dedicated Python process.

    Memory is the traced Python allocation peak, not RSS or native-library
    allocations. Do not compare timings across different instrumentation modes.
    """
    if not _MEASUREMENT.acquire(blocking=False):
        raise RuntimeError("resource measurements may not be nested or concurrent")
    try:
        if is_tracing():
            raise RuntimeError("an external tracemalloc measurement is already active")
        start()
        try:
            wall_start = perf_counter_ns()
            cpu_start = process_time_ns()
            value = work()
            cpu = process_time_ns() - cpu_start
            wall = perf_counter_ns() - wall_start
            _, peak = get_traced_memory()
        finally:
            stop()
        return value, ProcessResources(wall, cpu, peak)
    finally:
        _MEASUREMENT.release()
