"""Deterministic public Tier B receipts from private Polar collection metadata."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from typing import Any

SCHEMA = "noticer.k5.tier_b_private_log.v1"
RECEIPT_SCHEMA = "noticer.k5.tier_b_public_receipt.v1"
DOMAIN = b"NOTICER-K5-TIER-B-RECEIPT-V1\x00"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ROOT_FIELDS = frozenset(
    {
        "schema",
        "provenance",
        "preflight_digest",
        "private_bundle_sha256",
        "polar_sdk_version",
        "firmware_version",
        "battery_percent_start",
        "battery_percent_end",
        "streams",
        "windows",
        "resources",
    }
)
_STREAM_FIELDS = frozenset({"negotiated_rate_hz", "frames"})
_FRAME_FIELDS = frozenset({"sequence", "first_timestamp_ns", "last_timestamp_ns", "sample_count"})
_WINDOW_FIELDS = frozenset({"quality_pass", "latency_ms", "k1_decision_emitted"})
_RESOURCE_FIELDS = frozenset({"memory_mb", "cpu_percent"})


class TierBReceiptError(ValueError):
    """A fail-closed Tier B receipt construction error."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def _exact_fields(value: Mapping[str, Any], expected: frozenset[str], location: str) -> None:
    if set(value) != expected:
        raise TierBReceiptError(f"{location} fields differ from the private log contract")


def _number(value: object, field: str, *, minimum: float = 0.0) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value):
        raise TierBReceiptError(f"{field} must be a finite number")
    result = float(value)
    if result < minimum:
        raise TierBReceiptError(f"{field} must be at least {minimum}")
    return result


def _hash(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise TierBReceiptError(f"{field} must be lowercase SHA-256")
    return value


def _stream_metrics(stream: object, expected_rate: int, label: str) -> tuple[int, int, int, int]:
    if not isinstance(stream, Mapping):
        raise TierBReceiptError(f"streams.{label} must be an object")
    _exact_fields(stream, _STREAM_FIELDS, f"streams.{label}")
    if stream["negotiated_rate_hz"] != expected_rate:
        raise TierBReceiptError(f"streams.{label} negotiated rate must be {expected_rate} Hz")
    frames = stream["frames"]
    if not isinstance(frames, Sequence) or isinstance(frames, (str, bytes)) or not frames:
        raise TierBReceiptError(f"streams.{label}.frames must be a non-empty array")
    if len(frames) > 100_000:
        raise TierBReceiptError(f"streams.{label}.frames exceeds the bound")
    gap_count = 0
    rollback_count = 0
    total_samples = 0
    first_timestamp = -1
    last_timestamp = -1
    previous_sequence: int | None = None
    previous_last: int | None = None
    expected_period = 1_000_000_000 / expected_rate
    for index, frame in enumerate(frames):
        if not isinstance(frame, Mapping):
            raise TierBReceiptError(f"streams.{label}.frames[{index}] must be an object")
        _exact_fields(frame, _FRAME_FIELDS, f"streams.{label}.frames[{index}]")
        sequence = frame["sequence"]
        start = frame["first_timestamp_ns"]
        end = frame["last_timestamp_ns"]
        count = frame["sample_count"]
        integer_fields = (sequence, start, end, count)
        if not all(
            isinstance(item, int) and not isinstance(item, bool) for item in integer_fields
        ):
            raise TierBReceiptError(f"streams.{label}.frames[{index}] fields must be integers")
        if sequence < 0 or start < 0 or end < start or count < 1:
            raise TierBReceiptError(f"streams.{label}.frames[{index}] has invalid bounds")
        if count > 1:
            observed_rate = (count - 1) * 1_000_000_000 / (end - start)
            if abs(observed_rate - expected_rate) > expected_rate * 0.01:
                raise TierBReceiptError(
                    f"streams.{label}.frames[{index}] observed rate is out of tolerance"
                )
        if previous_sequence is not None:
            if sequence <= previous_sequence or start <= (previous_last or 0):
                rollback_count += 1
            elif (
                sequence > previous_sequence + 1
                or start - (previous_last or 0) > expected_period * 2
            ):
                gap_count += 1
        if first_timestamp < 0:
            first_timestamp = start
        last_timestamp = max(last_timestamp, end)
        total_samples += count
        previous_sequence = sequence
        previous_last = end
    return first_timestamp, last_timestamp, gap_count, rollback_count


def _nearest_rank_p95(values: Sequence[float]) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def build_tier_b_receipt(private_log: Mapping[str, Any]) -> dict[str, Any]:
    """Aggregate private metadata into a bounded non-identifying public receipt."""

    _exact_fields(private_log, _ROOT_FIELDS, "root")
    if private_log["schema"] != SCHEMA:
        raise TierBReceiptError("unexpected Tier B private log schema")
    provenance = private_log["provenance"]
    if provenance not in {"PHYSICAL_MEASUREMENT", "SOFTWARE_FIXTURE"}:
        raise TierBReceiptError("unsupported Tier B provenance")
    preflight_digest = _hash(private_log["preflight_digest"], "preflight_digest")
    private_bundle = _hash(private_log["private_bundle_sha256"], "private_bundle_sha256")
    if private_log["polar_sdk_version"] != "8.1.0":
        raise TierBReceiptError("Polar SDK must be 8.1.0")
    firmware_recorded = isinstance(private_log["firmware_version"], str) and bool(
        private_log["firmware_version"].strip()
    )
    if not firmware_recorded:
        raise TierBReceiptError("firmware version must be recorded privately")
    streams = private_log["streams"]
    if not isinstance(streams, Mapping) or set(streams) != {"ppg", "acc"}:
        raise TierBReceiptError("streams must contain exactly ppg and acc")
    ppg_start, ppg_end, ppg_gaps, ppg_rollbacks = _stream_metrics(streams["ppg"], 55, "ppg")
    acc_start, acc_end, acc_gaps, acc_rollbacks = _stream_metrics(streams["acc"], 52, "acc")
    duration_seconds = min(ppg_end, acc_end) - max(ppg_start, acc_start)
    duration_seconds /= 1_000_000_000

    windows = private_log["windows"]
    if not isinstance(windows, Sequence) or isinstance(windows, (str, bytes)) or not windows:
        raise TierBReceiptError("windows must be a non-empty array")
    latencies: list[float] = []
    quality_count = 0
    decision_count = 0
    for index, window in enumerate(windows):
        if not isinstance(window, Mapping):
            raise TierBReceiptError(f"windows[{index}] must be an object")
        _exact_fields(window, _WINDOW_FIELDS, f"windows[{index}]")
        if not isinstance(window["quality_pass"], bool) or not isinstance(
            window["k1_decision_emitted"], bool
        ):
            raise TierBReceiptError(f"windows[{index}] flags must be boolean")
        latencies.append(_number(window["latency_ms"], f"windows[{index}].latency_ms"))
        quality_count += int(window["quality_pass"])
        decision_count += int(window["k1_decision_emitted"])

    resources = private_log["resources"]
    if not isinstance(resources, Sequence) or isinstance(resources, (str, bytes)) or not resources:
        raise TierBReceiptError("resources must be a non-empty array")
    memory: list[float] = []
    cpu: list[float] = []
    for index, sample in enumerate(resources):
        if not isinstance(sample, Mapping):
            raise TierBReceiptError(f"resources[{index}] must be an object")
        _exact_fields(sample, _RESOURCE_FIELDS, f"resources[{index}]")
        memory.append(_number(sample["memory_mb"], f"resources[{index}].memory_mb"))
        value = _number(sample["cpu_percent"], f"resources[{index}].cpu_percent")
        if value > 100:
            raise TierBReceiptError(f"resources[{index}].cpu_percent must not exceed 100")
        cpu.append(value)
    battery_start = _number(private_log["battery_percent_start"], "battery_percent_start")
    battery_end = _number(private_log["battery_percent_end"], "battery_percent_end")
    if battery_start > 100 or battery_end > 100 or battery_end > battery_start:
        raise TierBReceiptError("battery percentages are inconsistent")

    measurements = {
        "duration_seconds": duration_seconds,
        "ppg_rate_hz": 55,
        "acc_rate_hz": 52,
        "polar_sdk_version": "8.1.0",
        "firmware_recorded": True,
        "gap_count": ppg_gaps + acc_gaps,
        "rollback_count": ppg_rollbacks + acc_rollbacks,
        "window_count": len(windows),
        "quality_pass_rate": quality_count / len(windows),
        "latency_ms_p95": _nearest_rank_p95(latencies),
        "peak_memory_mb": max(memory),
        "mean_cpu_percent": sum(cpu) / len(cpu),
        "battery_drop_percent": battery_start - battery_end,
        "k1_decision_count": decision_count,
        "k1_live_input_confirmed": provenance == "PHYSICAL_MEASUREMENT" and decision_count > 0,
    }
    body = {
        "schema": RECEIPT_SCHEMA,
        "tier": "B",
        "hardware_status": "NOT_VERIFIED",
        "review_status": (
            "READY_FOR_PHYSICAL_REVIEW"
            if provenance == "PHYSICAL_MEASUREMENT"
            else "SOFTWARE_FIXTURE_ONLY"
        ),
        "provenance": provenance,
        "preflight_digest": preflight_digest,
        "private_bundle_sha256": private_bundle,
        "measurements": measurements,
    }
    return {**body, "receipt_digest": hashlib.sha256(DOMAIN + _canonical_json(body)).hexdigest()}
