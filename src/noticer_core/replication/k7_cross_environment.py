"""Cross-environment semantic comparison for K7 replication artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Final

from noticer_core.replication.manifest import canonical_json

OBSERVATION_SCHEMA: Final = "noticer-core.k7-platform-observation.v1"
COMPARISON_SCHEMA: Final = "noticer-core.k7-cross-environment-comparison.v1"
_DIGEST_DOMAIN: Final = b"noticer-core/k7-cross-environment/v1\0"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OBSERVATION_KEYS: Final = {
    "schema",
    "platform",
    "contract_digest",
    "semantic_artifacts",
    "measurements",
    "audit_verdict",
}


class K7CrossEnvironmentError(ValueError):
    """Raised when a platform observation violates the public comparison contract."""


def _digest(value: object) -> str:
    return hashlib.sha256(_DIGEST_DOMAIN + canonical_json(value)).hexdigest()


def _public_string(value: object, location: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise K7CrossEnvironmentError(f"{location} must be a bounded string")
    lowered = value.lower()
    if any(marker in lowered for marker in ("secret", "subject_id", "raw_biosignal")):
        raise K7CrossEnvironmentError(f"{location} contains a private marker")
    if PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute():
        raise K7CrossEnvironmentError(f"{location} contains an absolute host path")
    return value


def validate_observation(value: object) -> dict[str, Any]:
    """Validate one bounded, public platform observation."""

    if not isinstance(value, dict) or set(value) != _OBSERVATION_KEYS:
        raise K7CrossEnvironmentError("platform observation fields are invalid")
    if value["schema"] != OBSERVATION_SCHEMA or value["platform"] not in {"windows", "linux"}:
        raise K7CrossEnvironmentError("platform observation schema or platform is invalid")
    contract_digest = value["contract_digest"]
    if not isinstance(contract_digest, str) or _SHA256.fullmatch(contract_digest) is None:
        raise K7CrossEnvironmentError("contract digest is invalid")
    if value["audit_verdict"] not in {"PASS", "FAIL"}:
        raise K7CrossEnvironmentError("audit verdict is invalid")
    artifacts = value["semantic_artifacts"]
    if not isinstance(artifacts, dict) or not 1 <= len(artifacts) <= 256:
        raise K7CrossEnvironmentError("semantic artifacts must be a bounded non-empty map")
    for path, digest in artifacts.items():
        _public_string(path, "semantic artifact path")
        pure = PurePosixPath(path)
        if "\\" in path or ".." in pure.parts or "." in pure.parts:
            raise K7CrossEnvironmentError("semantic artifact path is not canonical")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise K7CrossEnvironmentError("semantic artifact digest is invalid")
    measurements = value["measurements"]
    if not isinstance(measurements, dict) or len(measurements) > 128:
        raise K7CrossEnvironmentError("measurements must be a bounded map")
    for key, measurement in measurements.items():
        _public_string(key, "measurement key")
        _public_string(measurement, "measurement value")
    return value


def load_observation(path: Path) -> dict[str, Any]:
    """Load one UTF-8 platform observation with a byte bound."""

    if not path.is_file() or path.stat().st_size > 1_048_576:
        raise K7CrossEnvironmentError("platform observation is missing or too large")
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise K7CrossEnvironmentError("platform observation is not valid UTF-8 JSON") from error
    return validate_observation(value)


def compare_observations(observations: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Compare semantic digests while retaining platform measurements separately."""

    validated = [validate_observation(dict(item)) for item in observations]
    by_platform = {item["platform"]: item for item in validated}
    if len(validated) != 2 or set(by_platform) != {"windows", "linux"}:
        raise K7CrossEnvironmentError("exactly one Windows and one Linux observation are required")
    windows = by_platform["windows"]
    linux = by_platform["linux"]
    semantic_differences = []
    if windows["contract_digest"] != linux["contract_digest"]:
        semantic_differences.append(
            {
                "linux": linux["contract_digest"],
                "path": "@contract",
                "windows": windows["contract_digest"],
            }
        )
    artifact_paths = sorted(
        set(windows["semantic_artifacts"]) | set(linux["semantic_artifacts"])
    )
    for path in artifact_paths:
        left = windows["semantic_artifacts"].get(path, "MISSING")
        right = linux["semantic_artifacts"].get(path, "MISSING")
        if left != right:
            semantic_differences.append({"linux": right, "path": path, "windows": left})
    measurement_differences = []
    measurement_keys = sorted(set(windows["measurements"]) | set(linux["measurements"]))
    for key in measurement_keys:
        left = windows["measurements"].get(key, "MISSING")
        right = linux["measurements"].get(key, "MISSING")
        if left != right:
            measurement_differences.append({"key": key, "linux": right, "windows": left})
    semantic_status = "MATCH" if not semantic_differences else "DISAGREEMENT"
    audits_pass = windows["audit_verdict"] == linux["audit_verdict"] == "PASS"
    comparison: dict[str, Any] = {
        "audit_verdicts": {
            "linux": linux["audit_verdict"],
            "windows": windows["audit_verdict"],
        },
        "independent_replication": (
            "VERIFIED" if semantic_status == "MATCH" and audits_pass else "NOT_VERIFIED"
        ),
        "measurement_differences": measurement_differences,
        "schema": COMPARISON_SCHEMA,
        "semantic_differences": semantic_differences,
        "semantic_status": semantic_status,
    }
    comparison["comparison_digest"] = _digest(comparison)
    return comparison


def main(argv: Sequence[str] | None = None) -> int:
    """Compare independently produced Windows and Linux observations."""

    parser = argparse.ArgumentParser(description="K7 Windows/Linux再現結果を比較する")
    parser.add_argument("--windows", type=Path, required=True)
    parser.add_argument("--linux", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = compare_observations(
        [load_observation(args.windows), load_observation(args.linux)]
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json(report))
    return 0 if report["independent_replication"] == "VERIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
