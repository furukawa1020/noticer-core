"""Run the pinned AQRS external kernel checker without soft-failure paths."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import subprocess
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

SCHEMA = "noticer.aqrs.external_checker_lock.v1"
PolicyValue = bool | int | list[str]
EXPECTED_POLICY: dict[str, PolicyValue] = {
    "use_stdin": True,
    "nat_extension": True,
    "string_extension": True,
    "permitted_axioms": ["propext"],
    "unpermitted_axiom_hard_error": False,
    "unsafe_permit_all_axioms": False,
    "num_threads": 4,
}
MAX_CAPTURE_BYTES = 1024 * 1024
MAX_DIAGNOSTIC_CHARS = 4096


class ExternalCheckerError(RuntimeError):
    """A fail-closed external checker error."""


@dataclass(frozen=True)
class PinnedTool:
    """One source-pinned executable used by the external checking pipeline."""

    name: str | None
    repository: str
    revision: str
    binary: PurePosixPath


@dataclass(frozen=True)
class ExternalCheckerLock:
    """Validated immutable inputs for one external checking run."""

    lean_toolchain: str
    exporter: PinnedTool
    checker: PinnedTool
    policy: dict[str, PolicyValue]
    timeout_seconds: int
    max_export_bytes: int
    lock_digest: str


@dataclass(frozen=True)
class CheckerResult:
    """Sanitized result of an external checker process."""

    status: str
    return_code: int
    duration_ms: int
    stdout_sha256: str
    stderr_sha256: str


RevisionProbe = Callable[[Path], str]


def canonical_json(value: Any) -> bytes:
    """Encode a value using the repository's canonical JSON profile."""

    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def sha256_file(path: Path) -> str:
    """Return the lowercase SHA-256 digest of a file."""

    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_tool(value: Any, label: str) -> PinnedTool:
    expected_fields = {"repository", "revision", "binary"}
    if label == "checker":
        expected_fields.add("name")
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise ExternalCheckerError(f"{label} pin has unexpected fields")
    name = value.get("name")
    if label == "checker" and name != "nanoda":
        raise ExternalCheckerError("checker name must be nanoda")
    repository = value["repository"]
    revision = value["revision"]
    binary = value["binary"]
    if not all(isinstance(item, str) and item for item in (repository, revision, binary)):
        raise ExternalCheckerError(f"{label} pin contains an empty field")
    parsed = urlparse(repository)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or not repository.endswith(".git")
    ):
        raise ExternalCheckerError(f"{label} repository must be an HTTPS GitHub clone URL")
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        raise ExternalCheckerError(f"{label} revision must be a full lowercase commit SHA")
    binary_path = PurePosixPath(binary)
    if binary_path.is_absolute() or ".." in binary_path.parts:
        raise ExternalCheckerError(f"{label} binary must be a relative normalized path")
    return PinnedTool(name, repository, revision, binary_path)


def load_lock(path: Path) -> ExternalCheckerLock:
    """Load and strictly validate the external checker lock."""

    try:
        raw = path.read_bytes()
        document: dict[str, Any] = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise ExternalCheckerError(f"external checker lock could not be read: {error}") from error
    expected_fields = {
        "schema_version",
        "lean_toolchain",
        "exporter",
        "checker",
        "policy",
        "limits",
        "verification_status",
    }
    if set(document) != expected_fields or document["schema_version"] != SCHEMA:
        raise ExternalCheckerError("unexpected external checker lock schema")
    if document["lean_toolchain"] != "leanprover/lean4:v4.30.0":
        raise ExternalCheckerError("external checker lock must target Lean 4.30.0")
    if document["verification_status"] != "NOT_VERIFIED":
        raise ExternalCheckerError("checker cannot be promoted before a green compatibility run")
    if document["policy"] != EXPECTED_POLICY:
        raise ExternalCheckerError("external checker policy is not the fail-closed policy")
    limits = document["limits"]
    if not isinstance(limits, dict) or set(limits) != {"timeout_seconds", "max_export_bytes"}:
        raise ExternalCheckerError("external checker limits have unexpected fields")
    timeout_seconds = limits["timeout_seconds"]
    max_export_bytes = limits["max_export_bytes"]
    if not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 1800:
        raise ExternalCheckerError("external checker timeout is outside the accepted range")
    if not isinstance(max_export_bytes, int) or not 1 <= max_export_bytes <= 2**30:
        raise ExternalCheckerError("external checker export limit is outside the accepted range")
    return ExternalCheckerLock(
        lean_toolchain=document["lean_toolchain"],
        exporter=_load_tool(document["exporter"], "exporter"),
        checker=_load_tool(document["checker"], "checker"),
        policy=dict(document["policy"]),
        timeout_seconds=timeout_seconds,
        max_export_bytes=max_export_bytes,
        lock_digest=hashlib.sha256(canonical_json(document)).hexdigest(),
    )


def probe_git_revision(checkout: Path) -> str:
    """Read the exact checked-out Git revision without consulting the network."""

    try:
        completed = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ExternalCheckerError(f"could not inspect checker revision: {error}") from error
    if completed.returncode != 0:
        raise ExternalCheckerError("could not inspect checker revision")
    return completed.stdout.strip()


def resolve_pinned_binary(
    tool: PinnedTool,
    checkout: Path,
    revision_probe: RevisionProbe = probe_git_revision,
) -> Path:
    """Resolve an executable only after matching its checkout to the pinned commit."""

    actual_revision = revision_probe(checkout)
    if not hmac.compare_digest(actual_revision, tool.revision):
        raise ExternalCheckerError(
            f"checker revision mismatch: expected {tool.revision}, got {actual_revision}"
        )
    binary = checkout.joinpath(*tool.binary.parts)
    if not binary.is_file() or binary.is_symlink():
        raise ExternalCheckerError("pinned checker binary is missing or is a symbolic link")
    return binary.resolve(strict=True)


def execute_checker(
    command: Sequence[str],
    export_path: Path,
    policy: dict[str, PolicyValue],
    timeout_seconds: int,
) -> CheckerResult:
    """Execute a checker and convert every abnormal outcome into an error."""

    if not export_path.is_file() or export_path.is_symlink():
        raise ExternalCheckerError("Lean export is missing or is a symbolic link")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="aqrs-checker-") as temporary:
        root = Path(temporary)
        config_path = root / "config.json"
        stdout_path = root / "stdout.bin"
        stderr_path = root / "stderr.bin"
        config_path.write_bytes(canonical_json(policy) + b"\n")
        try:
            with (
                export_path.open("rb") as source,
                stdout_path.open("wb") as stdout,
                stderr_path.open("wb") as stderr,
            ):
                completed = subprocess.run(
                    [*command, str(config_path)],
                    stdin=source,
                    stdout=stdout,
                    stderr=stderr,
                    check=False,
                    timeout=timeout_seconds,
                )
        except subprocess.TimeoutExpired as error:
            raise ExternalCheckerError("external checker timed out") from error
        except OSError as error:
            raise ExternalCheckerError(f"external checker could not start: {error}") from error
        if (
            stdout_path.stat().st_size > MAX_CAPTURE_BYTES
            or stderr_path.stat().st_size > MAX_CAPTURE_BYTES
        ):
            raise ExternalCheckerError("external checker diagnostic output exceeded the limit")
        result = CheckerResult(
            status="VERIFIED" if completed.returncode == 0 else "REJECTED",
            return_code=completed.returncode,
            duration_ms=int((time.monotonic() - started) * 1000),
            stdout_sha256=sha256_file(stdout_path),
            stderr_sha256=sha256_file(stderr_path),
        )
        diagnostic = stderr_path.read_text(encoding="utf-8", errors="replace")
    if result.return_code != 0:
        diagnostic = "".join(
            character if character in "\n\r\t" or character.isprintable() else "?"
            for character in diagnostic[-MAX_DIAGNOSTIC_CHARS:]
        ).strip()
        raise ExternalCheckerError(
            f"external checker rejected export with code {result.return_code}; "
            f"stderr tail: {diagnostic or '<empty>'}"
        )
    return result


def run_pinned_checker(
    lock: ExternalCheckerLock,
    checker_checkout: Path,
    export_path: Path,
    artifact_path: Path,
    revision_probe: RevisionProbe = probe_git_revision,
) -> dict[str, Any]:
    """Run the source-pinned checker and write a sanitized success artifact."""

    size = export_path.stat().st_size if export_path.is_file() else -1
    if size < 1 or size > lock.max_export_bytes:
        raise ExternalCheckerError("Lean export size is outside the accepted range")
    binary = resolve_pinned_binary(lock.checker, checker_checkout, revision_probe)
    result = execute_checker(
        [str(binary)], export_path, lock.policy, lock.timeout_seconds
    )
    artifact: dict[str, Any] = {
        "schema_version": "noticer.aqrs.external_checker_result.v1",
        "status": result.status,
        "checker": lock.checker.name,
        "checker_revision": lock.checker.revision,
        "lean_toolchain": lock.lean_toolchain,
        "lock_digest": lock.lock_digest,
        "export_sha256": sha256_file(export_path),
        "policy_sha256": hashlib.sha256(canonical_json(lock.policy)).hexdigest(),
        "stdout_sha256": result.stdout_sha256,
        "stderr_sha256": result.stderr_sha256,
        "duration_ms": result.duration_ms,
    }
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_bytes(canonical_json(artifact) + b"\n")
    return artifact


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--checker-checkout", type=Path, required=True)
    parser.add_argument("--export", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    lock = load_lock(args.lock)
    artifact = run_pinned_checker(lock, args.checker_checkout, args.export, args.artifact)
    print(f"external checker verified export: {artifact['export_sha256']}")


if __name__ == "__main__":
    try:
        main()
    except ExternalCheckerError as error:
        raise SystemExit(f"external checker failed: {error}") from error
