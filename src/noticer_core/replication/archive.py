"""Deterministic, allowlisted QuotientSeal replication archives."""

from __future__ import annotations

import hashlib
import json
import math
import re
import zipfile
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Any, Final

from noticer_core.replication.decision import (
    DecisionError,
    evaluate_decision,
    verify_decision_report,
)
from noticer_core.replication.manifest import canonical_json

JsonObject = dict[str, Any]

_POLICY_SCHEMA: Final = "quotient-seal-archive-policy/v1"
_INDEX_SCHEMA: Final = "quotient-seal-replication-archive-index/v1"
_REPORT_SCHEMA: Final = "quotient-seal-final-report/v1"
_MAX_JSON_BYTES: Final = 2 * 1024 * 1024
_SHA256_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_PATH_RE: Final = re.compile(r"^[A-Za-z0-9._/-]{1,160}$")
_CODE_RE: Final = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SECRET_PATTERNS: Final = (
    re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(rb"Bearer[ \t]+[A-Za-z0-9._~+/-]{16,}", re.IGNORECASE),
    re.compile(
        rb"(?:password|api_key|access_token|refresh_token)[ \t]*=[ \t]*[^\s]{8,}",
        re.IGNORECASE,
    ),
)


class ArchiveError(ValueError):
    """Raised when an archive contract or package is invalid."""


def _reject_constant(value: str) -> None:
    raise ArchiveError(f"non-finite JSON number is forbidden: {value}")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_json_bytes(raw: bytes, label: str) -> JsonObject:
    if len(raw) > _MAX_JSON_BYTES:
        raise ArchiveError(f"{label} exceeds {_MAX_JSON_BYTES} bytes")
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArchiveError(f"{label} is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ArchiveError(f"{label} root must be an object")
    return value


def _load_json(
    source: Mapping[str, object] | Path,
    *,
    label: str,
) -> JsonObject:
    if isinstance(source, Path):
        try:
            raw = source.read_bytes()
        except OSError as exc:
            raise ArchiveError(f"cannot read {label}: {source}") from exc
        return _read_json_bytes(raw, label)
    if isinstance(source, Mapping):
        try:
            raw = json.dumps(source, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ArchiveError(f"{label} is not JSON-compatible") from exc
        return _read_json_bytes(raw, label)
    raise ArchiveError(f"{label} must be a mapping or pathlib.Path")


def _object(value: object, label: str) -> JsonObject:
    if not isinstance(value, dict):
        raise ArchiveError(f"{label} must be an object")
    return value


def _exact_keys(value: JsonObject, expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ArchiveError(
            f"{label} fields differ; "
            f"missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}"
        )


def _string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ArchiveError(f"{label} must be a string array")
    return value


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ArchiveError(f"{label} must be a positive integer")
    return value


def _canonical_path(value: object, label: str) -> str:
    if not isinstance(value, str) or _PATH_RE.fullmatch(value) is None:
        raise ArchiveError(f"{label} is not a bounded portable path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ArchiveError(f"{label} is not canonical")
    if path.as_posix() != value or "\\" in value:
        raise ArchiveError(f"{label} must use canonical POSIX separators")
    return value


def load_archive_policy(source: Mapping[str, object] | Path) -> JsonObject:
    """Load and strictly validate the deterministic archive policy."""

    policy = _load_json(source, label="archive policy")
    _exact_keys(
        policy,
        {
            "schema_version",
            "archive_format",
            "compression",
            "fixed_timestamp",
            "unix_mode",
            "index_path",
            "max_entries",
            "max_entry_bytes",
            "max_total_bytes",
            "required_entries",
            "prohibited_json_keys",
            "boundaries",
        },
        "archive policy",
    )
    if policy["schema_version"] != _POLICY_SCHEMA:
        raise ArchiveError("unsupported archive policy schema")
    if policy["archive_format"] != "ZIP" or policy["compression"] != "STORED":
        raise ArchiveError("v1 requires an uncompressed ZIP archive")
    if policy["fixed_timestamp"] != [1980, 1, 1, 0, 0, 0]:
        raise ArchiveError("v1 timestamp must be 1980-01-01T00:00:00")
    if policy["unix_mode"] != "100644":
        raise ArchiveError("v1 payload mode must be 100644")
    index_path = _canonical_path(policy["index_path"], "index_path")

    max_entries = _positive_int(policy["max_entries"], "max_entries")
    max_entry_bytes = _positive_int(policy["max_entry_bytes"], "max_entry_bytes")
    max_total_bytes = _positive_int(policy["max_total_bytes"], "max_total_bytes")
    if max_entries > 512 or max_entry_bytes > 128 * 1024 * 1024:
        raise ArchiveError("archive limits exceed the v1 safety ceiling")
    if max_total_bytes > 1024 * 1024 * 1024:
        raise ArchiveError("archive total limit exceeds 1 GiB")

    raw_entries = policy["required_entries"]
    if not isinstance(raw_entries, list) or not raw_entries:
        raise ArchiveError("required_entries must be a non-empty array")
    if len(raw_entries) + 1 > max_entries:
        raise ArchiveError("required entries exceed max_entries")
    paths: list[str] = []
    roles: set[str] = set()
    for index, raw_entry in enumerate(raw_entries):
        entry = _object(raw_entry, f"required_entries[{index}]")
        _exact_keys(
            entry,
            {"path", "media_type", "role"},
            f"required_entries[{index}]",
        )
        path = _canonical_path(entry["path"], f"required_entries[{index}].path")
        if path == index_path:
            raise ArchiveError("index_path may not also be a payload entry")
        if entry["media_type"] not in {"application/json", "text/markdown"}:
            raise ArchiveError("unsupported payload media type")
        role = entry["role"]
        if not isinstance(role, str) or _CODE_RE.fullmatch(role) is None:
            raise ArchiveError("payload role is invalid")
        paths.append(path)
        if role in roles:
            raise ArchiveError(f"duplicate payload role: {role}")
        roles.add(role)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ArchiveError("required entry paths must be unique and sorted")

    prohibited = _string_list(policy["prohibited_json_keys"], "prohibited_json_keys")
    if len(prohibited) != len(set(prohibited)) or any(
        not key or key != key.casefold() for key in prohibited
    ):
        raise ArchiveError("prohibited_json_keys must be unique case-folded names")
    boundaries = _string_list(policy["boundaries"], "boundaries")
    required_boundaries = {
        "DETERMINISTIC_ARCHIVE",
        "SOFTWARE_EVIDENCE_ONLY",
        "NOT_A_PROOF",
        "NOT_VERIFIED",
        "NO_PRIORITY_CLAIM",
    }
    if len(boundaries) != len(set(boundaries)) or not required_boundaries.issubset(
        boundaries
    ):
        raise ArchiveError("required archive boundaries are missing")
    return policy


def _payload_specs(policy: JsonObject) -> dict[str, JsonObject]:
    return {entry["path"]: entry for entry in policy["required_entries"]}


def _walk_json(value: object, prohibited: set[str], label: str) -> None:
    stack: list[tuple[object, int, str]] = [(value, 0, label)]
    nodes = 0
    while stack:
        current, depth, location = stack.pop()
        nodes += 1
        if depth > 32 or nodes > 100_000:
            raise ArchiveError(f"{label} exceeds JSON structural limits")
        if isinstance(current, dict):
            for key, child in current.items():
                if not isinstance(key, str):
                    raise ArchiveError(f"{location} contains a non-string key")
                if key.casefold() in prohibited:
                    raise ArchiveError(
                        f"{label} contains prohibited key at {location}.{key}"
                    )
                stack.append((child, depth + 1, f"{location}.{key}"))
        elif isinstance(current, list):
            stack.extend(
                (child, depth + 1, f"{location}[{index}]")
                for index, child in enumerate(current)
            )
        elif isinstance(current, float) and not math.isfinite(current):
            raise ArchiveError(f"{label} contains a non-finite number")


def _validate_exact_commands(value: JsonObject) -> JsonObject:
    _exact_keys(
        value,
        {"schema_version", "network_policy", "commands"},
        "exact commands",
    )
    if value["schema_version"] != "quotient-seal-exact-commands/v1":
        raise ArchiveError("exact commands schema is invalid")
    if value["network_policy"] != "OFFLINE":
        raise ArchiveError("replication commands must declare OFFLINE")
    commands = value["commands"]
    if not isinstance(commands, list) or not commands or len(commands) > 128:
        raise ArchiveError("commands must contain 1 to 128 entries")
    step_ids: list[str] = []
    for index, raw_command in enumerate(commands):
        command = _object(raw_command, f"commands[{index}]")
        _exact_keys(
            command,
            {"step_id", "argv", "expected_exit_code"},
            f"commands[{index}]",
        )
        step_id = command["step_id"]
        if not isinstance(step_id, str) or _CODE_RE.fullmatch(step_id) is None:
            raise ArchiveError("command step_id is invalid")
        argv = _string_list(command["argv"], f"commands[{index}].argv")
        if not argv or len(argv) > 64 or any(not arg or len(arg) > 512 for arg in argv):
            raise ArchiveError("command argv is empty or exceeds limits")
        if isinstance(command["expected_exit_code"], bool) or not isinstance(
            command["expected_exit_code"], int
        ):
            raise ArchiveError("expected_exit_code must be an integer")
        step_ids.append(step_id)
    if len(step_ids) != len(set(step_ids)):
        raise ArchiveError("command step_id values must be unique")
    return {"count": len(commands), "network_policy": "OFFLINE"}


def _validate_nonpass_outcomes(value: JsonObject) -> JsonObject:
    _exact_keys(
        value,
        {"schema_version", "declared_count", "outcomes"},
        "nonpass outcomes",
    )
    if value["schema_version"] != "quotient-seal-nonpass-outcomes/v1":
        raise ArchiveError("nonpass outcomes schema is invalid")
    outcomes = value["outcomes"]
    if not isinstance(outcomes, list) or len(outcomes) > 512:
        raise ArchiveError("outcomes must be a bounded array")
    if value["declared_count"] != len(outcomes):
        raise ArchiveError("declared nonpass outcome count does not match")
    counts: dict[str, int] = {}
    identities: set[tuple[str, str]] = set()
    for index, raw_outcome in enumerate(outcomes):
        outcome = _object(raw_outcome, f"outcomes[{index}]")
        _exact_keys(
            outcome,
            {"kind", "status", "reason_codes", "artifact_sha256"},
            f"outcomes[{index}]",
        )
        kind = outcome["kind"]
        status = outcome["status"]
        if not isinstance(kind, str) or _CODE_RE.fullmatch(kind) is None:
            raise ArchiveError("nonpass outcome kind is invalid")
        if status not in {"FAIL", "INCONCLUSIVE", "UNSUPPORTED", "RESOURCE_BOUND"}:
            raise ArchiveError("PASS or unknown status is forbidden in nonpass outcomes")
        reason_codes = _string_list(
            outcome["reason_codes"],
            f"outcomes[{index}].reason_codes",
        )
        if not reason_codes or len(reason_codes) != len(set(reason_codes)):
            raise ArchiveError("nonpass outcome reasons must be explicit and unique")
        if any(_CODE_RE.fullmatch(code) is None for code in reason_codes):
            raise ArchiveError("nonpass outcome reason code is invalid")
        digest = outcome["artifact_sha256"]
        if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
            raise ArchiveError("nonpass outcome artifact digest is invalid")
        identity = (kind, digest)
        if identity in identities:
            raise ArchiveError("duplicate nonpass outcome")
        identities.add(identity)
        counts[status] = counts.get(status, 0) + 1
    return {
        "declared_count": len(outcomes),
        "status_counts": {key: counts[key] for key in sorted(counts)},
    }


def _validate_studio_summary(value: JsonObject) -> None:
    _exact_keys(
        value,
        {
            "schema_version",
            "export_sha256",
            "size_bytes",
            "private_fields_included",
            "hardware_status",
        },
        "Studio export summary",
    )
    if value["schema_version"] != "quotient-seal-studio-export-summary/v1":
        raise ArchiveError("Studio export summary schema is invalid")
    digest = value["export_sha256"]
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        raise ArchiveError("Studio export digest is invalid")
    if (
        isinstance(value["size_bytes"], bool)
        or not isinstance(value["size_bytes"], int)
        or not 0 <= value["size_bytes"] <= 64 * 1024
    ):
        raise ArchiveError("Studio export size must be within 64 KiB")
    if value["private_fields_included"] is not False:
        raise ArchiveError("Studio summary must declare no private fields")
    if value["hardware_status"] != "NOT_VERIFIED":
        raise ArchiveError("Studio summary must remain NOT_VERIFIED")


def _validate_payload_semantics(
    contents: Mapping[str, bytes],
    policy: JsonObject,
) -> JsonObject:
    specs = _payload_specs(policy)
    parsed: dict[str, JsonObject] = {}
    prohibited = set(policy["prohibited_json_keys"])
    for path, data in contents.items():
        if path.startswith("evidence/") or path == "README.md":
            for pattern in _SECRET_PATTERNS:
                if pattern.search(data):
                    raise ArchiveError(f"credential-like bytes detected in {path}")
        if specs[path]["media_type"] == "application/json":
            document = _read_json_bytes(data, path)
            _walk_json(document, prohibited, path)
            parsed[path] = document
        else:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ArchiveError(f"{path} is not UTF-8 text") from exc
            if "\x00" in text:
                raise ArchiveError(f"{path} contains a NUL byte")

    if canonical_json(parsed["contracts/archive-policy.json"]) != canonical_json(policy):
        raise ArchiveError("archived policy does not match the active archive policy")
    command_summary = _validate_exact_commands(parsed["evidence/exact-commands.json"])
    nonpass_summary = _validate_nonpass_outcomes(
        parsed["evidence/nonpass-outcomes.json"]
    )
    _validate_studio_summary(parsed["evidence/studio-export-summary.json"])

    decision_policy = parsed["contracts/decision-policy.json"]
    decision_input = parsed["evidence/decision-input.json"]
    decision_report = parsed["evidence/decision.json"]
    try:
        expected_decision = evaluate_decision(decision_input, decision_policy)
        verify_decision_report(decision_report)
    except DecisionError as exc:
        raise ArchiveError(f"decision chain is invalid: {exc}") from exc
    if canonical_json(expected_decision) != canonical_json(decision_report):
        raise ArchiveError("archived decision does not reproduce from its input and policy")

    digest_links = {
        "manifest_sha256": "evidence/replication-manifest.json",
        "reproduction_sha256": "evidence/reproduction-report.json",
        "evidence_audit_sha256": "evidence/evidence-audit.json",
    }
    for field, path in digest_links.items():
        if decision_input["artifacts"][field] != _sha256(contents[path]):
            raise ArchiveError(f"decision input {field} does not match {path}")
    return {
        "source_commit": decision_report["source_commit"],
        "hardware_status": decision_report["hardware_status"],
        "decision": {
            "value": decision_report["decision"],
            "decision_id": decision_report["decision_id"],
            "report_sha256": decision_report["integrity"]["report_sha256"],
        },
        "command_summary": command_summary,
        "nonpass_summary": nonpass_summary,
    }


def _collect_payload(staging_dir: Path, policy: JsonObject) -> dict[str, bytes]:
    if staging_dir.is_symlink():
        raise ArchiveError("staging path may not be a symlink")
    try:
        root = staging_dir.resolve(strict=True)
    except OSError as exc:
        raise ArchiveError(f"staging directory does not exist: {staging_dir}") from exc
    if not root.is_dir():
        raise ArchiveError("staging path must be a real directory")
    specs = _payload_specs(policy)
    expected = set(specs)
    discovered: set[str] = set()
    for candidate in root.rglob("*"):
        relative = candidate.relative_to(root).as_posix()
        if candidate.is_symlink():
            raise ArchiveError(f"symlink is forbidden in staging: {relative}")
        if candidate.is_file():
            discovered.add(relative)
        elif not candidate.is_dir():
            raise ArchiveError(f"non-regular staging entry: {relative}")
        if len(discovered) > policy["max_entries"]:
            raise ArchiveError("staging entry count exceeds max_entries")
    if discovered != expected:
        raise ArchiveError(
            f"staging allowlist mismatch; "
            f"missing={sorted(expected - discovered)}, "
            f"unknown={sorted(discovered - expected)}"
        )
    contents: dict[str, bytes] = {}
    total = 0
    for path in sorted(expected):
        candidate = root.joinpath(*PurePosixPath(path).parts)
        try:
            data = candidate.read_bytes()
        except OSError as exc:
            raise ArchiveError(f"cannot read staging payload: {path}") from exc
        if len(data) > policy["max_entry_bytes"]:
            raise ArchiveError(f"payload exceeds max_entry_bytes: {path}")
        total += len(data)
        if total > policy["max_total_bytes"]:
            raise ArchiveError("payload total exceeds max_total_bytes")
        contents[path] = data
    return contents


def assemble_archive_staging(
    sources: Mapping[str, Path],
    staging_dir: Path,
    policy: Mapping[str, object] | Path,
) -> None:
    """Copy an exact source mapping into a new allowlisted staging directory."""

    checked_policy = load_archive_policy(policy)
    expected = set(_payload_specs(checked_policy))
    if set(sources) != expected:
        raise ArchiveError("source mapping must exactly equal the archive allowlist")
    if staging_dir.exists():
        raise ArchiveError("staging destination already exists")
    payload: dict[str, bytes] = {}
    total = 0
    for path in sorted(expected):
        source = sources[path]
        if not isinstance(source, Path) or source.is_symlink() or not source.is_file():
            raise ArchiveError(f"source is not a regular file: {path}")
        data = source.read_bytes()
        if len(data) > checked_policy["max_entry_bytes"]:
            raise ArchiveError(f"source exceeds max_entry_bytes: {path}")
        total += len(data)
        if total > checked_policy["max_total_bytes"]:
            raise ArchiveError("source total exceeds max_total_bytes")
        payload[path] = data
    _validate_payload_semantics(payload, checked_policy)
    staging_dir.mkdir(parents=True)
    for path, data in payload.items():
        destination = staging_dir.joinpath(*PurePosixPath(path).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)


def _index_bytes(index: Mapping[str, object]) -> bytes:
    return canonical_json(index) + b"\n"


def _make_index(
    contents: Mapping[str, bytes],
    policy: JsonObject,
    summary: JsonObject,
) -> JsonObject:
    specs = _payload_specs(policy)
    entries = [
        {
            "path": path,
            "role": specs[path]["role"],
            "media_type": specs[path]["media_type"],
            "size_bytes": len(contents[path]),
            "sha256": _sha256(contents[path]),
        }
        for path in sorted(contents)
    ]
    body: JsonObject = {
        "schema_version": _INDEX_SCHEMA,
        "archive_format": "ZIP_STORED",
        "fixed_timestamp": policy["fixed_timestamp"],
        "policy_sha256": _sha256(canonical_json(policy)),
        "source_commit": summary["source_commit"],
        "hardware_status": summary["hardware_status"],
        "decision": summary["decision"],
        "command_summary": summary["command_summary"],
        "nonpass_summary": summary["nonpass_summary"],
        "entries": entries,
        "boundaries": policy["boundaries"],
    }
    return {
        **body,
        "integrity": {
            "algorithm": "SHA-256",
            "coverage": "ALL_INDEX_FIELDS_EXCEPT_INTEGRITY",
            "index_sha256": _sha256(canonical_json(body)),
        },
    }


def _zip_info(path: str, policy: JsonObject) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, date_time=tuple(policy["fixed_timestamp"]))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    info.internal_attr = 0
    info.extra = b""
    info.comment = b""
    return info


def build_replication_archive(
    staging_dir: Path,
    output_path: Path,
    policy: Mapping[str, object] | Path,
) -> JsonObject:
    """Build a byte-deterministic ZIP and return its embedded index."""

    checked_policy = load_archive_policy(policy)
    if output_path.suffix.casefold() != ".zip":
        raise ArchiveError("archive output must use the .zip suffix")
    if output_path.exists():
        raise ArchiveError("archive output already exists")
    staging_root = staging_dir.resolve(strict=False)
    output_resolved = output_path.resolve(strict=False)
    if output_resolved == staging_root or staging_root in output_resolved.parents:
        raise ArchiveError("archive output may not be inside staging")
    contents = _collect_payload(staging_dir, checked_policy)
    try:
        summary = _validate_payload_semantics(contents, checked_policy)
    except (KeyError, TypeError) as exc:
        raise ArchiveError("payload semantic contract is incomplete") from exc
    index = _make_index(contents, checked_policy, summary)
    all_entries = {**contents, checked_policy["index_path"]: _index_bytes(index)}
    if any(len(data) > checked_policy["max_entry_bytes"] for data in all_entries.values()):
        raise ArchiveError("archive index or payload exceeds max_entry_bytes")
    if sum(len(data) for data in all_entries.values()) > checked_policy["max_total_bytes"]:
        raise ArchiveError("archive total exceeds max_total_bytes")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(f".{output_path.name}.tmp")
    if temporary.exists():
        raise ArchiveError("archive temporary path already exists")
    try:
        with zipfile.ZipFile(
            temporary,
            mode="w",
            compression=zipfile.ZIP_STORED,
            allowZip64=False,
            strict_timestamps=True,
        ) as archive:
            archive.comment = b""
            for path in sorted(all_entries):
                archive.writestr(_zip_info(path, checked_policy), all_entries[path])
        temporary.replace(output_path)
    except (OSError, RuntimeError, zipfile.LargeZipFile) as exc:
        temporary.unlink(missing_ok=True)
        raise ArchiveError(f"cannot create deterministic archive: {exc}") from exc
    return index


def _verify_index(index: JsonObject, policy: JsonObject) -> JsonObject:
    _exact_keys(
        index,
        {
            "schema_version",
            "archive_format",
            "fixed_timestamp",
            "policy_sha256",
            "source_commit",
            "hardware_status",
            "decision",
            "command_summary",
            "nonpass_summary",
            "entries",
            "boundaries",
            "integrity",
        },
        "archive index",
    )
    if index["schema_version"] != _INDEX_SCHEMA:
        raise ArchiveError("unsupported archive index schema")
    if index["archive_format"] != "ZIP_STORED":
        raise ArchiveError("archive index format is invalid")
    if index["fixed_timestamp"] != policy["fixed_timestamp"]:
        raise ArchiveError("archive index timestamp differs from policy")
    if index["policy_sha256"] != _sha256(canonical_json(policy)):
        raise ArchiveError("archive index policy digest mismatch")
    integrity = _object(index["integrity"], "archive index integrity")
    _exact_keys(
        integrity,
        {"algorithm", "coverage", "index_sha256"},
        "archive index integrity",
    )
    if integrity["algorithm"] != "SHA-256" or integrity["coverage"] != (
        "ALL_INDEX_FIELDS_EXCEPT_INTEGRITY"
    ):
        raise ArchiveError("archive index integrity contract is invalid")
    body = {key: value for key, value in index.items() if key != "integrity"}
    if integrity["index_sha256"] != _sha256(canonical_json(body)):
        raise ArchiveError("archive index SHA-256 mismatch")
    return index


def verify_replication_archive(
    archive_path: Path,
    policy: Mapping[str, object] | Path,
) -> JsonObject:
    """Verify ZIP metadata, bytes, semantic links, and embedded index."""

    checked_policy = load_archive_policy(policy)
    specs = _payload_specs(checked_policy)
    expected_names = sorted([*specs, checked_policy["index_path"]])
    contents: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(archive_path, mode="r", allowZip64=False) as archive:
            if archive.comment != b"":
                raise ArchiveError("archive comment must be empty")
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if names != expected_names or len(names) != len(set(names)):
                raise ArchiveError("archive entry order or allowlist is invalid")
            total = 0
            for info in infos:
                _canonical_path(info.filename, "archive entry")
                if info.is_dir() or info.compress_type != zipfile.ZIP_STORED:
                    raise ArchiveError("archive entries must be regular and stored")
                if info.date_time != tuple(checked_policy["fixed_timestamp"]):
                    raise ArchiveError("archive entry timestamp is not fixed")
                if info.create_system != 3 or info.external_attr >> 16 != 0o100644:
                    raise ArchiveError("archive entry mode is not fixed")
                if info.extra or info.comment or info.flag_bits & 0x1:
                    raise ArchiveError("archive entry has forbidden metadata")
                if info.file_size > checked_policy["max_entry_bytes"]:
                    raise ArchiveError("archive entry exceeds max_entry_bytes")
                total += info.file_size
                if total > checked_policy["max_total_bytes"]:
                    raise ArchiveError("archive exceeds max_total_bytes")
                contents[info.filename] = archive.read(info)
    except ArchiveError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise ArchiveError(f"cannot verify archive: {exc}") from exc

    index = _verify_index(
        _read_json_bytes(contents.pop(checked_policy["index_path"]), "archive index"),
        checked_policy,
    )
    indexed_entries = index["entries"]
    if not isinstance(indexed_entries, list):
        raise ArchiveError("archive index entries must be an array")
    expected_records = [
        {
            "path": path,
            "role": specs[path]["role"],
            "media_type": specs[path]["media_type"],
            "size_bytes": len(contents[path]),
            "sha256": _sha256(contents[path]),
        }
        for path in sorted(contents)
    ]
    if indexed_entries != expected_records:
        raise ArchiveError("archive payload does not match its index")
    try:
        summary = _validate_payload_semantics(contents, checked_policy)
    except (KeyError, TypeError) as exc:
        raise ArchiveError("archive semantic contract is incomplete") from exc
    for field in {
        "source_commit",
        "hardware_status",
        "decision",
        "command_summary",
        "nonpass_summary",
    }:
        if index[field] != summary[field]:
            raise ArchiveError(f"archive index summary mismatch: {field}")
    return index


def build_final_report(
    archive_path: Path,
    policy: Mapping[str, object] | Path,
) -> JsonObject:
    """Build a deterministic sidecar report for a verified archive."""

    checked_policy = load_archive_policy(policy)
    index = verify_replication_archive(archive_path, checked_policy)
    archive_bytes = archive_path.read_bytes()
    body: JsonObject = {
        "schema_version": _REPORT_SCHEMA,
        "archive_name": archive_path.name,
        "archive_sha256": _sha256(archive_bytes),
        "archive_size_bytes": len(archive_bytes),
        "archive_index_sha256": index["integrity"]["index_sha256"],
        "policy_sha256": index["policy_sha256"],
        "source_commit": index["source_commit"],
        "hardware_status": index["hardware_status"],
        "decision": index["decision"],
        "payload_count": len(index["entries"]),
        "command_summary": index["command_summary"],
        "nonpass_summary": index["nonpass_summary"],
        "verification": {
            "verdict": "PASS",
            "checks": [
                "ALLOWLIST",
                "FIXED_ZIP_METADATA",
                "PAYLOAD_DIGESTS",
                "DECISION_REPLAY",
                "EVIDENCE_CROSS_LINKS",
                "NONPASS_LEDGER",
                "SECRET_GUARD",
            ],
        },
        "boundaries": checked_policy["boundaries"],
    }
    return {
        **body,
        "integrity": {
            "algorithm": "SHA-256",
            "coverage": "ALL_FINAL_REPORT_FIELDS_EXCEPT_INTEGRITY",
            "report_sha256": _sha256(canonical_json(body)),
        },
    }


def verify_final_report(
    report: Mapping[str, object] | Path,
    archive_path: Path,
    policy: Mapping[str, object] | Path,
) -> None:
    """Verify a final report by independently rebuilding its expected value."""

    document = _load_json(report, label="final report")
    expected = build_final_report(archive_path, policy)
    if canonical_json(document) != canonical_json(expected):
        raise ArchiveError("final report does not match the verified archive")


def write_final_report(
    report: Mapping[str, object],
    output_path: Path,
    archive_path: Path,
    policy: Mapping[str, object] | Path,
) -> None:
    """Write a verified final report as canonical UTF-8 JSON."""

    verify_final_report(report, archive_path, policy)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(canonical_json(report) + b"\n")
