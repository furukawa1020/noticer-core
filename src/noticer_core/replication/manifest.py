"""Build and verify the bounded QuotientSeal replication manifest."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

SPEC_SCHEMA = "quotient-seal.replication-manifest-spec.v1"
MANIFEST_SCHEMA = "quotient-seal.replication-manifest.v1"
MAX_SPEC_BYTES = 2 * 1024 * 1024
MAX_INVENTORY_FILE_BYTES = 512 * 1024 * 1024
MAX_INVENTORY_ENTRIES = 256
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
GIT_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")

_SPEC_KEYS = {
    "schema",
    "manifest_version",
    "repository",
    "toolchains",
    "k7_dependencies",
    "inventory",
    "evidence_origin",
    "security_interpretation",
    "hardware_status",
}
_REPOSITORY_KEYS = {"name", "baseline_commit", "revision_policy"}
_TOOLCHAIN_KEYS = {"name", "version", "source", "required_marker"}
_DEPENDENCY_KEYS = {"issue", "name", "commit"}
_INVENTORY_KEYS = {"kind", "path"}
_MANIFEST_KEYS = _SPEC_KEYS | {"artifact_sha256"}
_FILE_RECORD_KEYS = {"kind", "path", "bytes", "sha256"}
_TOOLCHAIN_RECORD_KEYS = _TOOLCHAIN_KEYS | {"source_sha256"}


class ManifestError(ValueError):
    """Raised when a replication contract fails closed."""


def _require_exact_keys(value: dict[str, Any], allowed: set[str], location: str) -> None:
    unknown = set(value) - allowed
    missing = allowed - set(value)
    if unknown or missing:
        raise ManifestError(
            f"{location} fields mismatch: unknown={sorted(unknown)}, missing={sorted(missing)}"
        )


def _require_string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value:
        raise ManifestError(f"{location} must be a non-empty string")
    return value


def canonical_json(value: Any) -> bytes:
    """Encode a value with the manifest's deterministic JSON profile."""

    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> tuple[int, str]:
    size = path.stat().st_size
    if size > MAX_INVENTORY_FILE_BYTES:
        raise ManifestError(f"inventory file exceeds byte bound: {path.name}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return size, digest.hexdigest()


def resolve_repository_file(root: Path, relative_path: str) -> Path:
    """Resolve one canonical POSIX repository path without following symlink escapes."""

    if "\\" in relative_path:
        raise ManifestError(f"repository path must use POSIX separators: {relative_path}")
    pure = PurePosixPath(relative_path)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts or "." in pure.parts:
        raise ManifestError(f"repository path is not canonical: {relative_path}")
    root_resolved = root.resolve(strict=True)
    candidate = root_resolved.joinpath(*pure.parts)
    if candidate.is_symlink():
        raise ManifestError(f"inventory symlink is not allowed: {relative_path}")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as error:
        raise ManifestError(f"inventory file is missing: {relative_path}") from error
    if root_resolved != resolved and root_resolved not in resolved.parents:
        raise ManifestError(f"inventory path escapes repository: {relative_path}")
    if not resolved.is_file():
        raise ManifestError(f"inventory path is not a file: {relative_path}")
    return resolved


def load_spec(spec_path: Path) -> dict[str, Any]:
    """Load and structurally validate a replication manifest specification."""

    if spec_path.stat().st_size > MAX_SPEC_BYTES:
        raise ManifestError("replication manifest spec exceeds byte bound")
    try:
        value = json.loads(spec_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ManifestError("replication manifest spec is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ManifestError("replication manifest spec must be an object")
    _require_exact_keys(value, _SPEC_KEYS, "spec")
    if value["schema"] != SPEC_SCHEMA or value["manifest_version"] != 1:
        raise ManifestError("replication manifest spec version is unsupported")

    repository = value["repository"]
    if not isinstance(repository, dict):
        raise ManifestError("repository provenance must be an object")
    _require_exact_keys(repository, _REPOSITORY_KEYS, "repository")
    _require_string(repository["name"], "repository.name")
    if not GIT_COMMIT_PATTERN.fullmatch(
        _require_string(repository["baseline_commit"], "baseline")
    ):
        raise ManifestError("repository baseline commit must be a full lowercase Git commit id")
    if repository["revision_policy"] != "DESCENDANT_OF_BASELINE":
        raise ManifestError("repository revision policy is unsupported")

    toolchains = value["toolchains"]
    if not isinstance(toolchains, list) or not toolchains:
        raise ManifestError("toolchains must be a non-empty list")
    toolchain_names: set[str] = set()
    for index, toolchain in enumerate(toolchains):
        if not isinstance(toolchain, dict):
            raise ManifestError(f"toolchains[{index}] must be an object")
        _require_exact_keys(toolchain, _TOOLCHAIN_KEYS, f"toolchains[{index}]")
        name = _require_string(toolchain["name"], f"toolchains[{index}].name")
        if name in toolchain_names:
            raise ManifestError(f"duplicate toolchain: {name}")
        toolchain_names.add(name)
        _require_string(toolchain["version"], f"toolchains[{index}].version")
        _require_string(toolchain["source"], f"toolchains[{index}].source")
        _require_string(toolchain["required_marker"], f"toolchains[{index}].required_marker")

    dependencies = value["k7_dependencies"]
    if not isinstance(dependencies, list) or len(dependencies) != 3:
        raise ManifestError("exactly three K7 dependency records are required")
    issues: set[int] = set()
    for index, dependency in enumerate(dependencies):
        if not isinstance(dependency, dict):
            raise ManifestError(f"k7_dependencies[{index}] must be an object")
        _require_exact_keys(dependency, _DEPENDENCY_KEYS, f"k7_dependencies[{index}]")
        issue = dependency["issue"]
        if not isinstance(issue, int) or issue <= 0 or issue in issues:
            raise ManifestError("K7 dependency issue numbers must be unique positive integers")
        issues.add(issue)
        _require_string(dependency["name"], f"k7_dependencies[{index}].name")
        commit = _require_string(dependency["commit"], f"k7_dependencies[{index}].commit")
        if not GIT_COMMIT_PATTERN.fullmatch(commit):
            raise ManifestError("K7 dependency commit must be a full lowercase hex id")

    inventory = value["inventory"]
    if (
        not isinstance(inventory, list)
        or not inventory
        or len(inventory) > MAX_INVENTORY_ENTRIES
    ):
        raise ManifestError("inventory count is outside its bound")
    paths: set[str] = set()
    for index, entry in enumerate(inventory):
        if not isinstance(entry, dict):
            raise ManifestError(f"inventory[{index}] must be an object")
        _require_exact_keys(entry, _INVENTORY_KEYS, f"inventory[{index}]")
        kind = _require_string(entry["kind"], f"inventory[{index}].kind")
        path = _require_string(entry["path"], f"inventory[{index}].path")
        if kind not in {"TOOLCHAIN", "LOCKFILE", "CONFIG", "SCHEMA", "SOURCE", "FORMAL", "DOC"}:
            raise ManifestError(f"unsupported inventory kind: {kind}")
        if path in paths:
            raise ManifestError(f"duplicate inventory path: {path}")
        paths.add(path)

    if value["evidence_origin"] != "REPOSITORY_CONTRACT":
        raise ManifestError("unexpected evidence origin")
    if value["security_interpretation"] != "NOT_A_SECURITY_VERDICT":
        raise ManifestError("unexpected security interpretation")
    if value["hardware_status"] != "NOT_VERIFIED":
        raise ManifestError("hardware status must remain NOT_VERIFIED")
    return value


def _manifest_digest(manifest: dict[str, Any]) -> str:
    unsigned = copy.deepcopy(manifest)
    unsigned["artifact_sha256"] = ""
    return _sha256_bytes(canonical_json(unsigned))


def build_manifest(root: Path, spec_path: Path) -> dict[str, Any]:
    """Build a deterministic manifest from one validated repository specification."""

    spec = load_spec(spec_path)
    toolchains: list[dict[str, Any]] = []
    for entry in spec["toolchains"]:
        source = resolve_repository_file(root, entry["source"])
        try:
            source_text = source.read_text(encoding="utf-8")
        except UnicodeError as error:
            raise ManifestError(f"toolchain source is not UTF-8: {entry['source']}") from error
        if entry["required_marker"] not in source_text:
            raise ManifestError(f"toolchain marker is missing: {entry['name']}")
        _, source_sha256 = _sha256_file(source)
        toolchains.append({**entry, "source_sha256": source_sha256})

    inventory: list[dict[str, Any]] = []
    for entry in spec["inventory"]:
        source = resolve_repository_file(root, entry["path"])
        size, sha256 = _sha256_file(source)
        inventory.append({**entry, "bytes": size, "sha256": sha256})

    manifest: dict[str, Any] = {
        **spec,
        "schema": MANIFEST_SCHEMA,
        "toolchains": sorted(toolchains, key=lambda item: item["name"]),
        "k7_dependencies": sorted(spec["k7_dependencies"], key=lambda item: item["issue"]),
        "inventory": sorted(inventory, key=lambda item: item["path"]),
        "artifact_sha256": "",
    }
    manifest["artifact_sha256"] = _manifest_digest(manifest)
    verify_manifest(root, manifest)
    return manifest


def verify_manifest(root: Path, manifest: dict[str, Any]) -> None:
    """Recompute every source digest and the manifest digest."""

    if not isinstance(manifest, dict):
        raise ManifestError("manifest must be an object")
    _require_exact_keys(manifest, _MANIFEST_KEYS, "manifest")
    if manifest["schema"] != MANIFEST_SCHEMA or manifest["manifest_version"] != 1:
        raise ManifestError("manifest schema is unsupported")
    artifact_sha256 = manifest["artifact_sha256"]
    if not isinstance(artifact_sha256, str) or not SHA256_PATTERN.fullmatch(artifact_sha256):
        raise ManifestError("manifest artifact digest is malformed")
    if artifact_sha256 != _manifest_digest(manifest):
        raise ManifestError("manifest artifact digest mismatch")

    for index, toolchain in enumerate(manifest["toolchains"]):
        if not isinstance(toolchain, dict):
            raise ManifestError(f"toolchains[{index}] must be an object")
        _require_exact_keys(toolchain, _TOOLCHAIN_RECORD_KEYS, f"toolchains[{index}]")
        source = resolve_repository_file(root, toolchain["source"])
        _, actual = _sha256_file(source)
        if toolchain["source_sha256"] != actual:
            raise ManifestError(f"toolchain source digest mismatch: {toolchain['name']}")
        if toolchain["required_marker"] not in source.read_text(encoding="utf-8"):
            raise ManifestError(f"toolchain marker mismatch: {toolchain['name']}")

    for index, entry in enumerate(manifest["inventory"]):
        if not isinstance(entry, dict):
            raise ManifestError(f"inventory[{index}] must be an object")
        _require_exact_keys(entry, _FILE_RECORD_KEYS, f"inventory[{index}]")
        source = resolve_repository_file(root, entry["path"])
        size, actual = _sha256_file(source)
        if entry["bytes"] != size or entry["sha256"] != actual:
            raise ManifestError(f"inventory digest mismatch: {entry['path']}")


def write_manifest(root: Path, spec_path: Path, output_path: Path) -> dict[str, Any]:
    """Build a manifest and atomically replace its generated output."""

    manifest = build_manifest(root, spec_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(f"{output_path.suffix}.tmp")
    temporary.write_bytes(canonical_json(manifest))
    temporary.replace(output_path)
    return manifest


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="QuotientSeal replication manifestを生成する")
    parser.add_argument("--root", type=Path, default=_repository_root())
    parser.add_argument(
        "--spec",
        type=Path,
        default=Path("replication/manifest_spec_v1.json"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/replication/manifest.json"),
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()
    spec = args.spec if args.spec.is_absolute() else root / args.spec
    output = args.output if args.output.is_absolute() else root / args.output
    manifest = write_manifest(root, spec, output)
    print(f"manifest: {output}")
    print(f"sha256: {manifest['artifact_sha256']}")
    print(f"hardware_status: {manifest['hardware_status']}")
    print(f"security_interpretation: {manifest['security_interpretation']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
