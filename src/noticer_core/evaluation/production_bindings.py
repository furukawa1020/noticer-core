"""Production backend registry and run-lock binding for K7 scalability runs."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import yaml

BACKEND_IDS = ("reference", "cegis", "smt", "qbf")
FORBIDDEN_EXECUTABLE_MARKERS = ("fixture", "helper", "mock", "test")


class ProductionBindingError(ValueError):
    """Raised when a production backend binding fails closed."""


@dataclass(frozen=True)
class ProductionBinding:
    backend_id: str
    path: Path
    digest_sha256: str
    executable_name: str
    argument_templates: tuple[str, ...]


@dataclass(frozen=True)
class ProductionCommand:
    backend_id: str
    executable: Path
    argv: tuple[str, ...]
    binding_sha256: str
    executable_sha256: str


@dataclass(frozen=True)
class ProductionBindingRegistry:
    root: Path
    registry_path: Path
    registry_sha256: str
    bindings: Mapping[str, ProductionBinding]

    def command(
        self,
        backend_id: str,
        executable: Path,
        values: Mapping[str, object],
    ) -> ProductionCommand:
        binding = self.bindings.get(backend_id)
        if binding is None:
            raise ProductionBindingError(f"unknown backend: {backend_id}")
        resolved = executable.resolve()
        if not resolved.is_file():
            raise ProductionBindingError(f"production executable is unavailable: {resolved}")
        lowered = resolved.name.lower()
        if any(marker in lowered for marker in FORBIDDEN_EXECUTABLE_MARKERS):
            raise ProductionBindingError("fixture/helper/mock/test executable is forbidden")
        argv = tuple(_expand(template, values) for template in binding.argument_templates)
        return ProductionCommand(
            backend_id=backend_id,
            executable=resolved,
            argv=argv,
            binding_sha256=binding.digest_sha256,
            executable_sha256=_sha256(resolved.read_bytes()),
        )


def load_production_bindings(root: Path, registry_path: Path) -> ProductionBindingRegistry:
    """Load exactly four repository-contained production backend bindings."""
    resolved_root = root.resolve()
    resolved_registry = _contained(resolved_root, registry_path.resolve())
    registry_bytes = resolved_registry.read_bytes()
    document = yaml.safe_load(registry_bytes)
    if not isinstance(document, dict):
        raise ProductionBindingError("registry must be a mapping")
    entries = document.get("bindings")
    if not isinstance(entries, dict) or tuple(sorted(entries)) != tuple(sorted(BACKEND_IDS)):
        raise ProductionBindingError("registry must contain exactly four production backends")

    bindings: dict[str, ProductionBinding] = {}
    for backend_id in BACKEND_IDS:
        relative = entries[backend_id]
        if not isinstance(relative, str):
            raise ProductionBindingError(f"binding path must be text: {backend_id}")
        path = _contained(resolved_root, (resolved_root / relative).resolve())
        encoded = path.read_bytes()
        binding_document = yaml.safe_load(encoded)
        if not isinstance(binding_document, dict):
            raise ProductionBindingError(f"binding must be a mapping: {backend_id}")
        if binding_document.get("backend_id") != backend_id:
            raise ProductionBindingError(f"backend identity mismatch: {backend_id}")
        if binding_document.get("fixture_results_allowed") is not False:
            raise ProductionBindingError(f"fixture results must be forbidden: {backend_id}")
        executable_name = binding_document.get("executable")
        templates = binding_document.get("arguments")
        if not isinstance(executable_name, str) or not executable_name:
            raise ProductionBindingError(f"missing executable: {backend_id}")
        if not isinstance(templates, list) or not all(
            isinstance(item, str) for item in templates
        ):
            raise ProductionBindingError(f"missing argument contract: {backend_id}")
        bindings[backend_id] = ProductionBinding(
            backend_id=backend_id,
            path=path,
            digest_sha256=_sha256(encoded),
            executable_name=executable_name,
            argument_templates=tuple(templates),
        )
    return ProductionBindingRegistry(
        root=resolved_root,
        registry_path=resolved_registry,
        registry_sha256=_sha256(registry_bytes),
        bindings=bindings,
    )


def build_production_run_lock(
    registry: ProductionBindingRegistry,
    commands: Mapping[str, ProductionCommand],
    environment_id: str,
) -> dict[str, object]:
    """Bind all production commands to one canonical, content-addressed run lock."""
    if tuple(sorted(commands)) != tuple(sorted(BACKEND_IDS)):
        raise ProductionBindingError("run lock requires all four backend commands")
    payload: dict[str, object] = {
        "schema": "noticer.k7.production-run-lock.v1",
        "environment_id": environment_id,
        "registry_sha256": registry.registry_sha256,
        "backends": {
            backend_id: {
                "binding_sha256": commands[backend_id].binding_sha256,
                "executable_sha256": commands[backend_id].executable_sha256,
                "executable": commands[backend_id].executable.name,
                "argv": list(commands[backend_id].argv),
            }
            for backend_id in BACKEND_IDS
        },
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["run_lock_sha256"] = _sha256(canonical)
    return payload


def _expand(template: str, values: Mapping[str, object]) -> str:
    try:
        expanded = template.format_map(values)
    except KeyError as error:
        raise ProductionBindingError(f"missing command value: {error.args[0]}") from error
    if "{" in expanded or "}" in expanded:
        raise ProductionBindingError(f"unresolved command template: {template}")
    return expanded


def _contained(root: Path, path: Path) -> Path:
    if not path.is_relative_to(root):
        raise ProductionBindingError(f"path escapes repository root: {path}")
    if not path.is_file():
        raise ProductionBindingError(f"binding file is unavailable: {path}")
    return path


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
