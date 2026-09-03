from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

import pytest

from scripts.install_pinned_solver import InstallerError, extract_verified_archive


def _write_zip(path: Path, entries: dict[str, bytes]) -> str:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_verified_archive_extracts_expected_binary(tmp_path: Path) -> None:
    archive = tmp_path / "solver.zip"
    expected = _write_zip(archive, {"bin/solver": b"pinned solver fixture"})
    destination = tmp_path / "installed"

    binary_sha256 = extract_verified_archive(
        archive,
        expected,
        destination,
        "bin/solver",
    )

    executable = destination / "bin" / "solver"
    assert executable.read_bytes() == b"pinned solver fixture"
    assert binary_sha256 == hashlib.sha256(b"pinned solver fixture").hexdigest()


def test_hash_mismatch_fails_before_extraction(tmp_path: Path) -> None:
    archive = tmp_path / "solver.zip"
    _write_zip(archive, {"bin/solver": b"tampered"})
    destination = tmp_path / "installed"

    with pytest.raises(InstallerError, match="SHA-256 mismatch"):
        extract_verified_archive(archive, "0" * 64, destination, "bin/solver")

    assert not destination.exists()


def test_zip_path_escape_is_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "solver.zip"
    expected = _write_zip(
        archive,
        {
            "bin/solver": b"fixture",
            "../escaped": b"must not be written",
        },
    )
    destination = tmp_path / "installed"

    with pytest.raises(InstallerError, match="unsafe path"):
        extract_verified_archive(archive, expected, destination, "bin/solver")

    assert not destination.exists()
    assert not (tmp_path / "escaped").exists()
