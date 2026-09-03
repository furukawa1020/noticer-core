"""Install one solver asset only after strict manifest and archive verification."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import shutil
import stat
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 10_000
ALLOWED_REDIRECT_HOSTS = {"github.com", "release-assets.githubusercontent.com"}


class InstallerError(RuntimeError):
    """A fail-closed solver installation error."""


@dataclass(frozen=True)
class PinnedAsset:
    solver: str
    version: str
    release_tag: str
    platform: str
    archive_name: str
    download_url: str
    asset_sha256: str
    executable_path: str
    network_policy: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_pinned_asset(matrix_path: Path, solver: str, platform: str) -> PinnedAsset:
    try:
        document: dict[str, Any] = json.loads(matrix_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InstallerError(f"solver matrix could not be read: {error}") from error

    if document.get("schema_version") != "quotient-forge-solver-matrix/v1":
        raise InstallerError("unexpected solver matrix schema")
    network_policy = document.get("network_policy")
    if network_policy != "DOWNLOAD_ONLY_WITH_SHA256":
        raise InstallerError("solver matrix does not require SHA-256 verification")

    solvers = document.get("solvers")
    if not isinstance(solvers, list):
        raise InstallerError("solver matrix solvers must be an array")
    selected = [entry for entry in solvers if isinstance(entry, dict) and entry.get("id") == solver]
    if len(selected) != 1:
        raise InstallerError("solver selection is missing or ambiguous")
    solver_entry = selected[0]
    assets = solver_entry.get("assets")
    if not isinstance(assets, list):
        raise InstallerError("solver assets must be an array")
    matching_assets = [
        entry for entry in assets if isinstance(entry, dict) and entry.get("platform") == platform
    ]
    if len(matching_assets) != 1:
        raise InstallerError("solver platform selection is missing or ambiguous")
    asset = matching_assets[0]

    fields = {
        "version": solver_entry.get("version"),
        "release_tag": solver_entry.get("release_tag"),
        "archive_name": asset.get("archive_name"),
        "download_url": asset.get("download_url"),
        "asset_sha256": asset.get("sha256"),
        "executable_path": asset.get("executable_path"),
    }
    if any(not isinstance(value, str) or not value for value in fields.values()):
        raise InstallerError("solver asset contains an empty or non-string field")

    asset_sha256 = fields["asset_sha256"]
    if len(asset_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in asset_sha256
    ):
        raise InstallerError("solver asset SHA-256 is not canonical lowercase hex")
    archive_name = fields["archive_name"]
    download_url = fields["download_url"]
    parsed = urlparse(download_url)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        raise InstallerError("solver asset URL must use HTTPS on github.com")
    if not parsed.path.endswith(f"/{archive_name}"):
        raise InstallerError("solver asset URL does not end with the pinned archive name")

    return PinnedAsset(
        solver=solver,
        version=fields["version"],
        release_tag=fields["release_tag"],
        platform=platform,
        archive_name=archive_name,
        download_url=download_url,
        asset_sha256=asset_sha256,
        executable_path=fields["executable_path"],
        network_policy=network_policy,
    )


def download_asset(asset: PinnedAsset, destination: Path) -> None:
    request = urllib.request.Request(
        asset.download_url,
        headers={"User-Agent": "noticer-core-solver-ci/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
            final_host = (urlparse(response.geturl()).hostname or "").lower()
            if final_host not in ALLOWED_REDIRECT_HOSTS:
                raise InstallerError("solver download redirected to an untrusted host")
            content_length = response.headers.get("Content-Length")
            if content_length is not None and int(content_length) > MAX_ARCHIVE_BYTES:
                raise InstallerError("solver archive exceeds the download limit")
            written = 0
            with destination.open("xb") as output:
                while chunk := response.read(1024 * 1024):
                    written += len(chunk)
                    if written > MAX_ARCHIVE_BYTES:
                        raise InstallerError("solver archive exceeds the download limit")
                    output.write(chunk)
    except OSError as error:
        raise InstallerError(f"solver archive download failed: {error}") from error


def extract_verified_archive(
    archive: Path,
    expected_sha256: str,
    destination: Path,
    executable_path: str,
) -> str:
    actual_sha256 = sha256_file(archive)
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        raise InstallerError(
            f"solver archive SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
        )
    if destination.exists():
        raise InstallerError("solver installation destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="solver-extract-", dir=destination.parent) as temporary:
        extraction_root = Path(temporary) / "root"
        extraction_root.mkdir()
        _safe_extract_zip(archive, extraction_root)
        executable = extraction_root.joinpath(*PurePosixPath(executable_path).parts)
        if not executable.is_file() or executable.is_symlink():
            raise InstallerError("pinned solver executable is missing or not a regular file")
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        binary_sha256 = sha256_file(executable)
        extraction_root.replace(destination)
    return binary_sha256


def _safe_extract_zip(archive: Path, destination: Path) -> None:
    try:
        with zipfile.ZipFile(archive) as bundle:
            entries = bundle.infolist()
            if len(entries) > MAX_ARCHIVE_ENTRIES:
                raise InstallerError("solver archive contains too many entries")
            if sum(entry.file_size for entry in entries) > MAX_EXTRACTED_BYTES:
                raise InstallerError("solver archive exceeds the extracted-size limit")
            seen: set[Path] = set()
            for entry in entries:
                normalized = PurePosixPath(entry.filename.replace("\\", "/"))
                if (
                    normalized.is_absolute()
                    or not normalized.parts
                    or ".." in normalized.parts
                    or normalized.parts[0].endswith(":")
                ):
                    raise InstallerError("solver archive contains an unsafe path")
                mode = entry.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise InstallerError("solver archive contains a symbolic link")
                target = destination.joinpath(*normalized.parts)
                if target in seen:
                    raise InstallerError("solver archive contains a duplicate path")
                seen.add(target)
                if entry.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(entry) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
    except (OSError, zipfile.BadZipFile) as error:
        raise InstallerError(f"solver archive extraction failed: {error}") from error


def write_receipt(path: Path, asset: PinnedAsset, binary_sha256: str) -> None:
    receipt = {
        "schema_version": "noticer.quotient_forge.solver_install.v1",
        "solver": asset.solver,
        "version": asset.version,
        "release_tag": asset.release_tag,
        "platform": asset.platform,
        "archive_name": asset.archive_name,
        "download_url": asset.download_url,
        "asset_sha256": asset.asset_sha256,
        "binary_sha256": binary_sha256,
        "executable_path": asset.executable_path,
        "network_policy": asset.network_policy,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(receipt, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--solver", choices=("cvc5", "z3"), required=True)
    parser.add_argument(
        "--platform",
        choices=("linux-x86_64", "windows-x86_64"),
        required=True,
    )
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    asset = load_pinned_asset(args.matrix, args.solver, args.platform)
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="solver-download-", dir=args.destination.parent
    ) as temporary:
        archive = Path(temporary) / asset.archive_name
        download_asset(asset, archive)
        binary_sha256 = extract_verified_archive(
            archive,
            asset.asset_sha256,
            args.destination,
            asset.executable_path,
        )
    write_receipt(args.receipt, asset, binary_sha256)
    print(f"installed {asset.solver} {asset.version} for {asset.platform}")


if __name__ == "__main__":
    try:
        main()
    except InstallerError as error:
        raise SystemExit(f"solver installation failed: {error}") from error
