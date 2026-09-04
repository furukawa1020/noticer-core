"""Build a pinned QBF solver only after strict source verification."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import shutil
import stat
import subprocess
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_EXTRACTED_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 10_000
ALLOWED_HOSTS = {"github.com", "codeload.github.com"}
EXPECTED_SOURCE = {
    "solver": "caqe",
    "version": "4.0.2",
    "source_revision": "62ee7692dada5236307f8652234ed7a743651eb7",
    "source_tag": "4.0.2",
    "source_sha256": "d09ad720a29eedb27b64182eadd51820b5ac8f30784051f033cdf3972b4e5d37",
}


class InstallerError(RuntimeError):
    """A fail-closed QBF solver installation error."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(path: Path, platform: str) -> tuple[dict[str, Any], str]:
    try:
        manifest: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InstallerError(f"manifest could not be read: {error}") from error
    if manifest.get("schema_version") != "noticer.quotient_forge.qbf_solver_manifest.v1":
        raise InstallerError("unexpected manifest schema")
    if any(manifest.get(key) != value for key, value in EXPECTED_SOURCE.items()):
        raise InstallerError("official CAQE source pin mismatch")
    if manifest.get("network_policy") != "DOWNLOAD_SOURCE_ONLY_WITH_SHA256":
        raise InstallerError("source SHA-256 policy is missing")
    if manifest.get("security_interpretation") != "CANDIDATE_GENERATOR_NOT_SECURITY_ORACLE":
        raise InstallerError("solver trust boundary is weakened")
    assets = manifest.get("platforms")
    matches = [
        item
        for item in assets if isinstance(item, dict) and item.get("platform") == platform
    ] if isinstance(assets, list) else []
    if len(matches) != 1 or not isinstance(matches[0].get("executable_path"), str):
        raise InstallerError("platform executable path is missing or ambiguous")
    canonical = json.dumps(
        manifest, ensure_ascii=True, separators=(",", ":")
    ).encode("utf-8")
    return manifest, hashlib.sha256(canonical).hexdigest()


def download(url: str, destination: Path) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        raise InstallerError("source URL must use HTTPS on github.com")
    request = urllib.request.Request(url, headers={"User-Agent": "noticer-qbf-ci/1"})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
            if (urlparse(response.geturl()).hostname or "").lower() not in ALLOWED_HOSTS:
                raise InstallerError("source download redirected to an untrusted host")
            written = 0
            with destination.open("xb") as output:
                while chunk := response.read(1024 * 1024):
                    written += len(chunk)
                    if written > MAX_ARCHIVE_BYTES:
                        raise InstallerError("source archive exceeds size limit")
                    output.write(chunk)
    except OSError as error:
        raise InstallerError(f"source download failed: {error}") from error


def safe_extract(archive: Path, destination: Path) -> Path:
    try:
        with zipfile.ZipFile(archive) as bundle:
            entries = bundle.infolist()
            if len(entries) > MAX_ARCHIVE_ENTRIES:
                raise InstallerError("source archive contains too many entries")
            if sum(item.file_size for item in entries) > MAX_EXTRACTED_BYTES:
                raise InstallerError("expanded source exceeds size limit")
            seen: set[Path] = set()
            for item in entries:
                relative = PurePosixPath(item.filename.replace("\\", "/"))
                if relative.is_absolute() or ".." in relative.parts:
                    raise InstallerError("source archive contains path traversal")
                if stat.S_ISLNK(item.external_attr >> 16):
                    raise InstallerError("source archive contains a symbolic link")
                target = destination.joinpath(*relative.parts)
                if target in seen:
                    raise InstallerError("source archive contains a duplicate path")
                seen.add(target)
                if item.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with bundle.open(item) as source, target.open("xb") as output:
                        shutil.copyfileobj(source, output, length=1024 * 1024)
    except (OSError, zipfile.BadZipFile) as error:
        raise InstallerError(f"source extraction failed: {error}") from error
    roots = [item for item in destination.iterdir() if item.is_dir()]
    if len(roots) != 1 or roots[0].name != "caqe-4.0.2":
        raise InstallerError("source archive root is unexpected")
    return roots[0]


def build_and_install(
    source: Path,
    destination: Path,
    executable_path: str,
) -> str:
    windows = executable_path.endswith(".exe")
    target = "x86_64-pc-windows-gnu" if windows else None
    command = ["cargo", "build", "--release", "--locked"]
    if target is not None:
        command.extend(["--target", target])
    try:
        subprocess.run(  # noqa: S603
            command,
            cwd=source,
            check=True,
            timeout=15 * 60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise InstallerError(f"pinned CAQE build failed: {error}") from error
    built_name = "caqe.exe" if windows else "caqe"
    built = source / "target"
    if target is not None:
        built /= target
    built = built / "release" / built_name
    if not built.is_file() or built.is_symlink():
        raise InstallerError("CAQE build did not produce a regular executable")
    if destination.exists():
        raise InstallerError("installation destination already exists")
    installed = destination.joinpath(*PurePosixPath(executable_path).parts)
    installed.parent.mkdir(parents=True)
    shutil.copy2(built, installed)
    return sha256_file(installed)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--platform", choices=("linux-x86_64", "windows-x86_64"), required=True
    )
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    manifest, manifest_sha256 = load_manifest(args.manifest, args.platform)
    asset = next(item for item in manifest["platforms"] if item["platform"] == args.platform)
    with tempfile.TemporaryDirectory(prefix="qbf-source-") as temporary:
        root = Path(temporary)
        archive = root / manifest["source_archive_name"]
        download(manifest["source_url"], archive)
        if not hmac.compare_digest(sha256_file(archive), manifest["source_sha256"]):
            raise InstallerError("source archive SHA-256 mismatch")
        source = safe_extract(archive, root / "source")
        binary_sha256 = build_and_install(
            source, args.destination, asset["executable_path"]
        )
    receipt = {
        "schema_version": "noticer.quotient_forge.qbf_solver_install.v1",
        "solver": manifest["solver"],
        "version": manifest["version"],
        "platform": args.platform,
        "source_revision": manifest["source_revision"],
        "source_sha256": manifest["source_sha256"],
        "manifest_sha256": manifest_sha256,
        "binary_sha256": binary_sha256,
        "executable_path": asset["executable_path"],
    }
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(
        json.dumps(receipt, ensure_ascii=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(f"built CAQE {manifest['version']} for {args.platform}")


if __name__ == "__main__":
    try:
        main()
    except InstallerError as error:
        raise SystemExit(f"QBF solver installation failed: {error}") from error
