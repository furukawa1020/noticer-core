"""Non-identifying reproducibility fingerprint for the active Python process."""

import hashlib
import json
import os
import platform
from importlib.metadata import version

_PACKAGES = ("numpy", "pandas", "scikit-learn")
_THREAD_VARS = ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS")


def environment_fingerprint() -> tuple[bytes, str]:
    """Capture installed versions and explicit thread limits, not hardware identity."""
    limits: dict[str, int | None] = {}
    for key in _THREAD_VARS:
        raw = os.environ.get(key)
        if raw is None:
            limits[key] = None
        elif raw.isascii() and raw.isdecimal() and 1 <= int(raw) <= 100_000:
            limits[key] = int(raw)
        else:
            raise ValueError(f"{key} is not a supported explicit thread limit")
    manifest = {
        "schema": "noticer.k21.environment.v1",
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "dependencies": {package: version(package) for package in _PACKAGES},
        "configured_thread_limits": limits,
    }
    data = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("ascii")
    return data, hashlib.sha256(data).hexdigest()
