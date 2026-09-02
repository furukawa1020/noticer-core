"""Repository-local entry point for the QuotientSeal reproduction runner."""

from __future__ import annotations

import sys
from importlib import import_module
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

if __name__ == "__main__":
    runner = import_module("noticer_core.replication.runner")
    raise SystemExit(runner.main())
