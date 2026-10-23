"""Partner B: read text files from a local folder. Never executes anything."""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from repoguard.models import FileItem

MAX_FILE_BYTES = 1_000_000
SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__"}


def load_local(root: str) -> Iterator[FileItem]:
    base = Path(root)
    for p in sorted(base.rglob("*")):
        if not p.is_file() or any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.stat().st_size > MAX_FILE_BYTES:
            continue
        try:
            yield str(p.relative_to(base)), p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable: skip
