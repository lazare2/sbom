"""Recursive file walker that collects Python source files for scanning."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

#: Directory names skipped everywhere in the tree. A frozenset avoids the
#: mutable-default-argument pitfall while still being overridable per call.
DEFAULT_EXCLUDES: frozenset[str] = frozenset(
    {"venv", ".venv", ".git", "__pycache__", "node_modules"}
)


def walk_python_files(
    root: Path, excludes: frozenset[str] = DEFAULT_EXCLUDES
) -> Iterator[Path]:
    """Yield every ``.py`` file under ``root``, skipping directories in ``excludes``.

    ``root`` may be a single file (yielded directly if it is a ``.py`` file) or a
    directory (walked recursively). Traversal order is deterministic (sorted).
    """
    root = Path(root)

    if root.is_file():
        if root.suffix == ".py":
            yield root
        return

    if not root.exists():
        return

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in excludes)
        for filename in sorted(filenames):
            if filename.endswith(".py"):
                yield Path(dirpath) / filename
