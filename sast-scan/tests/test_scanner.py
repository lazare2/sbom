from __future__ import annotations

from pathlib import Path

from sast.scanner import DEFAULT_EXCLUDES, walk_python_files


def _touch(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# sample\n", encoding="utf-8")


def test_walks_py_files_recursively(tmp_path: Path) -> None:
    _touch(tmp_path / "a.py")
    _touch(tmp_path / "pkg" / "b.py")
    _touch(tmp_path / "pkg" / "sub" / "c.py")
    _touch(tmp_path / "not_python.txt")

    found = {p.name for p in walk_python_files(tmp_path)}
    assert found == {"a.py", "b.py", "c.py"}


def test_excludes_default_directories(tmp_path: Path) -> None:
    _touch(tmp_path / "keep.py")
    _touch(tmp_path / "venv" / "lib.py")
    _touch(tmp_path / ".venv" / "lib.py")
    _touch(tmp_path / ".git" / "hooks.py")
    _touch(tmp_path / "__pycache__" / "cached.py")
    _touch(tmp_path / "node_modules" / "pkg.py")

    found = {p.name for p in walk_python_files(tmp_path)}
    assert found == {"keep.py"}


def test_excludes_are_configurable(tmp_path: Path) -> None:
    _touch(tmp_path / "keep.py")
    _touch(tmp_path / "vendor" / "third_party.py")

    excludes = DEFAULT_EXCLUDES | frozenset({"vendor"})
    found = {p.name for p in walk_python_files(tmp_path, excludes)}
    assert found == {"keep.py"}


def test_single_file_argument(tmp_path: Path) -> None:
    file_path = tmp_path / "single.py"
    _touch(file_path)

    found = list(walk_python_files(file_path))
    assert found == [file_path]


def test_nonexistent_path_yields_nothing(tmp_path: Path) -> None:
    assert list(walk_python_files(tmp_path / "does_not_exist")) == []


def test_default_excludes_is_frozenset() -> None:
    assert isinstance(DEFAULT_EXCLUDES, frozenset)
