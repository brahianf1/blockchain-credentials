"""Ensure every subdirectory of a Python package has an ``__init__.py``.

Works around upstream projects that ship PEP 420 namespace subpackages
while declaring ``packages=find_packages()`` in their setup.py.
``find_packages()`` only picks up *regular* packages (directories that
contain an ``__init__.py``), so namespace subpackages end up missing
from the resulting wheel even though they are importable at runtime.

For the ``bcgov/indy-tails-server`` v1.1.0 build, this script promotes
directories like ``tails_server/config`` from namespace package to
regular package by creating an empty ``__init__.py`` in them. The
change is strictly additive: existing ``__init__.py`` files are never
touched, and directories already carrying one produce no side effects.

Running this helper is idempotent — re-running it on a previously
prepared tree is a no-op.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import List


def ensure_init_files(package_root: Path) -> List[Path]:
    """Create missing ``__init__.py`` files under ``package_root`` recursively.

    Returns the list of files that were actually created so the caller
    can log them. The list is empty if nothing was missing.
    """
    created: List[Path] = []
    for directory in sorted(package_root.rglob("*")):
        if not directory.is_dir():
            continue
        init_file = directory / "__init__.py"
        if not init_file.exists():
            init_file.touch()
            created.append(init_file)
    return created


def main(argv: List[str]) -> int:
    if len(argv) != 2:
        print("usage: prepare_package.py <package-root>", file=sys.stderr)
        return 64

    root = Path(argv[1])
    if not root.is_dir():
        print(f"ERROR: {root} is not a directory", file=sys.stderr)
        return 2

    created = ensure_init_files(root)
    if created:
        print(f"Created {len(created)} __init__.py file(s) under {root}/:")
        for path in created:
            print(f"  {path}")
    else:
        print(f"No missing __init__.py under {root}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
