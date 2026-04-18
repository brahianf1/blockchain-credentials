"""Prepare an upstream Python project for ``pip install``.

Works around two unrelated but common packaging defects:

1. **Namespace subpackages missing ``__init__.py``**. Projects that ship
   PEP 420 namespace subpackages while declaring
   ``packages=find_packages()`` in their ``setup.py`` end up producing
   wheels without those subpackages, because ``find_packages()`` only
   detects *regular* packages. Creating empty ``__init__.py`` files
   promotes them to regular packages so ``find_packages()`` picks them
   up.

2. **Non-Python data files silently dropped by pip**. When
   ``setup.py`` declares ``include_package_data=True`` but the project
   has no ``MANIFEST.in`` (or the existing one is incomplete),
   resources such as ``.ini`` configuration files or HTML templates
   are missing from the installed wheel. This helper ensures a
   ``MANIFEST.in`` exists at the project root with a conservative
   ``recursive-include`` rule for the package's data files.

Both operations are strictly additive and idempotent.

This is used by the ``tails-server`` image to fix
``bcgov/indy-tails-server`` v1.1.0, which exhibits both defects:

* ``tails_server/config/`` has no ``__init__.py``.
* ``tails_server/config/default_logging_config.ini`` is not listed in
  any ``MANIFEST.in`` or ``package_data`` entry, so the runtime
  crashes with ``BadLogConfigError``.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import List

# Non-Python data files that the package might carry. Wide enough to
# cover typical runtime assets without scooping up build artefacts.
_DATA_FILE_EXTENSIONS: tuple[str, ...] = (
    "*.ini",
    "*.cfg",
    "*.conf",
    "*.json",
    "*.yaml",
    "*.yml",
    "*.html",
    "*.css",
    "*.js",
    "*.txt",
    "*.md",
)


def ensure_init_files(package_root: Path) -> List[Path]:
    """Create missing ``__init__.py`` files under ``package_root``.

    Returns the list of files created (empty if none were missing).
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


def ensure_manifest(package_root: Path) -> Path:
    """Ensure ``MANIFEST.in`` at the project root includes the package data.

    The file lives next to ``setup.py`` and is consumed by
    ``include_package_data=True`` during ``pip install`` / wheel build.
    An existing ``MANIFEST.in`` is preserved; our rule is appended only
    when absent so re-running the helper is a no-op.
    """
    project_root = package_root.parent
    manifest = project_root / "MANIFEST.in"

    package_name = package_root.name
    rule = f"recursive-include {package_name} " + " ".join(_DATA_FILE_EXTENSIONS)

    existing_lines: List[str] = []
    if manifest.exists():
        existing_lines = manifest.read_text(encoding="utf-8").splitlines()

    if rule.strip() in (line.strip() for line in existing_lines):
        return manifest

    new_lines = list(existing_lines)
    if new_lines and new_lines[-1].strip():
        new_lines.append("")
    new_lines.append(rule)
    manifest.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    return manifest


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

    manifest = ensure_manifest(root)
    print(f"MANIFEST.in ready at {manifest}")
    print(f"--- {manifest.name} ---")
    print(manifest.read_text(encoding="utf-8"))

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
