"""Rewrite the upstream ``indy-tails-server`` setup.py to use find_packages().

The v1.1.0 (and older) releases of ``bcgov/indy-tails-server`` declare
``packages=["tails_server"]`` without calling
``setuptools.find_packages()``. The resulting wheel omits every
subpackage (``tails_server.config``, ``tails_server.utils``, …) and the
service crashes at import time with::

    ModuleNotFoundError: No module named 'tails_server.config'

This helper applies a deterministic, root-cause fix: it imports
``find_packages`` alongside ``setup`` and replaces the hard-coded
package list with ``find_packages()``. It is tolerant of common
whitespace and trailing-comma variants, and **fails loudly** if the
upstream file does not match a known pattern — we prefer a broken
build over a silently broken image.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


_IMPORT_PATTERN = re.compile(
    r"^from setuptools import setup\b(?P<rest>[^\n]*)$",
    flags=re.MULTILINE,
)

_PACKAGES_PATTERN = re.compile(
    r"packages\s*=\s*\[\s*['\"]tails_server['\"](?:\s*,)?\s*\]"
)


def patch(source: str) -> str:
    patched = source

    if "find_packages" not in patched:
        patched = _IMPORT_PATTERN.sub(
            lambda m: f"from setuptools import setup, find_packages{m.group('rest')}",
            patched,
            count=1,
        )

    patched = _PACKAGES_PATTERN.sub("packages=find_packages()", patched)

    return patched


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: patch_setup.py <path-to-setup.py>", file=sys.stderr)
        return 64

    path = Path(argv[1])
    original = path.read_text(encoding="utf-8")
    patched = patch(original)

    if patched == original:
        print(
            "ERROR: upstream setup.py does not match any known pattern. "
            "Refusing to ship an image whose package layout we cannot verify. "
            "Inspect the original setup.py printed above and extend "
            "patch_setup.py accordingly.",
            file=sys.stderr,
        )
        return 2

    path.write_text(patched, encoding="utf-8")
    print("setup.py patched: packages=[...] -> find_packages()")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
