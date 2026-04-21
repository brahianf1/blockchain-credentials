"""DID normalization helpers shared across the blockchain subsystem.

The system may handle DIDs in multiple representations:

* **Raw** (e.g. ``0xfe3b557e...`` for Ethereum addresses) — compact form
  used for database persistence.
* **Prefixed** (e.g. ``did:ethr:0xfe3b557e...`` or ``did:sov:5yUty...``)
  — W3C DID URL form used in API responses and in the UI.

Centralising the conversion avoids bugs where a value in one form is
passed to code that expects the other (e.g. DB queries not matching
because the row was stored raw but queried prefixed).
"""
from __future__ import annotations

from typing import Optional

_SOV_METHOD_PREFIX = "did:sov:"


def to_raw_did(did: Optional[str]) -> Optional[str]:
    """Return the raw DID, stripping any known method prefix if present."""
    if not did:
        return None
    if did.startswith(_SOV_METHOD_PREFIX):
        return did[len(_SOV_METHOD_PREFIX):]
    return did


def to_sov_did(did: Optional[str]) -> Optional[str]:
    """Return the ``did:sov:``-prefixed form of ``did``.

    Values that already carry any ``did:`` method prefix are returned
    unchanged so unknown methods pass through untouched.
    """
    if not did:
        return None
    if did.startswith("did:"):
        return did
    return f"{_SOV_METHOD_PREFIX}{did}"
