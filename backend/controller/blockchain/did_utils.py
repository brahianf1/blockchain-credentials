"""DID normalization helpers shared across the blockchain subsystem.

The system uses two representations of a Hyperledger Indy DID:

* **Raw** (e.g. ``5yUtyhQwfcVZo9bGoNfi2R``) — what ACA-Py returns from
  ``/wallet/did/public`` and what we persist in the database.
* **Sov-prefixed** (e.g. ``did:sov:5yUtyhQwfcVZo9bGoNfi2R``) — the W3C
  DID URL form used in API responses and in the UI.

Centralising the conversion avoids bugs where a value in one form is
passed to code that expects the other (e.g. DB queries not matching
because the row was stored raw but queried prefixed).
"""
from __future__ import annotations

from typing import Optional

_SOV_METHOD_PREFIX = "did:sov:"


def to_raw_did(did: Optional[str]) -> Optional[str]:
    """Return the raw Indy DID, stripping a ``did:sov:`` prefix if present."""
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
