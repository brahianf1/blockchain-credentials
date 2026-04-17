"""Blockchain integration package.

This package exposes a stable, ledger-agnostic interface (``LedgerClient``)
that the rest of the application depends on, together with concrete
implementations for Hyperledger Indy (via ACA-Py) and a null adapter for
testing. A factory selects the concrete client based on environment
configuration so that call sites never import concrete classes directly.
"""
from blockchain.base import (
    AnchorStatus,
    CredentialAnchor,
    LedgerClient,
    LedgerHealth,
    LedgerStatus,
)
from blockchain.factory import get_ledger_client

__all__ = [
    "AnchorStatus",
    "CredentialAnchor",
    "LedgerClient",
    "LedgerHealth",
    "LedgerStatus",
    "get_ledger_client",
]
