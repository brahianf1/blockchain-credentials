"""Ledger client factory refactored for Besu."""
from functools import lru_cache

from blockchain.base import LedgerClient
from blockchain.null_client import NullLedgerClient
from blockchain.repository import LedgerRepository


@lru_cache(maxsize=1)
def get_ledger_repository() -> LedgerRepository:
    """Return a process-wide singleton ``LedgerRepository``."""
    return LedgerRepository()


@lru_cache(maxsize=1)
def get_ledger_client() -> LedgerClient:
    """Return the process-wide ledger client.
    For Phase 2B this returns NullLedgerClient until Besu resolving is implemented.
    """
    return NullLedgerClient()
