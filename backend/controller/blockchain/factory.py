"""Ledger client factory for Hyperledger Besu.

Provides process-wide singletons for the ``LedgerClient`` (used by
Portal API endpoints to verify credentials on-chain) and the
``LedgerRepository`` (used for DB-level persistence of anchor records).
"""
from functools import lru_cache

from blockchain.base import LedgerClient
from blockchain.besu_ledger_client import BesuLedgerClient
from blockchain.repository import LedgerRepository


@lru_cache(maxsize=1)
def get_ledger_repository() -> LedgerRepository:
    """Return a process-wide singleton ``LedgerRepository``."""
    return LedgerRepository()


@lru_cache(maxsize=1)
def get_ledger_client() -> LedgerClient:
    """Return the process-wide ledger client.

    Uses ``BesuLedgerClient`` which queries the CredentialRegistry smart
    contract on Hyperledger Besu for real on-chain credential verification.
    """
    return BesuLedgerClient()
