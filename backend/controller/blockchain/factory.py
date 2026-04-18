"""Ledger client factory.

Centralises the selection and composition of the concrete
``LedgerClient`` implementation so call sites do not import adapters
directly. Selection is driven entirely by environment variables to keep
the configuration surface in one place and friendly to twelve-factor
deployments.
"""
from __future__ import annotations

import os
from functools import lru_cache

from blockchain.anoncreds_registry import AnonCredsRegistry
from blockchain.base import LedgerClient
from blockchain.bootstrap import LedgerBootstrapService
from blockchain.indy_client import IndyLedgerClient
from blockchain.null_client import NullLedgerClient
from blockchain.repository import LedgerRepository


_DEFAULT_ACAPY_ADMIN_URL = "http://acapy-agent:8020"
_DEFAULT_EXPLORER_URL = "https://ledger.utnpf.site"
_DEFAULT_NETWORK_NAME = IndyLedgerClient.DEFAULT_NETWORK_NAME


def _acapy_admin_url() -> str:
    return os.getenv("ACAPY_ADMIN_URL", _DEFAULT_ACAPY_ADMIN_URL)


def _explorer_url() -> str:
    return os.getenv("BLOCKCHAIN_EXPLORER_URL", _DEFAULT_EXPLORER_URL)


def _network_name() -> str:
    return os.getenv("BLOCKCHAIN_NETWORK_NAME", _DEFAULT_NETWORK_NAME)


@lru_cache(maxsize=1)
def get_ledger_repository() -> LedgerRepository:
    """Return a process-wide singleton ``LedgerRepository``."""
    return LedgerRepository()


@lru_cache(maxsize=1)
def get_anoncreds_registry() -> AnonCredsRegistry:
    """Return a process-wide singleton ``AnonCredsRegistry`` pointed at ACA-Py."""
    return AnonCredsRegistry(admin_url=_acapy_admin_url())


@lru_cache(maxsize=1)
def get_ledger_client() -> LedgerClient:
    """Return the process-wide ledger client.

    Environment variables:
        ``BLOCKCHAIN_DRIVER``
            ``"indy"`` (default) or ``"null"``.
        ``ACAPY_ADMIN_URL``
            Base URL of the ACA-Py admin API used by the Indy driver.
        ``BLOCKCHAIN_EXPLORER_URL``
            Public URL of the ledger explorer shown to verifiers.
        ``BLOCKCHAIN_NETWORK_NAME``
            Human-readable ledger label surfaced by the API.
    """
    driver = os.getenv("BLOCKCHAIN_DRIVER", "indy").strip().lower()
    if driver == "null":
        return NullLedgerClient()

    from portal.database import PortalSessionLocal

    return IndyLedgerClient(
        admin_url=_acapy_admin_url(),
        repository=get_ledger_repository(),
        session_factory=PortalSessionLocal,
        network_name=_network_name(),
        explorer_url=_explorer_url(),
    )


def get_bootstrap_service() -> LedgerBootstrapService:
    """Return a bootstrap service ready to be executed.

    The service is not cached because it has light state; a new instance
    per request avoids surprising locking semantics across FastAPI
    background tasks and CLI invocations.
    """
    from portal.database import PortalSessionLocal

    return LedgerBootstrapService(
        registry=get_anoncreds_registry(),
        repository=get_ledger_repository(),
        session_factory=PortalSessionLocal,
    )
