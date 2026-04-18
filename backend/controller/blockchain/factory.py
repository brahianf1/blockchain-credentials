"""Ledger client factory.

Centralises the selection of the concrete ``LedgerClient`` implementation
so call sites do not import adapters directly. Selection is driven
entirely by environment variables to keep the configuration surface in
one place and friendly to twelve-factor deployments.
"""
from __future__ import annotations

import os
from functools import lru_cache

from blockchain.base import LedgerClient
from blockchain.indy_client import IndyLedgerClient
from blockchain.null_client import NullLedgerClient


_DEFAULT_ACAPY_ADMIN_URL = "http://acapy-agent:8020"
_DEFAULT_EXPLORER_URL = "https://ledger.utnpf.site"
_DEFAULT_NETWORK_NAME = IndyLedgerClient.DEFAULT_NETWORK_NAME


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

    admin_url = os.getenv("ACAPY_ADMIN_URL", _DEFAULT_ACAPY_ADMIN_URL)
    explorer_url = os.getenv("BLOCKCHAIN_EXPLORER_URL", _DEFAULT_EXPLORER_URL)
    network_name = os.getenv("BLOCKCHAIN_NETWORK_NAME", _DEFAULT_NETWORK_NAME)

    return IndyLedgerClient(
        admin_url=admin_url,
        network_name=network_name,
        explorer_url=explorer_url,
    )
