"""Blockchain integration package.

Exposes a stable, ledger-agnostic surface (``LedgerClient``) and the
components that implement the Hyperledger Indy integration via ACA-Py.
Concrete call sites should depend on :func:`get_ledger_client` or
:func:`get_bootstrap_service` rather than importing adapters directly.
"""
from blockchain.anoncreds_registry import (
    AnonCredsRegistry,
    AnonCredsRegistryError,
    CredDefRecord,
    IssuerIdentity,
    SchemaRecord,
)
from blockchain.base import (
    AnchorStatus,
    CredentialAnchor,
    LedgerClient,
    LedgerHealth,
    LedgerStatus,
)
from blockchain.bootstrap import (
    ArtifactOutcome,
    ArtifactSummary,
    BootstrapResult,
    LedgerBootstrapService,
)
from blockchain.config import (
    DEFAULT_SCHEMA_ATTRIBUTES,
    BlockchainSettings,
    get_settings,
)
from blockchain.factory import (
    get_anoncreds_registry,
    get_bootstrap_service,
    get_ledger_client,
    get_ledger_repository,
)
from blockchain.repository import (
    AnchorRecord,
    ArtifactKind,
    ArtifactRecord,
    LedgerRepository,
)

__all__ = [
    "AnchorRecord",
    "AnchorStatus",
    "AnonCredsRegistry",
    "AnonCredsRegistryError",
    "ArtifactKind",
    "ArtifactOutcome",
    "ArtifactRecord",
    "ArtifactSummary",
    "BlockchainSettings",
    "BootstrapResult",
    "CredDefRecord",
    "CredentialAnchor",
    "DEFAULT_SCHEMA_ATTRIBUTES",
    "IssuerIdentity",
    "LedgerBootstrapService",
    "LedgerClient",
    "LedgerHealth",
    "LedgerRepository",
    "LedgerStatus",
    "SchemaRecord",
    "get_anoncreds_registry",
    "get_bootstrap_service",
    "get_ledger_client",
    "get_ledger_repository",
    "get_settings",
]
