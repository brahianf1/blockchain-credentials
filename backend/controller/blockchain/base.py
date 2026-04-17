"""Abstract ledger client interface and domain-level value objects.

The abstractions in this module follow the hexagonal architecture style:
business code depends on the ``LedgerClient`` port, while concrete adapters
(Hyperledger Indy via ACA-Py, no-op for tests, etc.) live in sibling
modules. This keeps the rest of the application ledger-agnostic and makes
it trivial to swap the underlying blockchain without touching callers.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class LedgerHealth(str, Enum):
    """Operational state of the ledger from the client's perspective."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class AnchorStatus(str, Enum):
    """Lifecycle state of a credential with respect to the public ledger.

    The state machine is:

        PENDING_ANCHORING  ──▶  ANCHORED  ──▶  REVOKED
               │                                │
               └──────────────▶ UNAVAILABLE ◀───┘
    """

    PENDING_ANCHORING = "pending_anchoring"
    ANCHORED = "anchored"
    REVOKED = "revoked"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True)
class LedgerStatus:
    """Operational snapshot of the ledger.

    Attributes:
        name: Human-readable network label surfaced to clients.
        health: Current :class:`LedgerHealth`.
        issuer_did: Canonical DID of the issuing institution, if known.
        endpoint: Service endpoint registered on-ledger for the issuer.
        explorer_url: Public URL of the ledger explorer, when available.
    """

    name: str
    health: LedgerHealth
    issuer_did: Optional[str] = None
    endpoint: Optional[str] = None
    explorer_url: Optional[str] = None


@dataclass(frozen=True)
class CredentialAnchor:
    """Verifiable on-ledger evidence bound to a credential hash.

    Fields are progressively populated as the anchoring pipeline matures
    across phases. Callers should drive their UI from :attr:`status`
    rather than from the presence of optional fields.
    """

    status: AnchorStatus
    network: str
    issuer_did: Optional[str] = None
    schema_id: Optional[str] = None
    cred_def_id: Optional[str] = None
    rev_reg_id: Optional[str] = None
    cred_rev_id: Optional[str] = None
    txn_id: Optional[str] = None
    seq_no: Optional[int] = None
    ledger_timestamp: Optional[str] = None
    explorer_url: Optional[str] = None

    @classmethod
    def pending(
        cls,
        network: str,
        issuer_did: Optional[str] = None,
        explorer_url: Optional[str] = None,
    ) -> "CredentialAnchor":
        """Build an anchor marked as awaiting on-ledger registration."""
        return cls(
            status=AnchorStatus.PENDING_ANCHORING,
            network=network,
            issuer_did=issuer_did,
            explorer_url=explorer_url,
        )

    @classmethod
    def unavailable(cls, network: str) -> "CredentialAnchor":
        """Build an anchor marking the ledger as unreachable."""
        return cls(status=AnchorStatus.UNAVAILABLE, network=network)


class LedgerClient(ABC):
    """Stable port that abstracts all blockchain interactions."""

    @abstractmethod
    async def get_status(self) -> LedgerStatus:
        """Return the operational status of the ledger."""

    @abstractmethod
    async def resolve_anchor(
        self, credential_hash: str
    ) -> Optional[CredentialAnchor]:
        """Return the anchor associated with ``credential_hash``.

        Returns:
            ``None`` when the credential is not present in the ledger
            registry, or a :class:`CredentialAnchor` carrying the
            appropriate :class:`AnchorStatus` otherwise.
        """
