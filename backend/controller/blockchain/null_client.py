"""No-op ledger client for tests and local development.

Reports the ledger as ``UNAVAILABLE`` and never fabricates anchors. This
is deliberately boring: it guarantees the rest of the system never
misrepresents blockchain state when a real client is not wired up.
"""
from __future__ import annotations

from typing import Optional

from blockchain.base import (
    CredentialAnchor,
    LedgerClient,
    LedgerHealth,
    LedgerStatus,
)


class NullLedgerClient(LedgerClient):
    """Honest stub: every call surfaces ``UNAVAILABLE``."""

    NETWORK_NAME = "null"

    async def get_status(self) -> LedgerStatus:
        return LedgerStatus(
            name=self.NETWORK_NAME,
            health=LedgerHealth.UNAVAILABLE,
        )

    async def resolve_anchor(
        self, credential_hash: str
    ) -> Optional[CredentialAnchor]:
        return None
