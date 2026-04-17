"""Hyperledger Indy ledger client backed by ACA-Py's admin API.

Phase 0 scope: expose real ledger health and the issuing DID that
ACA-Py has posted on the VON Network. The ``resolve_anchor`` method
returns :class:`AnchorStatus.PENDING_ANCHORING` for every credential
because the anchoring pipeline (schema / cred_def / revocation
registry entries) is wired up in a later phase.

Design choices:
    * HTTP is used directly via ``httpx`` instead of pulling a heavier
      dependency — the admin surface we need is minimal and stable.
    * Every outbound call is bounded by an explicit timeout so a slow
      ACA-Py cannot cascade into slow API responses to users.
    * Failures are logged at ``WARNING`` and converted to an
      ``UNAVAILABLE`` status; exceptions never bubble up so the rest
      of the app keeps working with degraded blockchain evidence.
"""
from __future__ import annotations

import logging
from typing import Optional

import httpx

from blockchain.base import (
    CredentialAnchor,
    LedgerClient,
    LedgerHealth,
    LedgerStatus,
)

logger = logging.getLogger(__name__)


class IndyLedgerClient(LedgerClient):
    """Ledger client that talks to an ACA-Py admin endpoint over HTTP."""

    DEFAULT_NETWORK_NAME = "VON Network (Hyperledger Indy)"
    DEFAULT_TIMEOUT_SECONDS = 5.0

    def __init__(
        self,
        admin_url: str,
        network_name: str = DEFAULT_NETWORK_NAME,
        explorer_url: Optional[str] = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._admin_url = admin_url.rstrip("/")
        self._network_name = network_name
        self._explorer_url = explorer_url
        self._timeout = httpx.Timeout(timeout_seconds)

    # ------------------------------------------------------------------
    # LedgerClient interface
    # ------------------------------------------------------------------
    async def get_status(self) -> LedgerStatus:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as http:
                live_resp = await http.get(f"{self._admin_url}/status/live")
                live_resp.raise_for_status()

                did_resp = await http.get(f"{self._admin_url}/wallet/did/public")
                did_resp.raise_for_status()
                did_payload = did_resp.json().get("result") or {}

            return LedgerStatus(
                name=self._network_name,
                health=LedgerHealth.HEALTHY,
                issuer_did=self._normalize_did(did_payload.get("did")),
                endpoint=(did_payload.get("metadata") or {}).get("endpoint"),
                explorer_url=self._explorer_url,
            )
        except Exception as exc:
            logger.warning("Indy ledger health probe failed: %s", exc)
            return LedgerStatus(
                name=self._network_name,
                health=LedgerHealth.UNAVAILABLE,
                explorer_url=self._explorer_url,
            )

    async def resolve_anchor(
        self, credential_hash: str
    ) -> Optional[CredentialAnchor]:
        status = await self.get_status()
        if status.health == LedgerHealth.UNAVAILABLE:
            return CredentialAnchor.unavailable(self._network_name)
        return CredentialAnchor.pending(
            network=self._network_name,
            issuer_did=status.issuer_did,
            explorer_url=self._explorer_url,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _normalize_did(did: Optional[str]) -> Optional[str]:
        """Prefix a bare Indy DID with the ``did:sov:`` method when needed."""
        if not did:
            return None
        return did if did.startswith("did:") else f"did:sov:{did}"
