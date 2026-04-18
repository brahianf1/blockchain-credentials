"""Hyperledger Indy ledger client backed by ACA-Py and the portal DB.

Responsibilities:
    * Report the operational health of the ledger via ACA-Py's admin API.
    * Resolve per-credential anchors and institutional registry artifacts
      stored in the portal database (populated by the Fase 1 bootstrap
      and by the Fase 2 issuance pipeline).

Failures are bounded by per-call timeouts and downgraded to
``UNAVAILABLE`` so the rest of the application keeps working with
partial blockchain evidence.
"""
from __future__ import annotations

import logging
from typing import Callable, Optional
from urllib.parse import quote, urlencode

import httpx
from sqlalchemy.orm import Session

from blockchain.base import (
    AnchorStatus,
    CredentialAnchor,
    LedgerClient,
    LedgerHealth,
    LedgerStatus,
)
from blockchain.did_utils import to_sov_did
from blockchain.repository import ArtifactKind, LedgerRepository

logger = logging.getLogger(__name__)


class IndyLedgerClient(LedgerClient):
    """Ledger client that combines ACA-Py health checks with DB-backed evidence."""

    DEFAULT_NETWORK_NAME = "VON Network (Hyperledger Indy)"
    DEFAULT_TIMEOUT_SECONDS = 5.0

    def __init__(
        self,
        *,
        admin_url: str,
        repository: LedgerRepository,
        session_factory: Callable[[], Session],
        network_name: str = DEFAULT_NETWORK_NAME,
        explorer_url: Optional[str] = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._admin_url = admin_url.rstrip("/")
        self._repository = repository
        self._session_factory = session_factory
        self._network_name = network_name
        self._explorer_url = explorer_url.rstrip("/") if explorer_url else None
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
                issuer_did=to_sov_did(did_payload.get("did")),
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

        anchor = self._lookup_anchor(credential_hash)
        if anchor is not None:
            return self._anchor_from_db(anchor, fallback_issuer_did=status.issuer_did)

        registry = self._lookup_registry(issuer_did=status.issuer_did)
        return CredentialAnchor(
            status=AnchorStatus.PENDING_ANCHORING,
            network=self._network_name,
            issuer_did=status.issuer_did,
            schema_id=registry.get("schema_id"),
            cred_def_id=registry.get("cred_def_id"),
            explorer_url=self._explorer_url,
        )

    # ------------------------------------------------------------------
    # DB helpers (synchronous, scoped to a short-lived session)
    # ------------------------------------------------------------------
    def _lookup_anchor(self, credential_hash: str):
        with self._session_scope() as db:
            return self._repository.get_anchor(db, credential_hash)

    def _lookup_registry(self, *, issuer_did: Optional[str]) -> dict:
        with self._session_scope() as db:
            schema = self._repository.find_artifact(
                db,
                kind=ArtifactKind.SCHEMA,
                issuer_did=issuer_did,
            )
            cred_def = self._repository.find_artifact(
                db,
                kind=ArtifactKind.CRED_DEF,
                issuer_did=issuer_did,
            )
        return {
            "schema_id": schema.artifact_id if schema else None,
            "cred_def_id": cred_def.artifact_id if cred_def else None,
        }

    def _anchor_from_db(self, anchor, *, fallback_issuer_did: Optional[str]):
        status = (
            AnchorStatus.REVOKED if anchor.revoked else AnchorStatus.ANCHORED
        )
        return CredentialAnchor(
            status=status,
            network=self._network_name,
            issuer_did=to_sov_did(anchor.issuer_did) or fallback_issuer_did,
            schema_id=anchor.schema_id,
            cred_def_id=anchor.cred_def_id,
            rev_reg_id=anchor.rev_reg_id,
            cred_rev_id=anchor.cred_rev_id,
            txn_id=anchor.txn_id,
            seq_no=anchor.seq_no,
            ledger_timestamp=(
                anchor.ledger_timestamp.isoformat()
                if anchor.ledger_timestamp
                else None
            ),
            explorer_url=self._build_explorer_url(seq_no=anchor.seq_no),
        )

    def _build_explorer_url(self, *, seq_no: Optional[int] = None) -> Optional[str]:
        if not self._explorer_url:
            return None
        if seq_no is None:
            return self._explorer_url
        query = urlencode({"query": str(seq_no)})
        return f"{self._explorer_url}/browse/domain?{query}"

    def _session_scope(self):
        class _Scope:
            def __init__(self, factory: Callable[[], Session]) -> None:
                self._factory = factory
                self._session: Optional[Session] = None

            def __enter__(self) -> Session:
                self._session = self._factory()
                return self._session

            def __exit__(self, exc_type, exc, tb) -> None:
                assert self._session is not None
                try:
                    self._session.rollback()
                finally:
                    self._session.close()

        return _Scope(self._session_factory)

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------
    @staticmethod
    def _escape_for_explorer(value: str) -> str:
        return quote(value, safe="")
