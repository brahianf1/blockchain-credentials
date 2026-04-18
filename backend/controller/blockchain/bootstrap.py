"""Idempotent bootstrap of the institutional AnonCreds registry.

This service is the single entry point that guarantees the issuer has a
SCHEMA and a CRED_DEF published on Hyperledger Indy. Running it a second
time is a no-op: existing artifacts are reused and persisted in the
portal database for fast local lookups.

The design intentionally keeps the three concerns separate:
    * :class:`AnonCredsRegistry` talks to ACA-Py (side effects on ledger).
    * :class:`LedgerRepository` persists artifact metadata (side effects on DB).
    * :class:`LedgerBootstrapService` orchestrates both and is the thing
      controllers, CLI scripts and background jobs should depend on.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional, Sequence

from sqlalchemy.orm import Session

from blockchain.anoncreds_registry import (
    AnonCredsRegistry,
    CredDefRecord,
    IssuerIdentity,
    SchemaRecord,
)
from blockchain.repository import (
    ArtifactKind,
    ArtifactRecord,
    LedgerRepository,
)

logger = logging.getLogger(__name__)


class ArtifactOutcome(str, Enum):
    CREATED = "created"
    REUSED = "reused"


@dataclass(frozen=True)
class ArtifactSummary:
    """Outcome for a single artifact touched by the bootstrap."""

    kind: str
    artifact_id: str
    outcome: ArtifactOutcome
    seq_no: Optional[int] = None


@dataclass(frozen=True)
class BootstrapResult:
    """Aggregate outcome of a bootstrap run."""

    issuer_did: str
    schema: ArtifactSummary
    cred_def: ArtifactSummary
    supports_revocation: bool
    schema_id: str
    cred_def_id: str


class LedgerBootstrapService:
    """Ensures the issuer has a SCHEMA and a CRED_DEF on the ledger.

    Dependencies are injected to keep the service easy to test and
    reuse. ``session_factory`` is any zero-arg callable returning a new
    :class:`Session` (e.g. ``PortalSessionLocal``).
    """

    def __init__(
        self,
        *,
        registry: AnonCredsRegistry,
        repository: LedgerRepository,
        session_factory: Callable[[], Session],
    ) -> None:
        self._registry = registry
        self._repository = repository
        self._session_factory = session_factory

    async def bootstrap(
        self,
        *,
        schema_name: str,
        schema_version: str,
        schema_attributes: Sequence[str],
        cred_def_tag: str,
        supports_revocation: bool,
    ) -> BootstrapResult:
        issuer = await self._registry.get_issuer()
        logger.info(
            "Bootstrapping AnonCreds registry for issuer %s (schema=%s v%s tag=%s)",
            issuer.did,
            schema_name,
            schema_version,
            cred_def_tag,
        )

        schema_record, schema_outcome = await self._ensure_schema(
            issuer=issuer,
            schema_name=schema_name,
            schema_version=schema_version,
            attributes=schema_attributes,
        )

        cred_def_record, cred_def_outcome = await self._ensure_cred_def(
            issuer=issuer,
            schema_record=schema_record,
            tag=cred_def_tag,
            supports_revocation=supports_revocation,
        )

        return BootstrapResult(
            issuer_did=issuer.did,
            schema=ArtifactSummary(
                kind=ArtifactKind.SCHEMA,
                artifact_id=schema_record.schema_id,
                outcome=schema_outcome,
                seq_no=schema_record.seq_no,
            ),
            cred_def=ArtifactSummary(
                kind=ArtifactKind.CRED_DEF,
                artifact_id=cred_def_record.cred_def_id,
                outcome=cred_def_outcome,
                seq_no=cred_def_record.schema_seq_no,
            ),
            supports_revocation=cred_def_record.supports_revocation,
            schema_id=schema_record.schema_id,
            cred_def_id=cred_def_record.cred_def_id,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    async def _ensure_schema(
        self,
        *,
        issuer: IssuerIdentity,
        schema_name: str,
        schema_version: str,
        attributes: Sequence[str],
    ) -> tuple[SchemaRecord, ArtifactOutcome]:
        # Fast path: already cached in our DB.
        cached = self._find_cached_schema(
            issuer_did=issuer.did,
            name=schema_name,
            version=schema_version,
        )
        if cached is not None:
            schema_record = await self._registry.get_schema(cached.artifact_id)
            if schema_record is not None:
                return schema_record, ArtifactOutcome.REUSED

        # Fall back to the ledger; the schema might exist even if our
        # cache is empty (fresh DB against a pre-existing ledger).
        existing = await self._registry.find_schema(
            issuer_did=issuer.did,
            name=schema_name,
            version=schema_version,
        )
        if existing is not None:
            self._persist_schema(issuer=issuer, schema=existing)
            return existing, ArtifactOutcome.REUSED

        created = await self._registry.create_schema(
            name=schema_name,
            version=schema_version,
            attributes=attributes,
        )
        self._persist_schema(issuer=issuer, schema=created)
        return created, ArtifactOutcome.CREATED

    async def _ensure_cred_def(
        self,
        *,
        issuer: IssuerIdentity,
        schema_record: SchemaRecord,
        tag: str,
        supports_revocation: bool,
    ) -> tuple[CredDefRecord, ArtifactOutcome]:
        # Fast path: already cached in our DB.
        cached = self._find_cached_cred_def(
            issuer_did=issuer.did,
            schema_id=schema_record.schema_id,
            tag=tag,
        )
        if cached is not None:
            cred_def_record = await self._registry.get_cred_def(cached.artifact_id)
            if cred_def_record is not None:
                return (
                    CredDefRecord(
                        cred_def_id=cred_def_record.cred_def_id,
                        schema_id=schema_record.schema_id,
                        tag=cred_def_record.tag or tag,
                        supports_revocation=cred_def_record.supports_revocation,
                        schema_seq_no=(
                            cred_def_record.schema_seq_no or schema_record.seq_no
                        ),
                    ),
                    ArtifactOutcome.REUSED,
                )

        existing = await self._registry.find_cred_def(
            issuer_did=issuer.did,
            schema_id=schema_record.schema_id,
            tag=tag,
        )
        if existing is not None:
            self._persist_cred_def(issuer=issuer, cred_def=existing)
            return existing, ArtifactOutcome.REUSED

        created = await self._registry.create_cred_def(
            schema_id=schema_record.schema_id,
            tag=tag,
            supports_revocation=supports_revocation,
        )
        self._persist_cred_def(issuer=issuer, cred_def=created)
        return created, ArtifactOutcome.CREATED

    def _find_cached_schema(
        self,
        *,
        issuer_did: str,
        name: str,
        version: str,
    ) -> Optional[ArtifactRecord]:
        with self._session_scope() as db:
            return self._repository.find_artifact(
                db,
                kind=ArtifactKind.SCHEMA,
                issuer_did=issuer_did,
                name=name,
                version=version,
            )

    def _find_cached_cred_def(
        self,
        *,
        issuer_did: str,
        schema_id: str,
        tag: str,
    ) -> Optional[ArtifactRecord]:
        with self._session_scope() as db:
            return self._repository.find_artifact(
                db,
                kind=ArtifactKind.CRED_DEF,
                issuer_did=issuer_did,
                schema_id=schema_id,
                tag=tag,
            )

    def _persist_schema(
        self, *, issuer: IssuerIdentity, schema: SchemaRecord
    ) -> None:
        with self._session_scope() as db:
            self._repository.upsert_artifact(
                db,
                kind=ArtifactKind.SCHEMA,
                artifact_id=schema.schema_id,
                name=schema.name,
                version=schema.version,
                issuer_did=issuer.did,
                seq_no=schema.seq_no,
            )

    def _persist_cred_def(
        self, *, issuer: IssuerIdentity, cred_def: CredDefRecord
    ) -> None:
        with self._session_scope() as db:
            self._repository.upsert_artifact(
                db,
                kind=ArtifactKind.CRED_DEF,
                artifact_id=cred_def.cred_def_id,
                tag=cred_def.tag,
                issuer_did=issuer.did,
                schema_id=cred_def.schema_id,
                supports_revocation=cred_def.supports_revocation,
                seq_no=cred_def.schema_seq_no,
            )

    def _session_scope(self):
        """Yield a managed session that commits on success and rolls back on error."""

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
                    if exc_type is None:
                        self._session.commit()
                    else:
                        self._session.rollback()
                finally:
                    self._session.close()

        return _Scope(self._session_factory)
