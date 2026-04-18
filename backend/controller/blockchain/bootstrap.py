"""Idempotent bootstrap of the institutional AnonCreds registry.

This service is the single entry point that guarantees the issuer has a
SCHEMA, a CRED_DEF and — optionally — a REV_REG_DEF published on
Hyperledger Indy. Running it a second time is a no-op: existing
artifacts are reused and only the missing ones are registered.

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
from typing import Callable, Optional, Sequence, Tuple

from sqlalchemy.orm import Session

from blockchain.anoncreds_registry import (
    AnonCredsRegistry,
    CredDefRecord,
    IssuerIdentity,
    RevRegRecord,
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
    rev_reg: Optional[ArtifactSummary] = None
    rev_reg_id: Optional[str] = None
    rev_reg_max_cred_num: Optional[int] = None
    rev_reg_issuance_type: Optional[str] = None


class LedgerBootstrapService:
    """Ensures the issuer has a SCHEMA, CRED_DEF and (optional) REV_REG_DEF
    registered on the ledger.

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
        rev_reg_max_cred_num: int = 1000,
        rev_reg_issuance_type: str = "ISSUANCE_ON_DEMAND",
    ) -> BootstrapResult:
        issuer = await self._registry.get_issuer()
        logger.info(
            "Bootstrapping AnonCreds registry for issuer %s "
            "(schema=%s v%s, tag=%s, revocation=%s)",
            issuer.did,
            schema_name,
            schema_version,
            cred_def_tag,
            supports_revocation,
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

        rev_reg_summary: Optional[ArtifactSummary] = None
        rev_reg_id: Optional[str] = None
        rev_reg_max: Optional[int] = None
        rev_reg_issuance: Optional[str] = None

        if supports_revocation:
            rev_reg_record, rev_reg_outcome = await self._ensure_rev_reg(
                issuer=issuer,
                cred_def_record=cred_def_record,
                max_cred_num=rev_reg_max_cred_num,
                issuance_type=rev_reg_issuance_type,
            )
            rev_reg_id = rev_reg_record.rev_reg_id
            rev_reg_max = rev_reg_record.max_cred_num
            rev_reg_issuance = rev_reg_record.issuance_type
            rev_reg_summary = ArtifactSummary(
                kind=ArtifactKind.REV_REG_DEF,
                artifact_id=rev_reg_record.rev_reg_id,
                outcome=rev_reg_outcome,
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
            rev_reg=rev_reg_summary,
            rev_reg_id=rev_reg_id,
            rev_reg_max_cred_num=rev_reg_max,
            rev_reg_issuance_type=rev_reg_issuance,
        )

    # ------------------------------------------------------------------
    # Schemas
    # ------------------------------------------------------------------
    async def _ensure_schema(
        self,
        *,
        issuer: IssuerIdentity,
        schema_name: str,
        schema_version: str,
        attributes: Sequence[str],
    ) -> Tuple[SchemaRecord, ArtifactOutcome]:
        cached = self._find_cached_schema(
            issuer_did=issuer.did,
            name=schema_name,
            version=schema_version,
        )
        if cached is not None:
            schema_record = await self._registry.get_schema(cached.artifact_id)
            if schema_record is not None:
                return schema_record, ArtifactOutcome.REUSED

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

    # ------------------------------------------------------------------
    # Credential definitions
    # ------------------------------------------------------------------
    async def _ensure_cred_def(
        self,
        *,
        issuer: IssuerIdentity,
        schema_record: SchemaRecord,
        tag: str,
        supports_revocation: bool,
    ) -> Tuple[CredDefRecord, ArtifactOutcome]:
        cached = self._find_cached_cred_def(
            issuer_did=issuer.did,
            schema_id=schema_record.schema_id,
            tag=tag,
        )
        if cached is not None:
            cred_def_record = await self._registry.get_cred_def(cached.artifact_id)
            if cred_def_record is not None:
                self._guard_revocation_match(
                    existing=cred_def_record,
                    requested_supports_revocation=supports_revocation,
                    tag=tag,
                )
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
            self._guard_revocation_match(
                existing=existing,
                requested_supports_revocation=supports_revocation,
                tag=tag,
            )
            self._persist_cred_def(issuer=issuer, cred_def=existing)
            return existing, ArtifactOutcome.REUSED

        created = await self._registry.create_cred_def(
            schema_id=schema_record.schema_id,
            tag=tag,
            supports_revocation=supports_revocation,
        )
        self._persist_cred_def(issuer=issuer, cred_def=created)
        return created, ArtifactOutcome.CREATED

    @staticmethod
    def _guard_revocation_match(
        *,
        existing: CredDefRecord,
        requested_supports_revocation: bool,
        tag: str,
    ) -> None:
        """Abort with a clear error if the caller asks for revocation but the
        existing cred_def was published without it (or vice versa).

        ``cred_def`` objects are immutable in Indy: once published they
        cannot be upgraded in place. The only remediation is to publish
        a new cred_def under a different tag, so we bail early with
        actionable guidance.
        """
        if existing.supports_revocation == requested_supports_revocation:
            return
        expected = "revocable" if requested_supports_revocation else "non-revocable"
        actual = "revocable" if existing.supports_revocation else "non-revocable"
        raise ValueError(
            f"Existing credential definition '{existing.cred_def_id}' is {actual}, "
            f"but bootstrap was asked for a {expected} one. Cred defs are "
            "immutable on Indy: pick a different BLOCKCHAIN_CRED_DEF_TAG "
            f"(current value: '{tag}') and re-run the bootstrap to publish a "
            "new cred_def without losing the existing one."
        )

    # ------------------------------------------------------------------
    # Revocation registries
    # ------------------------------------------------------------------
    async def _ensure_rev_reg(
        self,
        *,
        issuer: IssuerIdentity,
        cred_def_record: CredDefRecord,
        max_cred_num: int,
        issuance_type: str,
    ) -> Tuple[RevRegRecord, ArtifactOutcome]:
        cached = self._find_cached_rev_reg(
            issuer_did=issuer.did,
            cred_def_id=cred_def_record.cred_def_id,
        )
        if cached is not None:
            rev_reg_record = await self._registry.get_rev_reg(cached.artifact_id)
            if rev_reg_record is not None:
                return rev_reg_record, ArtifactOutcome.REUSED

        existing = await self._registry.find_active_rev_reg(
            cred_def_id=cred_def_record.cred_def_id
        )
        if existing is not None:
            self._persist_rev_reg(
                issuer=issuer,
                cred_def=cred_def_record,
                rev_reg=existing,
            )
            return existing, ArtifactOutcome.REUSED

        logger.info(
            "Creating rev_reg for cred_def %s (max_cred_num=%d, issuance=%s)",
            cred_def_record.cred_def_id,
            max_cred_num,
            issuance_type,
        )
        created = await self._registry.create_rev_reg(
            cred_def_id=cred_def_record.cred_def_id,
            max_cred_num=max_cred_num,
            issuance_type=issuance_type,
        )

        # Push tails file to the tails server so verifiers can later fetch
        # it when validating non-revocation proofs.
        logger.info("Uploading tails file for %s", created.rev_reg_id)
        await self._registry.upload_tails_file(created.rev_reg_id)

        # Anchor the rev_reg_def on the ledger (1 tx) and then publish
        # the initial rev_reg_entry / accumulator (another tx).
        logger.info("Publishing rev_reg_def on ledger: %s", created.rev_reg_id)
        await self._registry.publish_rev_reg_def(created.rev_reg_id)

        logger.info("Publishing initial rev_reg_entry: %s", created.rev_reg_id)
        await self._registry.publish_rev_reg_entry(created.rev_reg_id)

        # Re-read so we capture the state ACA-Py assigned after publish.
        final = await self._registry.get_rev_reg(created.rev_reg_id) or created
        self._persist_rev_reg(
            issuer=issuer,
            cred_def=cred_def_record,
            rev_reg=final,
        )
        return final, ArtifactOutcome.CREATED

    # ------------------------------------------------------------------
    # Cached lookups
    # ------------------------------------------------------------------
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

    def _find_cached_rev_reg(
        self,
        *,
        issuer_did: str,
        cred_def_id: str,
    ) -> Optional[ArtifactRecord]:
        with self._session_scope() as db:
            return self._repository.find_artifact(
                db,
                kind=ArtifactKind.REV_REG_DEF,
                issuer_did=issuer_did,
                schema_id=cred_def_id,
            )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
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

    def _persist_rev_reg(
        self,
        *,
        issuer: IssuerIdentity,
        cred_def: CredDefRecord,
        rev_reg: RevRegRecord,
    ) -> None:
        """Persist the rev_reg_def reference so lookups are fast."""
        with self._session_scope() as db:
            self._repository.upsert_artifact(
                db,
                kind=ArtifactKind.REV_REG_DEF,
                artifact_id=rev_reg.rev_reg_id,
                name=rev_reg.issuance_type,
                version=str(rev_reg.max_cred_num) if rev_reg.max_cred_num else None,
                tag=cred_def.tag,
                issuer_did=issuer.did,
                # Reuse ``schema_id`` column as the parent cred_def reference so
                # the generic artifact table stays flexible without new columns.
                schema_id=cred_def.cred_def_id,
                supports_revocation=True,
            )

    # ------------------------------------------------------------------
    # Session handling
    # ------------------------------------------------------------------
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
