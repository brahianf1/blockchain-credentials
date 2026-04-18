"""Persistence layer for ledger artifacts and credential anchors.

Responsibilities:
    * Idempotent upserts for institutional artifacts (schema, cred_def).
    * CRUD for per-credential anchors keyed by ``credential_hash``.
    * Revocation state updates.

The repository is deliberately decoupled from FastAPI's request lifecycle
so it can be used from the HTTP layer, background tasks and CLI scripts.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, List, Optional

from sqlalchemy.orm import Session

from portal.models import CredentialAnchor, LedgerArtifact


@dataclass(frozen=True)
class ArtifactRecord:
    """Subset of ``LedgerArtifact`` fields used by callers outside the ORM."""

    id: int
    kind: str
    artifact_id: str
    name: Optional[str]
    version: Optional[str]
    tag: Optional[str]
    issuer_did: Optional[str]
    schema_id: Optional[str]
    supports_revocation: bool
    txn_id: Optional[str]
    seq_no: Optional[int]
    ledger_timestamp: Optional[datetime]


@dataclass(frozen=True)
class AnchorRecord:
    """Subset of ``CredentialAnchor`` fields used by callers outside the ORM."""

    id: int
    credential_hash: str
    moodle_credential_id: Optional[int]
    moodle_user_id: Optional[int]
    moodle_course_id: Optional[int]
    issuer_did: Optional[str]
    schema_id: Optional[str]
    cred_def_id: Optional[str]
    rev_reg_id: Optional[str]
    cred_rev_id: Optional[str]
    txn_id: Optional[str]
    seq_no: Optional[int]
    ledger_timestamp: Optional[datetime]
    revoked: bool
    revoked_at: Optional[datetime]
    revoked_reason: Optional[str]
    anchored_at: datetime


class ArtifactKind:
    """Supported values for ``LedgerArtifact.kind``."""

    SCHEMA = "schema"
    CRED_DEF = "cred_def"
    REV_REG_DEF = "rev_reg_def"


class LedgerRepository:
    """Data-access object for the ``portal_ledger_artifacts`` and
    ``portal_blockchain_anchors`` tables.

    All methods expect an externally managed :class:`Session`, which lets
    callers compose transactions across the repository and other models.
    """

    # ------------------------------------------------------------------
    # Ledger artifacts
    # ------------------------------------------------------------------
    def get_artifact(
        self,
        db: Session,
        *,
        kind: str,
        artifact_id: str,
    ) -> Optional[ArtifactRecord]:
        row = (
            db.query(LedgerArtifact)
            .filter(
                LedgerArtifact.kind == kind,
                LedgerArtifact.artifact_id == artifact_id,
            )
            .one_or_none()
        )
        return _artifact_to_record(row) if row else None

    def find_artifact(
        self,
        db: Session,
        *,
        kind: str,
        issuer_did: Optional[str] = None,
        name: Optional[str] = None,
        version: Optional[str] = None,
        schema_id: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> Optional[ArtifactRecord]:
        query = db.query(LedgerArtifact).filter(LedgerArtifact.kind == kind)
        if issuer_did is not None:
            query = query.filter(LedgerArtifact.issuer_did == issuer_did)
        if name is not None:
            query = query.filter(LedgerArtifact.name == name)
        if version is not None:
            query = query.filter(LedgerArtifact.version == version)
        if schema_id is not None:
            query = query.filter(LedgerArtifact.schema_id == schema_id)
        if tag is not None:
            query = query.filter(LedgerArtifact.tag == tag)
        row = query.order_by(LedgerArtifact.created_at.desc()).first()
        return _artifact_to_record(row) if row else None

    def list_artifacts(
        self, db: Session, *, kind: Optional[str] = None
    ) -> List[ArtifactRecord]:
        query = db.query(LedgerArtifact)
        if kind is not None:
            query = query.filter(LedgerArtifact.kind == kind)
        rows: Iterable[LedgerArtifact] = query.order_by(
            LedgerArtifact.created_at.desc()
        ).all()
        return [_artifact_to_record(row) for row in rows]

    def upsert_artifact(
        self,
        db: Session,
        *,
        kind: str,
        artifact_id: str,
        name: Optional[str] = None,
        version: Optional[str] = None,
        tag: Optional[str] = None,
        issuer_did: Optional[str] = None,
        schema_id: Optional[str] = None,
        supports_revocation: bool = False,
        txn_id: Optional[str] = None,
        seq_no: Optional[int] = None,
        ledger_timestamp: Optional[datetime] = None,
        extra: Optional[str] = None,
    ) -> ArtifactRecord:
        row = (
            db.query(LedgerArtifact)
            .filter(
                LedgerArtifact.kind == kind,
                LedgerArtifact.artifact_id == artifact_id,
            )
            .one_or_none()
        )
        if row is None:
            row = LedgerArtifact(
                kind=kind,
                artifact_id=artifact_id,
                name=name,
                version=version,
                tag=tag,
                issuer_did=issuer_did,
                schema_id=schema_id,
                supports_revocation=supports_revocation,
                txn_id=txn_id,
                seq_no=seq_no,
                ledger_timestamp=ledger_timestamp,
                extra=extra,
            )
            db.add(row)
        else:
            row.name = name if name is not None else row.name
            row.version = version if version is not None else row.version
            row.tag = tag if tag is not None else row.tag
            row.issuer_did = (
                issuer_did if issuer_did is not None else row.issuer_did
            )
            row.schema_id = (
                schema_id if schema_id is not None else row.schema_id
            )
            row.supports_revocation = supports_revocation
            if txn_id is not None:
                row.txn_id = txn_id
            if seq_no is not None:
                row.seq_no = seq_no
            if ledger_timestamp is not None:
                row.ledger_timestamp = ledger_timestamp
            if extra is not None:
                row.extra = extra
        db.flush()
        return _artifact_to_record(row)

    # ------------------------------------------------------------------
    # Credential anchors
    # ------------------------------------------------------------------
    def get_anchor(
        self, db: Session, credential_hash: str
    ) -> Optional[AnchorRecord]:
        row = (
            db.query(CredentialAnchor)
            .filter(CredentialAnchor.credential_hash == credential_hash)
            .one_or_none()
        )
        return _anchor_to_record(row) if row else None

    def upsert_anchor(
        self,
        db: Session,
        *,
        credential_hash: str,
        moodle_credential_id: Optional[int] = None,
        moodle_user_id: Optional[int] = None,
        moodle_course_id: Optional[int] = None,
        issuer_did: Optional[str] = None,
        schema_id: Optional[str] = None,
        cred_def_id: Optional[str] = None,
        rev_reg_id: Optional[str] = None,
        cred_rev_id: Optional[str] = None,
        txn_id: Optional[str] = None,
        seq_no: Optional[int] = None,
        ledger_timestamp: Optional[datetime] = None,
    ) -> AnchorRecord:
        row = (
            db.query(CredentialAnchor)
            .filter(CredentialAnchor.credential_hash == credential_hash)
            .one_or_none()
        )
        if row is None:
            row = CredentialAnchor(
                credential_hash=credential_hash,
                moodle_credential_id=moodle_credential_id,
                moodle_user_id=moodle_user_id,
                moodle_course_id=moodle_course_id,
                issuer_did=issuer_did,
                schema_id=schema_id,
                cred_def_id=cred_def_id,
                rev_reg_id=rev_reg_id,
                cred_rev_id=cred_rev_id,
                txn_id=txn_id,
                seq_no=seq_no,
                ledger_timestamp=ledger_timestamp,
            )
            db.add(row)
        else:
            for attr, value in (
                ("moodle_credential_id", moodle_credential_id),
                ("moodle_user_id", moodle_user_id),
                ("moodle_course_id", moodle_course_id),
                ("issuer_did", issuer_did),
                ("schema_id", schema_id),
                ("cred_def_id", cred_def_id),
                ("rev_reg_id", rev_reg_id),
                ("cred_rev_id", cred_rev_id),
                ("txn_id", txn_id),
                ("seq_no", seq_no),
                ("ledger_timestamp", ledger_timestamp),
            ):
                if value is not None:
                    setattr(row, attr, value)
        db.flush()
        return _anchor_to_record(row)

    def mark_revoked(
        self,
        db: Session,
        credential_hash: str,
        *,
        reason: Optional[str] = None,
    ) -> Optional[AnchorRecord]:
        row = (
            db.query(CredentialAnchor)
            .filter(CredentialAnchor.credential_hash == credential_hash)
            .one_or_none()
        )
        if row is None:
            return None
        row.revoked = True
        row.revoked_at = datetime.now(tz=timezone.utc)
        row.revoked_reason = reason
        db.flush()
        return _anchor_to_record(row)

    def count_anchors(self, db: Session) -> int:
        return db.query(CredentialAnchor).count()


# ----------------------------------------------------------------------
# Internal converters
# ----------------------------------------------------------------------
def _artifact_to_record(row: LedgerArtifact) -> ArtifactRecord:
    return ArtifactRecord(
        id=row.id,
        kind=row.kind,
        artifact_id=row.artifact_id,
        name=row.name,
        version=row.version,
        tag=row.tag,
        issuer_did=row.issuer_did,
        schema_id=row.schema_id,
        supports_revocation=bool(row.supports_revocation),
        txn_id=row.txn_id,
        seq_no=row.seq_no,
        ledger_timestamp=row.ledger_timestamp,
    )


def _anchor_to_record(row: CredentialAnchor) -> AnchorRecord:
    return AnchorRecord(
        id=row.id,
        credential_hash=row.credential_hash,
        moodle_credential_id=row.moodle_credential_id,
        moodle_user_id=row.moodle_user_id,
        moodle_course_id=row.moodle_course_id,
        issuer_did=row.issuer_did,
        schema_id=row.schema_id,
        cred_def_id=row.cred_def_id,
        rev_reg_id=row.rev_reg_id,
        cred_rev_id=row.cred_rev_id,
        txn_id=row.txn_id,
        seq_no=row.seq_no,
        ledger_timestamp=row.ledger_timestamp,
        revoked=bool(row.revoked),
        revoked_at=row.revoked_at,
        revoked_reason=row.revoked_reason,
        anchored_at=row.anchored_at,
    )
