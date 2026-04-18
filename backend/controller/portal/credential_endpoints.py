"""Authenticated credential endpoints for the student portal."""
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from blockchain import CredentialAnchor, LedgerClient, get_ledger_client
from portal import moodle_queries
from portal.dependencies import get_current_user, get_moodle_db
from portal.models import PortalStudent
from portal.schemas import (
    BlockchainEvidence,
    CredentialDetail,
    CredentialSummary,
)
from utils.hashing import compute_credential_hash

credential_router = APIRouter(prefix="/credentials", tags=["Portal Credentials"])


def _unix_to_iso(ts: int) -> str:
    """Convert a Unix timestamp (as stored by Moodle) to an ISO 8601 string."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _build_credential_hash(row: dict, grade: str, student_id: Optional[int] = None) -> str:
    """Compute the canonical credential hash from a Moodle DB row."""
    resolved_student_id = row.get("userid") if student_id is None else student_id
    return compute_credential_hash(
        student_id=str(resolved_student_id) if resolved_student_id is not None else "",
        course_id=str(row["courseid"]),
        completion_date=_unix_to_iso(row["timecreated"]),
        grade=grade,
    )


def _anchor_to_evidence(anchor: Optional[CredentialAnchor]) -> Optional[BlockchainEvidence]:
    """Translate a domain-level anchor into the API evidence schema."""
    if anchor is None:
        return None
    return BlockchainEvidence(
        network=anchor.network,
        status=anchor.status,
        issuer_did=anchor.issuer_did,
        schema_id=anchor.schema_id,
        cred_def_id=anchor.cred_def_id,
        rev_reg_id=anchor.rev_reg_id,
        cred_rev_id=anchor.cred_rev_id,
        txn_id=anchor.txn_id,
        seq_no=anchor.seq_no,
        ledger_timestamp=anchor.ledger_timestamp,
        explorer_url=anchor.explorer_url,
    )


@credential_router.get("", response_model=List[CredentialSummary])
def list_credentials(
    current_user: PortalStudent = Depends(get_current_user),
    moodle_db: Session = Depends(get_moodle_db),
):
    """List all credentials for the authenticated student."""
    rows = moodle_queries.get_credentials_for_user(moodle_db, current_user.moodle_user_id)

    credentials: List[CredentialSummary] = []
    for row in rows:
        grade = (
            moodle_queries.get_user_grade(
                moodle_db, current_user.moodle_user_id, row["courseid"]
            )
            or "Aprobado"
        )

        credentials.append(
            CredentialSummary(
                id=row["id"],
                course_name=row["course_name"],
                course_id=row["courseid"],
                status=row["status"],
                completion_date=_unix_to_iso(row["timecreated"]),
                credential_hash=_build_credential_hash(
                    row, grade, student_id=current_user.moodle_user_id
                ),
                created_at=_unix_to_iso(row["timecreated"]),
            )
        )

    return credentials


@credential_router.get("/{credential_id}", response_model=CredentialDetail)
def get_credential(
    credential_id: int,
    current_user: PortalStudent = Depends(get_current_user),
    moodle_db: Session = Depends(get_moodle_db),
):
    """Return full details for a specific credential owned by the authenticated student."""
    row = moodle_queries.get_credential_by_id(
        moodle_db, credential_id, current_user.moodle_user_id
    )
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credencial no encontrada",
        )

    grade = (
        moodle_queries.get_user_grade(
            moodle_db, current_user.moodle_user_id, row["courseid"]
        )
        or "Aprobado"
    )

    credential_hash = _build_credential_hash(row, grade)
    student_name = f"{row['firstname']} {row['lastname']}"

    return CredentialDetail(
        id=row["id"],
        course_name=row["course_name"],
        course_id=row["courseid"],
        status=row["status"],
        completion_date=_unix_to_iso(row["timecreated"]),
        credential_hash=credential_hash,
        created_at=_unix_to_iso(row["timecreated"]),
        student_name=student_name,
        student_email=row["student_email"],
        grade=grade,
        invitation_url=row.get("invitation_url"),
        qr_code_base64=row.get("qr_code_base64"),
        claimed_at=_unix_to_iso(row["timemodified"]) if row.get("timemodified") else None,
    )


@credential_router.get("/{credential_id}/verify", response_model=CredentialDetail)
async def verify_credential(
    credential_id: int,
    current_user: PortalStudent = Depends(get_current_user),
    moodle_db: Session = Depends(get_moodle_db),
    ledger: LedgerClient = Depends(get_ledger_client),
):
    """Verify a credential and attach on-ledger evidence when available."""
    row = moodle_queries.get_credential_by_id(
        moodle_db, credential_id, current_user.moodle_user_id
    )
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credencial no encontrada",
        )

    grade = (
        moodle_queries.get_user_grade(
            moodle_db, current_user.moodle_user_id, row["courseid"]
        )
        or "Aprobado"
    )

    credential_hash = _build_credential_hash(row, grade)
    student_name = f"{row['firstname']} {row['lastname']}"

    anchor = await ledger.resolve_anchor(credential_hash)

    return CredentialDetail(
        id=row["id"],
        course_name=row["course_name"],
        course_id=row["courseid"],
        status=row["status"],
        completion_date=_unix_to_iso(row["timecreated"]),
        credential_hash=credential_hash,
        created_at=_unix_to_iso(row["timecreated"]),
        student_name=student_name,
        student_email=row["student_email"],
        grade=grade,
        invitation_url=row.get("invitation_url"),
        qr_code_base64=row.get("qr_code_base64"),
        blockchain=_anchor_to_evidence(anchor),
        claimed_at=_unix_to_iso(row["timemodified"]) if row.get("timemodified") else None,
    )
