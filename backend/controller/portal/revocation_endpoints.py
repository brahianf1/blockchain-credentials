"""Administrative credential management endpoints.

These endpoints are protected by the ``require_admin`` guard which
verifies that the current user has the ``admin`` role — derived from
Moodle's ``is_siteadmin()`` claim in the authentication JWT.

Capabilities:
    * List all credentials with blockchain status
    * Revoke a credential on-chain and in the portal database
"""
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from blockchain import LedgerClient, get_ledger_client
from blockchain.web3_client import besu_client
from portal import moodle_queries
from portal.dependencies import get_moodle_db, get_portal_db, require_admin
from portal.models import CredentialAnchor, PortalStudent
from utils.hashing import compute_credential_hash

import structlog

logger = structlog.get_logger(__name__)

admin_credential_router = APIRouter(
    prefix="/admin/credentials",
    tags=["Admin · Credentials"],
)


# ── Request / Response schemas ──


class RevokeRequest(BaseModel):
    """Request body for revoking a credential."""

    credential_hash: str = Field(
        ..., min_length=64, max_length=64, description="SHA-256 hash"
    )
    reason: str = Field(
        ...,
        min_length=3,
        max_length=256,
        description="Motivo de revocación",
    )


class RevokeResponse(BaseModel):
    """Response after a successful revocation."""

    success: bool
    credential_hash: str
    reason: str
    revoked_at: str
    tx_hash: Optional[str] = None


class AdminCredentialItem(BaseModel):
    """Summary of a credential for the admin dashboard."""

    moodle_credential_id: int
    student_name: str
    student_email: str
    course_name: str
    course_id: int
    completion_date: str
    grade: str
    credential_hash: str
    blockchain_status: str  # "anchored", "revoked", "not_anchored"
    revoked: bool = False
    revoked_at: Optional[str] = None
    revoked_reason: Optional[str] = None


# ── Helpers ──


def _unix_to_iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


# ── Endpoints ──


@admin_credential_router.get("", response_model=List[AdminCredentialItem])
async def list_all_credentials(
    _admin: PortalStudent = Depends(require_admin),
    moodle_db: Session = Depends(get_moodle_db),
    portal_db: Session = Depends(get_portal_db),
    ledger: LedgerClient = Depends(get_ledger_client),
):
    """List all credentials across all students for admin oversight.

    Joins Moodle credential records with on-chain status and portal
    revocation state.
    """
    rows = moodle_queries.get_all_credential_hashes(moodle_db)

    # Pre-load all portal anchors for efficient lookup.
    anchors_by_hash = {}
    all_anchors = portal_db.query(CredentialAnchor).all()
    for a in all_anchors:
        anchors_by_hash[a.credential_hash] = a

    results: List[AdminCredentialItem] = []

    for row in rows:
        grade = (
            moodle_queries.get_user_grade(
                moodle_db, row["userid"], row["courseid"]
            )
            or "Aprobado"
        )

        cred_hash = compute_credential_hash(
            student_id=str(row["userid"]),
            course_id=str(row["courseid"]),
            completion_date=_unix_to_iso(row["timecreated"]),
            grade=grade,
        )

        # Determine blockchain status from portal DB anchor.
        anchor = anchors_by_hash.get(cred_hash)
        if anchor and anchor.revoked:
            bc_status = "revoked"
        elif anchor:
            bc_status = "anchored"
        else:
            bc_status = "not_anchored"

        results.append(
            AdminCredentialItem(
                moodle_credential_id=row["id"],
                student_name=f"{row['firstname']} {row['lastname']}",
                student_email=row.get("email", ""),
                course_name=row["course_name"],
                course_id=row["courseid"],
                completion_date=_unix_to_iso(row["timecreated"]),
                grade=grade,
                credential_hash=cred_hash,
                blockchain_status=bc_status,
                revoked=bool(anchor.revoked) if anchor else False,
                revoked_at=(
                    anchor.revoked_at.isoformat() if anchor and anchor.revoked_at else None
                ),
                revoked_reason=(
                    anchor.revoked_reason if anchor else None
                ),
            )
        )

    return results


@admin_credential_router.post("/revoke", response_model=RevokeResponse)
async def revoke_credential(
    body: RevokeRequest,
    admin: PortalStudent = Depends(require_admin),
    portal_db: Session = Depends(get_portal_db),
):
    """Revoke a credential on-chain and in the portal database.

    Steps:
        1. Validate the credential hash exists in the portal anchors.
        2. Execute ``revokeCredential(bytes32)`` on-chain.
        3. Mark the anchor as revoked in the portal database.
        4. Return the revocation confirmation with TX hash.
    """
    repo = BlockchainRepository()

    # 1. Look up the anchor in the portal DB.
    anchor = (
        portal_db.query(CredentialAnchor)
        .filter(CredentialAnchor.credential_hash == body.credential_hash)
        .first()
    )

    if not anchor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credencial no encontrada en los registros de blockchain",
        )

    if anchor.revoked:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="La credencial ya fue revocada",
        )

    # 2. Revoke on-chain.
    tx_hash = await besu_client.revoke_credential_hash(body.credential_hash)

    if not tx_hash:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="No se pudo revocar en la blockchain. "
            "La credencial puede no estar anclada on-chain.",
        )

    # 3. Mark revoked in portal DB.
    revoked_at = datetime.now(tz=timezone.utc)
    anchor.revoked = True
    anchor.revoked_at = revoked_at
    anchor.revoked_reason = body.reason
    portal_db.commit()

    logger.info(
        "🔴 Credencial revocada",
        credential_hash=body.credential_hash,
        reason=body.reason,
        admin_id=admin.id,
        admin_email=admin.email,
        tx_hash=tx_hash,
    )

    return RevokeResponse(
        success=True,
        credential_hash=body.credential_hash,
        reason=body.reason,
        revoked_at=revoked_at.isoformat(),
        tx_hash=tx_hash,
    )
