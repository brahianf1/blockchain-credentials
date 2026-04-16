from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from portal.dependencies import get_current_user, get_moodle_db
from portal.models import PortalStudent
from portal.schemas import CredentialDetail, CredentialSummary
from portal import moodle_queries
from utils.hashing import compute_credential_hash
from fabric_client import FabricClient

credential_router = APIRouter(prefix="/credentials", tags=["Portal Credentials"])


def _unix_to_iso(ts: int) -> str:
    """Convert a Unix timestamp (as stored by Moodle) to an ISO 8601 string."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _build_fabric_hash(row: dict, grade: str) -> str:
    """Compute the Fabric credential hash from a Moodle DB row."""
    return compute_credential_hash(
        student_id=str(row["userid"]) if "userid" in row else "",
        course_id=str(row["courseid"]),
        completion_date=_unix_to_iso(row["timecreated"]),
        grade=grade,
    )


@credential_router.get("", response_model=List[CredentialSummary])
def list_credentials(
    current_user: PortalStudent = Depends(get_current_user),
    moodle_db: Session = Depends(get_moodle_db),
):
    """List all credentials for the authenticated student."""
    rows = moodle_queries.get_credentials_for_user(moodle_db, current_user.moodle_user_id)

    credentials = []
    for row in rows:
        grade = moodle_queries.get_user_grade(
            moodle_db, current_user.moodle_user_id, row["courseid"]
        ) or "Aprobado"

        credentials.append(
            CredentialSummary(
                id=row["id"],
                course_name=row["course_name"],
                course_id=row["courseid"],
                status=row["status"],
                completion_date=_unix_to_iso(row["timecreated"]),
                fabric_hash=_build_fabric_hash(
                    {**row, "userid": current_user.moodle_user_id}, grade
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

    grade = moodle_queries.get_user_grade(
        moodle_db, current_user.moodle_user_id, row["courseid"]
    ) or "Aprobado"

    fabric_hash = _build_fabric_hash(row, grade)
    student_name = f"{row['firstname']} {row['lastname']}"

    return CredentialDetail(
        id=row["id"],
        course_name=row["course_name"],
        course_id=row["courseid"],
        status=row["status"],
        completion_date=_unix_to_iso(row["timecreated"]),
        fabric_hash=fabric_hash,
        created_at=_unix_to_iso(row["timecreated"]),
        student_name=student_name,
        student_email=row["student_email"],
        grade=grade,
        invitation_url=row.get("invitation_url"),
        qr_code_base64=row.get("qr_code_base64"),
        fabric_asset_id=f"credential_{row['userid']}_{row['timecreated']}",
        claimed_at=_unix_to_iso(row["timemodified"]) if row.get("timemodified") else None,
    )


@credential_router.get("/{credential_id}/verify", response_model=CredentialDetail)
def verify_credential(
    credential_id: int,
    current_user: PortalStudent = Depends(get_current_user),
    moodle_db: Session = Depends(get_moodle_db),
):
    """Verify a credential against the Hyperledger Fabric blockchain."""
    row = moodle_queries.get_credential_by_id(
        moodle_db, credential_id, current_user.moodle_user_id
    )
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credencial no encontrada",
        )

    grade = moodle_queries.get_user_grade(
        moodle_db, current_user.moodle_user_id, row["courseid"]
    ) or "Aprobado"

    fabric_hash = _build_fabric_hash(row, grade)
    asset_id = f"credential_{row['userid']}_{row['timecreated']}"
    student_name = f"{row['firstname']} {row['lastname']}"

    # Attempt Fabric ledger verification
    fabric_verified = False
    try:
        client = FabricClient()
        result = client.query_credential(asset_id)
        if result and result.get("success"):
            fabric_verified = True
    except Exception:
        pass  # Fabric unavailable — report as unverified

    return CredentialDetail(
        id=row["id"],
        course_name=row["course_name"],
        course_id=row["courseid"],
        status=row["status"],
        completion_date=_unix_to_iso(row["timecreated"]),
        fabric_hash=fabric_hash,
        created_at=_unix_to_iso(row["timecreated"]),
        student_name=student_name,
        student_email=row["student_email"],
        grade=grade,
        invitation_url=row.get("invitation_url"),
        qr_code_base64=row.get("qr_code_base64"),
        fabric_verified=fabric_verified,
        fabric_asset_id=asset_id,
        claimed_at=_unix_to_iso(row["timemodified"]) if row.get("timemodified") else None,
    )
