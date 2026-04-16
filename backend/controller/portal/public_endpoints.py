from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from portal.dependencies import get_moodle_db
from portal.schemas import PublicVerificationResponse
from portal.config import ISSUER_NAME
from portal import moodle_queries
from utils.hashing import compute_credential_hash
from fabric_client import FabricClient

public_router = APIRouter(prefix="/public", tags=["Public Verification"])


def _unix_to_iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


@public_router.get("/verify/{credential_hash}", response_model=PublicVerificationResponse)
def verify_public(
    credential_hash: str,
    moodle_db: Session = Depends(get_moodle_db),
):
    """Publicly verify a credential by its Fabric hash.

    No authentication required. Returns basic metadata if the hash is valid.
    """
    # 1. Try Fabric ledger first
    blockchain_confirmed = False
    try:
        client = FabricClient()
        all_assets = client.get_all_credentials()
        if all_assets and all_assets.get("success"):
            for asset in all_assets.get("assets", []):
                if asset.get("Hash") == credential_hash:
                    blockchain_confirmed = True
                    break
    except Exception:
        pass

    # 2. Search Moodle DB to find the credential matching this hash
    rows = moodle_queries.get_all_credential_hashes(moodle_db)

    for row in rows:
        grade = moodle_queries.get_user_grade(
            moodle_db, row["userid"], row["courseid"]
        ) or "Aprobado"

        computed_hash = compute_credential_hash(
            student_id=str(row["userid"]),
            course_id=str(row["courseid"]),
            completion_date=_unix_to_iso(row["timecreated"]),
            grade=grade,
        )

        if computed_hash == credential_hash:
            student_name = f"{row['firstname']} {row['lastname']}"
            return PublicVerificationResponse(
                valid=True,
                credential_hash=credential_hash,
                student_name=student_name,
                course_name=row["course_name"],
                completion_date=_unix_to_iso(row["timecreated"]),
                issuer=ISSUER_NAME,
                blockchain_confirmed=blockchain_confirmed,
            )

    return PublicVerificationResponse(
        valid=False,
        credential_hash=credential_hash,
        blockchain_confirmed=blockchain_confirmed,
    )
