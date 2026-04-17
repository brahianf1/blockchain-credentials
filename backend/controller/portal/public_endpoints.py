"""Public verification endpoints.

No authentication is required: any third party (e.g. a prospective
employer) can submit a credential hash and obtain the credential
metadata plus verifiable on-ledger evidence.

Design notes:
    * The source of truth for a credential's existence is the Moodle
      database. The ledger provides independent, tamper-evident
      evidence that the institution committed to the issuance.
    * The ledger client is an injected abstraction (``LedgerClient``)
      so this handler is agnostic to the concrete blockchain stack.
"""
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from blockchain import CredentialAnchor, LedgerClient, get_ledger_client
from portal import moodle_queries
from portal.config import ISSUER_NAME
from portal.dependencies import get_moodle_db
from portal.schemas import BlockchainEvidence, PublicVerificationResponse
from utils.hashing import compute_credential_hash

public_router = APIRouter(prefix="/public", tags=["Public Verification"])


def _unix_to_iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


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


@public_router.get(
    "/verify/{credential_hash}",
    response_model=PublicVerificationResponse,
)
async def verify_public(
    credential_hash: str,
    moodle_db: Session = Depends(get_moodle_db),
    ledger: LedgerClient = Depends(get_ledger_client),
):
    """Publicly verify a credential by its SHA-256 hash."""
    rows = moodle_queries.get_all_credential_hashes(moodle_db)

    for row in rows:
        grade = (
            moodle_queries.get_user_grade(moodle_db, row["userid"], row["courseid"])
            or "Aprobado"
        )

        computed_hash = compute_credential_hash(
            student_id=str(row["userid"]),
            course_id=str(row["courseid"]),
            completion_date=_unix_to_iso(row["timecreated"]),
            grade=grade,
        )

        if computed_hash == credential_hash:
            anchor = await ledger.resolve_anchor(credential_hash)
            return PublicVerificationResponse(
                valid=True,
                credential_hash=credential_hash,
                student_name=f"{row['firstname']} {row['lastname']}",
                course_name=row["course_name"],
                completion_date=_unix_to_iso(row["timecreated"]),
                issuer=ISSUER_NAME,
                blockchain=_anchor_to_evidence(anchor),
            )

    return PublicVerificationResponse(
        valid=False,
        credential_hash=credential_hash,
    )
