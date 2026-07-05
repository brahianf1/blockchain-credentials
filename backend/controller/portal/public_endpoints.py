"""Public verification endpoints.

No authentication is required: any third party (e.g. a prospective
employer) can submit a credential hash and obtain the credential
metadata plus verifiable on-ledger evidence.

Privacy policy:
    * By default credentials are **private**. The student must
      explicitly opt-in to public visibility via the portal.
    * When a credential is private, the endpoint still confirms the
      hash is valid (blockchain evidence is immutable / public) but
      does NOT reveal the student's personal information.
    * When a credential is public, full metadata is returned.

Design notes:
    * The source of truth for a credential's existence is the Moodle
      database. The ledger provides independent, tamper-evident
      evidence that the institution committed to the issuance.
    * The ledger client is an injected abstraction (``LedgerClient``)
      so this handler is agnostic to the concrete blockchain stack.
"""
import html
import json
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.orm import Session

from blockchain import AnchorStatus, CredentialAnchor, LedgerClient, get_ledger_client
from portal import moodle_queries
from portal.config import ISSUER_NAME, PORTAL_FRONTEND_URL, PORTAL_OG_IMAGE_URL
from portal.dependencies import get_moodle_db, get_portal_db
from portal.models import CredentialVisibility
from portal.schemas import (
    BlockchainEvidence,
    PublicVerificationResponse,
    VerificationVerdict,
)
from utils.hashing import compute_credential_hash
from portal.image_generator import generate_dynamic_og_image

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


def _derive_verdict(anchor: Optional[CredentialAnchor]) -> VerificationVerdict:
    """Map on-chain evidence to an authoritative third-party verdict.

    The institutional registry already confirmed the credential exists
    (the caller only invokes this after a hash match).  The *validity*,
    however, is decided by the ledger — the single source of truth for
    revocation:

        on-chain ANCHORED  -> VALID
        on-chain REVOKED   -> REVOKED   (explicitly NOT valid)
        no confirmed proof -> NOT_ANCHORED
    """
    if anchor is None:
        return VerificationVerdict.NOT_ANCHORED
    if anchor.status == AnchorStatus.ANCHORED:
        return VerificationVerdict.VALID
    if anchor.status == AnchorStatus.REVOKED:
        return VerificationVerdict.REVOKED
    # PENDING_ANCHORING / UNAVAILABLE → no confirmed cryptographic proof yet.
    return VerificationVerdict.NOT_ANCHORED


def _is_credential_public(portal_db: Session, user_id: int, cred_hash: str) -> bool:
    """Check whether the student has opted to make this credential publicly visible."""
    row = (
        portal_db.query(CredentialVisibility)
        .filter(
            CredentialVisibility.moodle_user_id == user_id,
            CredentialVisibility.credential_hash == cred_hash,
            CredentialVisibility.is_public.is_(True),
        )
        .first()
    )
    return row is not None


async def _resolve_verification(
    credential_hash: str,
    moodle_db: Session,
    portal_db: Session,
    ledger: LedgerClient,
) -> PublicVerificationResponse:
    """Resolve the public verification verdict for a credential hash.

    Shared by the JSON endpoint and the Open Graph embed page so both
    surface the exact same verdict and respect the same privacy policy.

    Respects the holder's visibility preference (W3C VC 2.0 data
    minimization):
    - Public credentials: full certificate metadata + blockchain evidence.
    - Private credentials: only the verdict is disclosed (it exists and is
      valid/revoked); name, course, date and the on-chain evidence link are
      withheld. The revocation signal is always surfaced regardless of
      visibility, so a holder cannot hide a revocation from a verifier.
    """
    # Postel's Law (Robustness Principle): Be liberal in what you accept.
    # If the user copied the hash from the Blockscout explorer, it will
    # have a "0x" prefix and might contain uppercase letters. We normalize
    # it to match our internal lowercase representation.
    credential_hash = credential_hash.lower().removeprefix("0x")

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

            # The ledger is the authority on validity: a revoked credential
            # MUST NOT be reported as valid, even though it exists in the
            # institutional registry.
            verdict = _derive_verdict(anchor)
            is_valid = verdict == VerificationVerdict.VALID
            revoked_at = (
                anchor.ledger_timestamp
                if anchor and verdict == VerificationVerdict.REVOKED
                else None
            )

            is_public = _is_credential_public(
                portal_db, row["userid"], credential_hash
            )

            # Holder sovereignty (W3C VC 2.0 data minimization): a private
            # credential withholds ALL certificate data — name, course and
            # date — and the on-chain evidence deep-link, disclosing only that
            # it exists and its verdict. The verifier is told it is private by
            # the holder's choice, not that it is missing.
            #
            # The revocation signal is the one exception: it is the issuer's
            # statement about validity (public by design, like a W3C
            # StatusList) and is ALWAYS surfaced so a holder cannot hide a
            # revocation from a third party.
            if not is_public:
                return PublicVerificationResponse(
                    valid=is_valid,
                    verdict=verdict,
                    credential_hash=credential_hash,
                    is_private=True,
                    issuer=ISSUER_NAME,
                    revoked_at=revoked_at,
                )

            # Public: the holder opted in to full disclosure. Personal data is
            # still only shown while the credential is valid — a revoked one
            # never discloses identity beyond what the ledger already exposes.
            student_name = (
                f"{row['firstname']} {row['lastname']}" if is_valid else None
            )

            return PublicVerificationResponse(
                valid=is_valid,
                verdict=verdict,
                credential_hash=credential_hash,
                is_private=False,
                student_name=student_name,
                course_name=row["course_name"],
                completion_date=_unix_to_iso(row["timecreated"]),
                issuer=ISSUER_NAME,
                revoked_at=revoked_at,
                blockchain=_anchor_to_evidence(anchor),
            )

    return PublicVerificationResponse(
        valid=False,
        verdict=VerificationVerdict.NOT_FOUND,
        credential_hash=credential_hash,
    )


@public_router.get(
    "/verify/{credential_hash}",
    response_model=PublicVerificationResponse,
)
async def verify_public(
    credential_hash: str,
    moodle_db: Session = Depends(get_moodle_db),
    portal_db: Session = Depends(get_portal_db),
    ledger: LedgerClient = Depends(get_ledger_client),
):
    """Publicly verify a credential by its SHA-256 hash (machine-readable JSON)."""
    return await _resolve_verification(credential_hash, moodle_db, portal_db, ledger)


def _build_og_card(result: PublicVerificationResponse) -> tuple[str, str]:
    """Return a privacy-aware ``(title, description)`` for the social card.

    Mirrors the verification policy: a revoked credential always shows the
    revocation; a private one reveals no certificate data; only a public,
    valid credential exposes the course and holder name.
    """
    issuer = result.issuer or ISSUER_NAME

    if result.verdict == VerificationVerdict.NOT_FOUND:
        return (
            "Credencial no encontrada",
            "No existe una credencial que corresponda a este identificador.",
        )
    if result.verdict == VerificationVerdict.REVOKED:
        return (
            "Credencial revocada",
            f"Esta credencial fue revocada por {issuer} y ya no es válida.",
        )
    if result.is_private:
        return (
            "Credencial privada",
            f"Credencial verificable emitida por {issuer}. "
            "Su titular decidió mantener los detalles en privado.",
        )
    if result.verdict == VerificationVerdict.VALID:
        title = result.course_name or "Credencial verificada"
        who = f" · {result.student_name}" if result.student_name else ""
        return (title, f"Credencial verificada en blockchain · {issuer}{who}")

    # NOT_ANCHORED (public)
    return (
        result.course_name or "Credencial reconocida",
        f"Reconocida por {issuer}. Anclaje en blockchain pendiente.",
    )


def _render_og_html(result: PublicVerificationResponse, request: Request) -> str:
    """Render a minimal HTML page carrying Open Graph tags for social crawlers.

    Social bots (LinkedIn, WhatsApp, X…) don't run JavaScript, so the SPA's
    client-rendered meta tags never reach them. This server-rendered page gives
    a rich preview card and redirects human visitors to the canonical portal
    verification page.
    """
    canonical = f"{PORTAL_FRONTEND_URL.rstrip('/')}/verificar/{result.credential_hash}"
    title, description = _build_og_card(result)

    def e(value: str) -> str:
        return html.escape(str(value), quote=True)
        
    image_url = str(request.url_for("verify_image", credential_hash=result.credential_hash))

    image_tag = (
        f'<meta property="og:image" content="{e(image_url)}"/>'
    )

    return (
        "<!doctype html>\n"
        '<html lang="es"><head><meta charset="utf-8"/>\n'
        f"<title>{e(title)}</title>\n"
        '<meta name="robots" content="noindex"/>\n'
        '<meta property="og:type" content="website"/>\n'
        f'<meta property="og:site_name" content="{e(result.issuer or ISSUER_NAME)}"/>\n'
        f'<meta property="og:title" content="{e(title)}"/>\n'
        f'<meta property="og:description" content="{e(description)}"/>\n'
        f'<meta property="og:url" content="{e(canonical)}"/>\n'
        f"{image_tag}\n"
        '<meta name="twitter:card" content="summary_large_image"/>\n'
        f'<meta name="twitter:title" content="{e(title)}"/>\n'
        f'<meta name="twitter:description" content="{e(description)}"/>\n'
        f'<meta http-equiv="refresh" content="0; url={e(canonical)}"/>\n'
        f'<link rel="canonical" href="{e(canonical)}"/>\n'
        "</head><body>\n"
        f'<p>Redirigiendo a la verificación… Si no ocurre, '
        f'<a href="{e(canonical)}">hacé clic aquí</a>.</p>\n'
        f"<script>window.location.replace({json.dumps(canonical)});</script>\n"
        "</body></html>"
    )


@public_router.get("/verify/{credential_hash}/embed", response_class=HTMLResponse)
async def verify_embed(
    request: Request,
    credential_hash: str,
    moodle_db: Session = Depends(get_moodle_db),
    portal_db: Session = Depends(get_portal_db),
    ledger: LedgerClient = Depends(get_ledger_client),
):
    """Open Graph share page: rich preview for social crawlers, redirect for humans.

    This is the URL to embed in social shares so LinkedIn/WhatsApp render a card.
    It honours the same privacy policy as the JSON endpoint — a private
    credential's card discloses no certificate data.
    """
    result = await _resolve_verification(credential_hash, moodle_db, portal_db, ledger)
    return HTMLResponse(content=_render_og_html(result, request))


@public_router.get("/verify/{credential_hash}/image", response_class=Response)
async def verify_image(
    credential_hash: str,
    moodle_db: Session = Depends(get_moodle_db),
    portal_db: Session = Depends(get_portal_db),
    ledger: LedgerClient = Depends(get_ledger_client),
):
    """Dynamic Open Graph image generation.
    
    Returns a PNG image. If the credential is public and valid, it prints the
    course name and student name on the certificate image.
    """
    result = await _resolve_verification(credential_hash, moodle_db, portal_db, ledger)
    
    course_name = None
    student_name = None
    
    if result.verdict == VerificationVerdict.VALID and not result.is_private:
        course_name = result.course_name
        student_name = result.student_name

    image_bytes = generate_dynamic_og_image(course_name, student_name)
    return Response(content=image_bytes, media_type="image/png")
