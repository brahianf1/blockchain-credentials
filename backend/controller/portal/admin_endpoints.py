"""Administrative endpoints for blockchain management.

These routes expose privileged operations (registering the institutional
schema and credential definition on the ledger, inspecting anchoring
state) and are therefore gated behind a shared secret passed in the
``X-Admin-Token`` header. The secret is read from the
``ADMIN_BOOTSTRAP_TOKEN`` environment variable.

The endpoints are intentionally narrow and idempotent so they are safe
to re-invoke from CI/CD pipelines or operational runbooks.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status

from blockchain import (
    BootstrapResult,
    LedgerBootstrapService,
    LedgerRepository,
    get_bootstrap_service,
    get_ledger_repository,
    get_settings,
)
from portal.blockchain_views import build_registry_view, normalize_did_sov
from portal.schemas import (
    BlockchainRegistryResponse,
    BootstrapArtifactReport,
    BootstrapResponse,
)

logger = logging.getLogger(__name__)

admin_router = APIRouter(prefix="/admin/blockchain", tags=["Admin · Blockchain"])


def require_admin_token(
    x_admin_token: Optional[str] = Header(default=None, alias="X-Admin-Token"),
) -> None:
    """FastAPI dependency that enforces the admin shared secret."""
    settings = get_settings()
    expected = settings.admin_bootstrap_token
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ADMIN_BOOTSTRAP_TOKEN not configured on the server",
        )
    if not x_admin_token or x_admin_token != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-Admin-Token header",
        )


@admin_router.post(
    "/bootstrap",
    response_model=BootstrapResponse,
    dependencies=[Depends(require_admin_token)],
)
async def bootstrap_blockchain(
    service: LedgerBootstrapService = Depends(get_bootstrap_service),
) -> BootstrapResponse:
    """Register (or confirm the existence of) the institutional AnonCreds registry.

    Idempotent: when the schema and credential definition are already
    published on the ledger, the response reports them as ``reused``.
    """
    settings = get_settings()
    try:
        result = await service.bootstrap(
            schema_name=settings.schema_name,
            schema_version=settings.schema_version,
            schema_attributes=settings.schema_attributes,
            cred_def_tag=settings.cred_def_tag,
            supports_revocation=settings.supports_revocation,
            rev_reg_max_cred_num=settings.rev_reg_max_cred_num,
            rev_reg_issuance_type=settings.rev_reg_issuance_type,
        )
    except Exception as exc:
        logger.exception("Blockchain bootstrap failed")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Bootstrap failed: {exc}",
        ) from exc

    return _bootstrap_response(result=result, network=settings.network_name)


@admin_router.get(
    "/status",
    response_model=BlockchainRegistryResponse,
    dependencies=[Depends(require_admin_token)],
)
def blockchain_status(
    repository: LedgerRepository = Depends(get_ledger_repository),
) -> BlockchainRegistryResponse:
    """Return the cached state of the institutional registry."""
    return build_registry_view(repository=repository)


def _bootstrap_response(
    *, result: BootstrapResult, network: str
) -> BootstrapResponse:
    rev_reg_report: Optional[BootstrapArtifactReport] = None
    if result.rev_reg is not None:
        rev_reg_report = BootstrapArtifactReport(
            kind=result.rev_reg.kind,
            artifact_id=result.rev_reg.artifact_id,
            outcome=result.rev_reg.outcome.value,
            seq_no=result.rev_reg.seq_no,
        )

    return BootstrapResponse(
        issuer_did=normalize_did_sov(result.issuer_did) or result.issuer_did,
        network=network,
        schema_id=result.schema_id,
        cred_def_id=result.cred_def_id,
        supports_revocation=result.supports_revocation,
        schema=BootstrapArtifactReport(
            kind=result.schema.kind,
            artifact_id=result.schema.artifact_id,
            outcome=result.schema.outcome.value,
            seq_no=result.schema.seq_no,
        ),
        cred_def=BootstrapArtifactReport(
            kind=result.cred_def.kind,
            artifact_id=result.cred_def.artifact_id,
            outcome=result.cred_def.outcome.value,
            seq_no=result.cred_def.seq_no,
        ),
        rev_reg=rev_reg_report,
        rev_reg_id=result.rev_reg_id,
        rev_reg_max_cred_num=result.rev_reg_max_cred_num,
        rev_reg_issuance_type=result.rev_reg_issuance_type,
    )
