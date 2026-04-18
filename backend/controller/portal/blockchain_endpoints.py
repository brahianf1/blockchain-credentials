"""Public, read-only blockchain endpoints.

All information exposed here is already anchored on the public Indy
ledger (schemas, credential definitions, issuer DID), so no
authentication is required.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from blockchain import LedgerRepository, get_ledger_repository
from portal.blockchain_views import build_registry_view
from portal.schemas import BlockchainRegistryResponse

blockchain_public_router = APIRouter(
    prefix="/public/blockchain", tags=["Public Blockchain"]
)


@blockchain_public_router.get(
    "/registry",
    response_model=BlockchainRegistryResponse,
)
def public_registry(
    repository: LedgerRepository = Depends(get_ledger_repository),
) -> BlockchainRegistryResponse:
    """Return the institutional AnonCreds registry as seen by verifiers."""
    return build_registry_view(repository=repository)
