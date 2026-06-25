"""Public, read-only blockchain endpoints.

Exposes institutional blockchain configuration and contract metadata
for transparency. No authentication required.
"""
import os

from fastapi import APIRouter, Depends

from blockchain import LedgerClient, get_ledger_client
from blockchain.web3_client import besu_client
from portal.schemas import BlockchainRegistryResponse

blockchain_public_router = APIRouter(
    prefix="/public/blockchain", tags=["Public Blockchain"]
)

_EXPLORER_BASE_URL = os.getenv("BLOCKCHAIN_EXPLORER_URL", "").rstrip("/")


@blockchain_public_router.get(
    "/registry",
    response_model=BlockchainRegistryResponse,
)
async def public_registry(
    ledger: LedgerClient = Depends(get_ledger_client),
) -> dict:
    """Return the institutional blockchain registry as seen by verifiers.

    Provides real-time information about the Besu network status,
    the deployed CredentialRegistry contract address, and a link to
    the Blockscout explorer for independent verification.
    """
    status = await ledger.get_status()

    contract_address = besu_client.contract_address

    return {
        "network": status.name,
        "issuer_did": status.issuer_did,
        "contract_address": contract_address,
        "explorer_url": _EXPLORER_BASE_URL or None,
        "total_anchored_credentials": 0,  # TODO: query contract event count
    }
