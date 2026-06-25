"""Administrative blockchain endpoints.

These endpoints require the ``ADMIN_BOOTSTRAP_TOKEN`` for authentication
and provide operational visibility into the Besu deployment.
"""
import os

from fastapi import APIRouter, Depends

from blockchain import LedgerClient, get_ledger_client
from blockchain.web3_client import besu_client

admin_router = APIRouter(prefix="/admin/blockchain", tags=["Admin · Blockchain"])


@admin_router.post("/bootstrap")
async def bootstrap_blockchain(
    ledger: LedgerClient = Depends(get_ledger_client),
):
    """Ensure the CredentialRegistry contract is deployed on Besu.

    This is an idempotent operation: if the contract is already deployed,
    it returns the existing address without redeploying.
    """
    deployed = besu_client.deploy_contract_if_needed()

    status = await ledger.get_status()

    return {
        "success": deployed,
        "network": status.name,
        "issuer_did": status.issuer_did,
        "contract_address": besu_client.contract_address,
        "explorer_url": os.getenv("BLOCKCHAIN_EXPLORER_URL", ""),
    }


@admin_router.get("/status")
async def blockchain_status(
    ledger: LedgerClient = Depends(get_ledger_client),
):
    """Return the operational status of the Besu blockchain layer."""
    status = await ledger.get_status()

    return {
        "network": status.name,
        "health": status.health.value,
        "issuer_did": status.issuer_did,
        "contract_address": besu_client.contract_address,
        "explorer_url": status.explorer_url,
    }
