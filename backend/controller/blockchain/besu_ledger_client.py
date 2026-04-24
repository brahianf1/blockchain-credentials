"""Production ledger client for Hyperledger Besu.

Resolves credential anchors by querying the ``CredentialRegistry`` smart
contract deployed on the Besu network, and constructs Blockscout explorer
URLs for transparent, verifiable on-chain evidence.

The ``txn_id`` is resolved from the ``portal_blockchain_anchors`` table
so the portal can link directly to the exact transaction on Blockscout
where the credential hash was recorded.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional

import structlog

from blockchain.base import (
    AnchorStatus,
    CredentialAnchor,
    LedgerClient,
    LedgerHealth,
    LedgerStatus,
)
from blockchain.web3_client import besu_client

logger = structlog.get_logger()

# Default network label surfaced to API consumers.
_NETWORK_NAME = "UTN Credential Chain (Hyperledger Besu)"

# Base URL for the Blockscout explorer, used to build deep-links.
_EXPLORER_BASE_URL = os.getenv("BLOCKCHAIN_EXPLORER_URL", "").rstrip("/")


def _lookup_txn_id(credential_hash: str) -> tuple[Optional[str], Optional[str]]:
    """Query the portal DB for the persisted transaction hashes.

    Returns a tuple ``(effective_txn_id, issuance_txn_id)`` where:
      - ``effective_txn_id`` is the revocation TX if revoked, otherwise
        the issuance TX — i.e. the TX that defines the current state.
      - ``issuance_txn_id`` is always the original issuance TX hash.

    This ensures the explorer link always points to the transaction
    that proves the credential's **current** on-chain state, following
    the W3C VC Data Model principle that a credential's status must
    be resolvable to its most recent status entry.
    """
    try:
        from portal.database import PortalSessionLocal
        from portal.models import CredentialAnchor as CredentialAnchorModel

        db = PortalSessionLocal()
        try:
            row = (
                db.query(CredentialAnchorModel)
                .filter(CredentialAnchorModel.credential_hash == credential_hash)
                .first()
            )
            if not row:
                return None, None

            # If revoked and we have the revocation TX, surface that.
            if row.revoked and row.revocation_txn_id:
                return row.revocation_txn_id, row.txn_id

            return row.txn_id, row.txn_id
        finally:
            db.close()
    except Exception as e:
        logger.warning(
            "⚠️ _lookup_txn_id error",
            credential_hash=credential_hash[:16],
            error=str(e),
        )
        return None, None


class BesuLedgerClient(LedgerClient):
    """Real ledger client backed by a Hyperledger Besu node.

    Responsibilities:
      - Health checking the Besu RPC connection
      - Querying the ``CredentialRegistry`` smart contract for credential
        state (Valid / Revoked / NotIssued)
      - Resolving the persisted ``txn_id`` for direct Blockscout links
      - Building Blockscout explorer URLs for each transaction
    """

    # -- LedgerClient interface ----------------------------------------

    async def get_status(self) -> LedgerStatus:
        """Return the operational status of the Besu network."""
        connected = besu_client._ensure_connection()
        if not connected:
            return LedgerStatus(
                name=_NETWORK_NAME,
                health=LedgerHealth.UNAVAILABLE,
            )

        explorer = _EXPLORER_BASE_URL or None
        issuer_did = None
        if besu_client.admin_account:
            issuer_did = f"did:ethr:{besu_client.admin_account.address}"

        return LedgerStatus(
            name=_NETWORK_NAME,
            health=LedgerHealth.HEALTHY,
            issuer_did=issuer_did,
            explorer_url=explorer,
        )

    async def resolve_anchor(
        self, credential_hash: str
    ) -> Optional[CredentialAnchor]:
        """Resolve a credential hash against the on-chain registry.

        Calls the ``credentials(bytes32)`` view function on the deployed
        ``CredentialRegistry`` contract.  This is a gas-free read-only
        call that returns the ``RegistryEntry`` struct:

            struct RegistryEntry {
                CredentialState state;  // 0=NotIssued, 1=Valid, 2=Revoked
                uint256 timestamp;
                string courseName;
            }

        Additionally resolves the ``txn_id`` from the portal database to
        build a direct Blockscout transaction link.

        Returns ``None`` when the credential is not present on-chain.
        """
        if not besu_client.deploy_contract_if_needed():
            logger.warning("⚠️ BesuLedgerClient: contrato no disponible")
            return CredentialAnchor.unavailable(_NETWORK_NAME)

        try:
            # Normalize the hash to bytes32.
            hash_hex = credential_hash
            if hash_hex.startswith("0x"):
                hash_hex = hash_hex[2:]
            cred_hash_bytes = bytes.fromhex(hash_hex)

            contract = besu_client.w3.eth.contract(
                address=besu_client.contract_address,
                abi=besu_client.contract_abi,
            )

            # Read the full RegistryEntry struct from the mapping.
            entry = contract.functions.credentials(cred_hash_bytes).call()
            state = entry[0]       # CredentialState enum: 0=NotIssued, 1=Valid, 2=Revoked
            timestamp = entry[1]   # uint256 — block.timestamp at issuance/revocation

            # State 0 = NotIssued → credential not found on-chain.
            if state == 0:
                return None

            # Resolve the transaction hash from the portal DB.
            # effective_txn_id is the state-defining TX (revocation if
            # revoked, issuance otherwise).
            effective_txn_id, _issuance_txn_id = _lookup_txn_id(
                credential_hash
            )

            # Build explorer URL: link to the state-defining transaction
            # so the viewer always sees proof of the current state.
            explorer_url = None
            if _EXPLORER_BASE_URL:
                if effective_txn_id:
                    explorer_url = f"{_EXPLORER_BASE_URL}/tx/{effective_txn_id}"
                elif besu_client.contract_address:
                    explorer_url = (
                        f"{_EXPLORER_BASE_URL}/address"
                        f"/{besu_client.contract_address}"
                    )

            # Build issuer DID from the contract owner.
            issuer_did = None
            if besu_client.admin_account:
                issuer_did = f"did:ethr:{besu_client.admin_account.address}"

            # Map Solidity enum to domain AnchorStatus.
            if state == 1:
                anchor_status = AnchorStatus.ANCHORED
            elif state == 2:
                anchor_status = AnchorStatus.REVOKED
            else:
                anchor_status = AnchorStatus.UNAVAILABLE

            # Format the ledger timestamp as ISO 8601.
            ledger_ts = None
            if timestamp > 0:
                ledger_ts = datetime.fromtimestamp(
                    timestamp, tz=timezone.utc
                ).isoformat()

            return CredentialAnchor(
                status=anchor_status,
                network=_NETWORK_NAME,
                issuer_did=issuer_did,
                txn_id=effective_txn_id,
                explorer_url=explorer_url,
                ledger_timestamp=ledger_ts,
            )

        except Exception as e:
            logger.error(
                "❌ BesuLedgerClient.resolve_anchor error",
                credential_hash=credential_hash,
                error=str(e),
            )
            return CredentialAnchor.unavailable(_NETWORK_NAME)
