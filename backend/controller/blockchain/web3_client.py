"""Hyperledger Besu Web3 Client — Smart Contract Layer.

Manages the lifecycle of the ``CredentialRegistry`` smart contract
and anchors credential hashes on-chain.

Architecture:
    - Designed for Besu's ``--network=dev`` mode (PoW with auto-mining).
    - Uses the official Besu dev pre-funded account for gas fees.
    - Contract address is **persisted** in ``portal_ledger_artifacts``
      so existing anchors survive backend restarts.
    - Contract is deployed lazily on first anchor request only when
      no persisted address is found or the on-chain code is gone.
    - After a fresh deploy, the contract is automatically verified in
      Blockscout so that transaction inputs are decoded for explorers.
"""
import json
import os
import threading
import time
from typing import Optional

import structlog
from eth_account import Account
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware

logger = structlog.get_logger()

# Official Hyperledger Besu Dev Network pre-funded account.
# This key is PUBLIC by design — it controls test ETH only on isolated
# dev networks. Never use on mainnet. See:
# https://besu.hyperledger.org/private-networks/reference/accounts-for-testing
BESU_DEV_PRIVATE_KEY = (
    "0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63"
)
BESU_DEV_ADDRESS = "0xfe3b557e8fb62b89f4916b721be55ceb828dbd73"

# Gas ceilings for deployment and anchoring transactions.
DEPLOY_GAS_LIMIT = 5_000_000
ANCHOR_GAS_LIMIT = 3_000_000

# Connection retry settings.
MAX_CONNECTION_RETRIES = 3
RETRY_DELAY_SECONDS = 2

# Tag used to identify the CredentialRegistry contract in the DB.
_CONTRACT_TAG = "credential_registry"


class BesuWeb3Client:
    """Production-grade Web3 client for Hyperledger Besu.

    Responsibilities:
      - Lazy deployment of the CredentialRegistry smart contract
      - Persistent storage of the contract address across restarts
      - On-chain anchoring of pre-computed credential hashes
      - Resilient connection handling with automatic retries
    """

    def __init__(self):
        self.rpc_url = os.getenv("BESU_RPC_URL", "http://besu-node:8545")
        self.w3: Optional[Web3] = None
        self.contract_address: Optional[str] = None
        self.contract_abi: Optional[list] = None
        self.admin_account: Optional[Account] = None

    # -----------------------------------------------------------------
    # Connection Management
    # -----------------------------------------------------------------

    def _ensure_connection(self) -> bool:
        """Establish or verify the Web3 connection to the Besu RPC node.

        Returns True if connected and ready, False otherwise.
        """
        # Fast path: already connected
        if self.w3 and self.w3.is_connected() and self.admin_account:
            return True

        for attempt in range(1, MAX_CONNECTION_RETRIES + 1):
            try:
                self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))

                if not self.w3.is_connected():
                    logger.warning(
                        f"⏳ Besu RPC no disponible (intento {attempt}/{MAX_CONNECTION_RETRIES})"
                    )
                    time.sleep(RETRY_DELAY_SECONDS)
                    continue

                # Besu dev mode (Ethash/Clique) requires POA middleware
                # to correctly parse block headers with non-standard extraData.
                self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

                # Initialize the pre-funded dev account.
                self.admin_account = Account.from_key(BESU_DEV_PRIVATE_KEY)
                self.w3.eth.default_account = self.admin_account.address

                # Validate on-chain balance as a sanity check.
                balance_wei = self.w3.eth.get_balance(self.admin_account.address)
                balance_eth = self.w3.from_wei(balance_wei, "ether")
                logger.info(f"✅ Conectado a Besu Dev | Saldo: {balance_eth} ETH")

                if balance_eth == 0:
                    logger.error(
                        "❌ CRÍTICO: Cuenta Dev con 0 ETH. "
                        "El volumen 'besu_data' puede estar corrupto."
                    )
                    return False

                return True

            except Exception as e:
                logger.error(f"❌ Error conectando a Besu (intento {attempt}): {e}")
                time.sleep(RETRY_DELAY_SECONDS)

        logger.error("❌ No se pudo conectar a Besu después de todos los reintentos.")
        return False

    # -----------------------------------------------------------------
    # Contract ABI Loader
    # -----------------------------------------------------------------

    def _load_contract_abi(self) -> None:
        """Load the pre-compiled ABI from the contract artifact JSON.

        Called once — the ABI is cached for the process lifetime.
        """
        if self.contract_abi:
            return

        contract_path = "/contracts/CredentialRegistry.json"
        if not os.path.exists(contract_path):
            contract_path = os.path.join(
                os.path.dirname(__file__),
                "../../contracts/CredentialRegistry.json",
            )
        with open(contract_path, "r") as f:
            contract_data = json.load(f)

        self.contract_abi = contract_data["abi"]

    # -----------------------------------------------------------------
    # Contract Persistence
    # -----------------------------------------------------------------

    def _load_persisted_address(self) -> Optional[str]:
        """Attempt to load a previously deployed contract address from the DB."""
        try:
            from portal.database import PortalSessionLocal
            from portal.models import LedgerArtifact

            db = PortalSessionLocal()
            try:
                row = (
                    db.query(LedgerArtifact)
                    .filter(
                        LedgerArtifact.kind == "contract",
                        LedgerArtifact.tag == _CONTRACT_TAG,
                    )
                    .order_by(LedgerArtifact.created_at.desc())
                    .first()
                )
                return row.artifact_id if row else None
            finally:
                db.close()
        except Exception as e:
            logger.warning(f"⚠️ No se pudo cargar contract address de la DB: {e}")
            return None

    def _persist_address(self, address: str) -> None:
        """Store the deployed contract address in the DB for future restarts."""
        try:
            from portal.database import PortalSessionLocal
            from portal.models import LedgerArtifact

            db = PortalSessionLocal()
            try:
                artifact = LedgerArtifact(
                    kind="contract",
                    artifact_id=address,
                    name="CredentialRegistry",
                    tag=_CONTRACT_TAG,
                    issuer_did=(
                        f"did:ethr:{self.admin_account.address}"
                        if self.admin_account
                        else None
                    ),
                )
                db.add(artifact)
                db.commit()
                logger.info(f"💾 Contract address persistida en DB: {address}")
            finally:
                db.close()
        except Exception as e:
            logger.warning(f"⚠️ No se pudo persistir contract address: {e}")

    # -----------------------------------------------------------------
    # Smart Contract Deployment
    # -----------------------------------------------------------------

    def deploy_contract_if_needed(self) -> bool:
        """Deploy the CredentialRegistry contract if not already deployed.

        Resolution order:
          1. In-memory cache (``self.contract_address``)
          2. Persisted address in ``portal_ledger_artifacts``
          3. Fresh deployment

        Returns True if the contract is ready to use, False otherwise.
        """
        if self.contract_address:
            return True

        if not self._ensure_connection():
            return False

        self._load_contract_abi()

        # Step 1: Try to load a persisted address.
        persisted = self._load_persisted_address()
        if persisted:
            # Verify the contract code still exists on-chain (guard against
            # chain resets or volume wipes).
            try:
                code = self.w3.eth.get_code(persisted)
                if code and code != b"" and code != b"0x":
                    self.contract_address = persisted
                    logger.info(
                        f"✅ Contrato recuperado de DB: {self.contract_address}"
                    )
                    # Ensure contract is verified in Blockscout even if
                    # Blockscout was reset while the blockchain persisted.
                    self._ensure_blockscout_verified(self.contract_address)
                    return True
                else:
                    logger.warning(
                        f"⚠️ Contrato {persisted} ya no existe on-chain. "
                        "Re-desplegando..."
                    )
            except Exception as e:
                logger.warning(f"⚠️ Error verificando contrato persistido: {e}")

        # Step 2: Fresh deployment.
        try:
            logger.info("⚙️ Cargando contrato CredentialRegistry.sol (Besu EVM)...")

            contract_path = "/contracts/CredentialRegistry.json"
            if not os.path.exists(contract_path):
                contract_path = os.path.join(
                    os.path.dirname(__file__),
                    "../../contracts/CredentialRegistry.json",
                )
            with open(contract_path, "r") as f:
                contract_data = json.load(f)

            bytecode = contract_data["bytecode"]
            registry = self.w3.eth.contract(
                abi=self.contract_abi, bytecode=bytecode
            )

            logger.info("🚀 Desplegando Contrato Notarial en la red Besu Dev...")

            nonce = self.w3.eth.get_transaction_count(self.admin_account.address)
            tx = registry.constructor().build_transaction(
                {
                    "chainId": self.w3.eth.chain_id,
                    "gasPrice": self.w3.eth.gas_price,
                    "gas": DEPLOY_GAS_LIMIT,
                    "from": self.admin_account.address,
                    "nonce": nonce,
                }
            )

            signed_tx = self.w3.eth.account.sign_transaction(
                tx, private_key=BESU_DEV_PRIVATE_KEY
            )
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)

            self.contract_address = tx_receipt.contractAddress
            logger.info(f"✅ Contrato desplegado en: {self.contract_address}")

            # Persist for future restarts.
            self._persist_address(self.contract_address)

            # Auto-verify in Blockscout (fire-and-forget, non-blocking).
            self._verify_in_blockscout(self.contract_address)

            return True

        except Exception as e:
            logger.error(f"❌ Fallo al desplegar contrato en Besu: {e}")
            return False

    # -----------------------------------------------------------------
    # Blockscout Contract Verification
    # -----------------------------------------------------------------

    _BLOCKSCOUT_BASE_URL = os.getenv(
        "BLOCKSCOUT_API_URL", "http://blockscout-backend:4000"
    ).rstrip("/")

    def _ensure_blockscout_verified(self, address: str) -> None:
        """Check if the contract is already verified in Blockscout.

        If not verified, triggers background verification.  This is called
        on every contract recovery from the DB, but the actual verification
        POST only fires when the ABI is missing from Blockscout
        (e.g., after a Blockscout DB reset).
        """
        def _check_and_verify():
            try:
                import requests

                url = (
                    f"{self._BLOCKSCOUT_BASE_URL}"
                    f"/api/v2/smart-contracts/{address}"
                )
                resp = requests.get(url, timeout=10)

                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("is_verified"):
                        logger.info(
                            f"✅ Contrato ya verificado en Blockscout: "
                            f"{address}"
                        )
                        return

                logger.info(
                    "🔍 Contrato no verificado en Blockscout — "
                    "verificando..."
                )
                self._submit_verification(address)

            except Exception as exc:
                logger.warning(
                    f"⚠️ No se pudo consultar Blockscout "
                    f"(verificación): {exc}"
                )

        thread = threading.Thread(target=_check_and_verify, daemon=True)
        thread.start()

    def _verify_in_blockscout(self, address: str) -> None:
        """Submit contract verification after a fresh deploy.

        Runs in a background thread with a short delay to give Blockscout
        time to index the deploy transaction.
        """
        def _delayed_verify():
            time.sleep(5)
            self._submit_verification(address)

        thread = threading.Thread(target=_delayed_verify, daemon=True)
        thread.start()

    def _submit_verification(self, address: str) -> None:
        """POST the contract source to Blockscout's V2 verification API.

        Uses the ``/api/v2/smart-contracts/{address}/verification/via/
        flattened-code`` endpoint, which is the standard in modern
        Blockscout versions.  Once verified, the explorer automatically
        decodes transaction inputs, events, and exposes Read/Write
        Contract UIs.

        This is a synchronous helper — callers are responsible for
        running it in a thread if non-blocking behaviour is required.
        """
        try:
            import requests

            # Read Solidity source from the same path the deployer uses.
            source_path = "/contracts/CredentialRegistry.sol"
            if not os.path.exists(source_path):
                source_path = os.path.join(
                    os.path.dirname(__file__),
                    "../../contracts/CredentialRegistry.sol",
                )
            with open(source_path, "r") as f:
                source_code = f.read()

            # Compiler version must match the one used in compile.py.
            compiler_version = os.getenv(
                "SOLC_VERSION", "v0.8.0+commit.c7dfd78e"
            )

            url = (
                f"{self._BLOCKSCOUT_BASE_URL}"
                f"/api/v2/smart-contracts/{address}"
                f"/verification/via/flattened-code"
            )

            payload = {
                "compiler_version": compiler_version,
                "source_code": source_code,
                "is_optimization_enabled": False,
                "optimization_runs": 200,
                "contract_name": "CredentialRegistry",
                "evm_version": "default",
                "autodetect_constructor_args": True,
            }

            resp = requests.post(url, json=payload, timeout=30)

            if resp.status_code == 200:
                result = resp.json()
                msg = result.get("message", "")
                if "started" in msg.lower() or result.get("is_verified"):
                    logger.info(
                        f"✅ Contrato verificado en Blockscout: {address}"
                    )
                else:
                    logger.warning(
                        f"⚠️ Blockscout verificación respuesta: {msg}"
                    )
            else:
                logger.warning(
                    f"⚠️ Blockscout verificación HTTP {resp.status_code}: "
                    f"{resp.text[:200]}"
                )
        except Exception as exc:
            logger.warning(
                f"⚠️ No se pudo verificar contrato en Blockscout: {exc}"
            )

    # -----------------------------------------------------------------
    # Credential Anchoring
    # -----------------------------------------------------------------

    async def anchor_credential_hash(
        self, credential_hash_hex: str, course_name: str
    ) -> Optional[str]:
        """Anchor a pre-computed credential hash on-chain.

        The ``credential_hash_hex`` is the canonical SHA-256 digest computed
        by ``utils.hashing.compute_credential_hash``.  This is the **same**
        hash displayed in the student portal and verified publicly, ensuring
        a single cryptographic identity across all layers.

        Args:
            credential_hash_hex: 64-char hex string (SHA-256 digest).
            course_name: Human-readable course label stored on-chain alongside
                the hash for explorer readability.

        Returns:
            The Ethereum transaction hash on success, ``None`` on failure.
        """
        try:
            if not self.deploy_contract_if_needed():
                logger.error("❌ No se puede anclar: Smart Contract no disponible")
                return None

            # Convert the hex string to bytes32 for the Solidity function.
            cred_hash_bytes = bytes.fromhex(credential_hash_hex)
            logger.info(f"🔗 Portal Hash (SHA-256): 0x{credential_hash_hex}")

            contract = self.w3.eth.contract(
                address=self.contract_address, abi=self.contract_abi
            )

            # Check idempotency — skip if already anchored.
            if contract.functions.isValid(cred_hash_bytes).call():
                logger.warning("⚠️ Credencial ya anclada en la Blockchain.")
                return None

            nonce = self.w3.eth.get_transaction_count(self.admin_account.address)

            logger.info("⚡ Construyendo Transacción Blockchain hacia Besu Node...")
            tx = contract.functions.issueCredential(
                cred_hash_bytes, course_name
            ).build_transaction(
                {
                    "chainId": self.w3.eth.chain_id,
                    "gasPrice": self.w3.eth.gas_price,
                    "gas": ANCHOR_GAS_LIMIT,
                    "from": self.admin_account.address,
                    "nonce": nonce,
                }
            )

            signed_tx = self.w3.eth.account.sign_transaction(
                tx, private_key=BESU_DEV_PRIVATE_KEY
            )
            tx_hash_bytes = self.w3.eth.send_raw_transaction(
                signed_tx.raw_transaction
            )
            tx_hash = self.w3.to_hex(tx_hash_bytes)

            logger.info(f"🪙 Tx enviada! Block Explorer Hash: {tx_hash}")
            return tx_hash

        except Exception as e:
            logger.error(f"❌ Error en operación Blockchain: {e}")
            import traceback

            traceback.print_exc()
            return None

    # -----------------------------------------------------------------
    # Credential Revocation
    # -----------------------------------------------------------------

    async def revoke_credential_hash(
        self, credential_hash_hex: str
    ) -> Optional[str]:
        """Revoke a credential hash on-chain.

        Calls ``revokeCredential(bytes32)`` on the ``CredentialRegistry``
        contract, transitioning the credential state from ``Valid`` to
        ``Revoked``.  The smart contract enforces that only the owner
        (university issuer) can revoke, and that the credential must
        currently be in ``Valid`` state.

        Args:
            credential_hash_hex: 64-char hex string (SHA-256 digest).

        Returns:
            The Ethereum transaction hash on success, ``None`` on failure.
        """
        try:
            if not self.deploy_contract_if_needed():
                logger.error(
                    "❌ No se puede revocar: Smart Contract no disponible"
                )
                return None

            cred_hash_bytes = bytes.fromhex(credential_hash_hex)

            contract = self.w3.eth.contract(
                address=self.contract_address, abi=self.contract_abi
            )

            # Verify the credential is currently Valid before sending the TX.
            if not contract.functions.isValid(cred_hash_bytes).call():
                logger.warning(
                    "⚠️ Credencial no está en estado Valid — "
                    "no se puede revocar"
                )
                return None

            nonce = self.w3.eth.get_transaction_count(
                self.admin_account.address
            )

            logger.info(
                f"🔴 Revocando credencial on-chain: 0x{credential_hash_hex}"
            )
            tx = contract.functions.revokeCredential(
                cred_hash_bytes
            ).build_transaction(
                {
                    "chainId": self.w3.eth.chain_id,
                    "gasPrice": self.w3.eth.gas_price,
                    "gas": ANCHOR_GAS_LIMIT,
                    "from": self.admin_account.address,
                    "nonce": nonce,
                }
            )

            signed_tx = self.w3.eth.account.sign_transaction(
                tx, private_key=BESU_DEV_PRIVATE_KEY
            )
            tx_hash_bytes = self.w3.eth.send_raw_transaction(
                signed_tx.raw_transaction
            )
            tx_hash = self.w3.to_hex(tx_hash_bytes)

            logger.info(
                f"🔴 Credencial revocada on-chain — TX: {tx_hash}"
            )
            return tx_hash

        except Exception as e:
            logger.error(f"❌ Error al revocar credencial on-chain: {e}")
            import traceback

            traceback.print_exc()
            return None


# Singleton instance — shared across the application lifecycle.
besu_client = BesuWeb3Client()
