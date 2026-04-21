import os
import time
import hashlib
import json
from typing import Optional
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
from eth_account import Account
import structlog

logger = structlog.get_logger()

# =====================================================================
# Hyperledger Besu Client (EVM Smart Contract Layer)
# =====================================================================
# This module manages the lifecycle of the CredentialRegistry smart
# contract and anchors credential hashes on-chain.
#
# Architecture notes:
#   - Designed for Besu's `--network=dev` mode (PoW with auto-mining)
#   - Uses the official Besu dev pre-funded account for gas fees
#   - Contract is deployed lazily on first credential anchor request
#   - Contract address is cached in-memory for the process lifetime
# =====================================================================

# Official Hyperledger Besu Dev Network pre-funded account.
# This key is PUBLIC by design — it controls test ETH only on isolated
# dev networks. Never use on mainnet. See:
# https://besu.hyperledger.org/private-networks/reference/accounts-for-testing
BESU_DEV_PRIVATE_KEY = "0x8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63"
BESU_DEV_ADDRESS = "0xfe3b557e8fb62b89f4916b721be55ceb828dbd73"

# Deployment gas ceiling — generous enough for CredentialRegistry
# while preventing runaway estimations on fresh networks.
DEPLOY_GAS_LIMIT = 5_000_000
ANCHOR_GAS_LIMIT = 3_000_000

# Connection retry settings
MAX_CONNECTION_RETRIES = 3
RETRY_DELAY_SECONDS = 2


class BesuWeb3Client:
    """
    Production-grade Web3 client for Hyperledger Besu.

    Responsibilities:
      - Lazy deployment of the CredentialRegistry smart contract
      - SHA-256 hashing and on-chain anchoring of issued credentials
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
        """
        Establish or verify the Web3 connection to the Besu RPC node.
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
                # to correctly parse block headers with non-standard extraData
                self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

                # Initialize the pre-funded dev account
                self.admin_account = Account.from_key(BESU_DEV_PRIVATE_KEY)
                self.w3.eth.default_account = self.admin_account.address

                # Validate on-chain balance as a sanity check
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
    # Smart Contract Deployment
    # -----------------------------------------------------------------

    def deploy_contract_if_needed(self) -> bool:
        """
        Deploy the CredentialRegistry contract if not already deployed.
        Returns True if contract is ready to use, False otherwise.
        """
        if self.contract_address:
            return True

        if not self._ensure_connection():
            return False

        try:
            logger.info("⚙️ Cargando contrato CredentialRegistry.sol (Besu EVM)...")

            # Load pre-compiled contract artifacts (ABI + bytecode).
            # In Docker the artifacts live at /contracts/ (see Dockerfile),
            # locally they are at ../../contracts/ relative to this file.
            contract_path = "/contracts/CredentialRegistry.json"
            if not os.path.exists(contract_path):
                contract_path = os.path.join(
                    os.path.dirname(__file__),
                    "../../contracts/CredentialRegistry.json",
                )
            with open(contract_path, "r") as f:
                contract_data = json.load(f)

            bytecode = contract_data["bytecode"]
            self.contract_abi = contract_data["abi"]

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
            return True

        except Exception as e:
            logger.error(f"❌ Fallo al desplegar contrato en Besu: {e}")
            return False

    # -----------------------------------------------------------------
    # Credential Anchoring
    # -----------------------------------------------------------------

    async def anchor_credential_hash(
        self, credential_jwt: str, course_name: str
    ) -> Optional[str]:
        """
        Hash the issued JWT credential (SHA-256) and anchor the digest
        on-chain via the CredentialRegistry smart contract.

        Returns the transaction hash on success, None on failure.
        """
        try:
            if not self.deploy_contract_if_needed():
                logger.error("❌ No se puede anclar: Smart Contract no disponible")
                return None

            # Compute SHA-256 digest → Solidity bytes32
            cred_hash = hashlib.sha256(credential_jwt.encode("utf-8")).digest()
            logger.info(f"🔗 SHA-256 calculado: 0x{cred_hash.hex()}")

            contract = self.w3.eth.contract(
                address=self.contract_address, abi=self.contract_abi
            )

            # Check idempotency — skip if already anchored
            if contract.functions.isValid(cred_hash).call():
                logger.warning("⚠️ Credencial ya anclada en la Blockchain.")
                return None

            nonce = self.w3.eth.get_transaction_count(self.admin_account.address)

            logger.info("⚡ Construyendo Transacción Blockchain hacia Besu Node...")
            tx = contract.functions.issueCredential(
                cred_hash, course_name
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


# Singleton instance — shared across the application lifecycle
besu_client = BesuWeb3Client()
