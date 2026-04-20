import os
import time
import hashlib
import json
from decimal import Decimal
from typing import Optional
import asyncio
from web3 import Web3
from web3.middleware import ExtraDataToPOAMiddleware
from eth_account import Account
import structlog

logger = structlog.get_logger()
class BesuWeb3Client:
    """
    Cliente Web3 asíncrono-seguro para Hyperledger Besu.
    Maneja despliegue de contratos y anclaje de firmas.
    """
    def __init__(self):
        self.rpc_url = os.getenv("BESU_RPC_URL", "http://besu-node:8545")
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        
        # Hyperledger Besu (y la red dev de POA/Clique) requiere este middleware extra para leer los logs
        if self.w3.is_connected():
            self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
            logger.info("✅ Conectado al nodo Besu EVM en modo Dev")
        else:
            logger.warning("⏳ Nodo Besu EVM aun no disponible. Reintentara al primer anclaje.")
            
        self.contract_address = None
        self.contract_abi = None
        self.admin_account = None

        # Al usar modo Dev, Besu inyecta esta clave pre-cargada con Ether infinito (miner account)
        self.dev_private_key = "0x8f2a55949038a9610f50fb23b5883af3b4ca139ced43cb39566270e5b8d5a16d" # Default Dev Miner Key in Besu

    def _ensure_connection(self):
        if not self.w3.is_connected():
            self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            self.w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
            
        if not self.admin_account:
            try:
                self.admin_account = Account.from_key(self.dev_private_key)
                self.w3.eth.default_account = self.admin_account.address
            except Exception as e:
                logger.error(f"❌ Error importando clave Dev de Besu: {e}")

    def deploy_contract_if_needed(self):
        """Compila y despliega el contrato si no existe"""
        self._ensure_connection()
        if self.contract_address:
            return

        try:
            logger.info("⚙️ Cargando contrato CredentialRegistry.sol (Besu EVM)...")
            
            # Leer el archivo JSON pre-compilado (Ruta relativa desde controller)
            contract_path = os.path.join(os.path.dirname(__file__), "../../contracts/CredentialRegistry.json")
            with open(contract_path, "r") as f:
                contract_data = json.load(f)

            bytecode = contract_data["bytecode"]
            self.contract_abi = contract_data["abi"]

            RegistryContract = self.w3.eth.contract(abi=self.contract_abi, bytecode=bytecode)
            
            logger.info("🚀 Desplegando Contrato Notarial en la red Besu Dev...")
            
            # Construir Tx
            nonce = self.w3.eth.get_transaction_count(self.admin_account.address)
            tx = RegistryContract.constructor().build_transaction({
                "chainId": self.w3.eth.chain_id,
                "gasPrice": self.w3.eth.gas_price,
                "from": self.admin_account.address,
                "nonce": nonce,
            })

            # Firmar y Enviar
            signed_tx = self.w3.eth.account.sign_transaction(tx, private_key=self.dev_private_key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            self.contract_address = tx_receipt.contractAddress
            
            logger.info(f"✅ Contrato desplegado en: {self.contract_address}")
        except Exception as e:
            logger.error(f"❌ Fallo al inicializar/desplegar contrato en Besu: {e}")

    async def anchor_credential_hash(self, credential_jwt: str, course_name: str) -> Optional[str]:
        """
        Hashea localmente el JWT emitido y ancla el SHA-256 en Blockchain.
        Retorna el Hash de la Transacción en la Blockchain.
        """
        try:
            self._ensure_connection()
            if not self.contract_address:
                self.deploy_contract_if_needed()

            if not self.contract_address:
                logger.error("❌ No se puede anclar: Smart Contract no fue desplegado correctemente")
                return None

            # Calcular SHA-256 del certificado original
            hasher = hashlib.sha256()
            hasher.update(credential_jwt.encode('utf-8'))
            cred_hash_bytes32 = hasher.digest()  # Devuelve raw bytes que cuadran con solidity bytes32

            hex_hash = cred_hash_bytes32.hex()
            logger.info(f"🔗 Calculado SHA-256 localmente: 0x{hex_hash}")

            contract = self.w3.eth.contract(address=self.contract_address, abi=self.contract_abi)

            # Verificar si ya existe para no gastar gas
            is_valid = contract.functions.isValid(cred_hash_bytes32).call()
            if is_valid:
                logger.warning(f"⚠️ El JWT ya se encontraba anclado en la Blockchain como válido.")
                return None

            nonce = self.w3.eth.get_transaction_count(self.admin_account.address)
            
            logger.info("⚡ Construyendo Transacción Blockchain hacia Besu Node...")
            # Preparar transacción asíncrona hacia EVM
            tx = contract.functions.issueCredential(
                cred_hash_bytes32, 
                course_name
            ).build_transaction({
                "chainId": self.w3.eth.chain_id,
                "gasPrice": self.w3.eth.gas_price,
                "gas": 3000000, 
                "from": self.admin_account.address,
                "nonce": nonce,
            })

            signed_tx = self.w3.eth.account.sign_transaction(tx, private_key=self.dev_private_key)
            
            # Ejecutar transacción enviándola a Besu RPC
            tx_hash_bytes = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            tx_hash = self.w3.to_hex(tx_hash_bytes)
            
            logger.info(f"🪙 Tx enviada! Block Explorer Hash: {tx_hash}")
            return tx_hash

        except Exception as e:
            logger.error(f"❌ Error grave conectando a Besu u operando en Blockchain: {e}")
            import traceback
            traceback.print_exc()
            return None

besu_client = BesuWeb3Client()
