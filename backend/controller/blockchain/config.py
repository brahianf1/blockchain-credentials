"""Configuration for the blockchain subsystem.

All values come from environment variables so the configuration surface
is declarative and twelve-factor friendly.  Defaults are tuned for the
Hyperledger Besu dev-mode deployment documented in ``backend/README.md``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class BlockchainSettings:
    """Static configuration for the Hyperledger Besu blockchain layer."""

    besu_rpc_url: str
    explorer_base_url: str
    network_name: str
    admin_bootstrap_token: str


def get_settings() -> BlockchainSettings:
    """Load blockchain settings from the environment.

    Returns a frozen :class:`BlockchainSettings` instance.  The function
    is intentionally not cached so tests and CLI scripts can mutate the
    environment before invoking it.
    """
    return BlockchainSettings(
        besu_rpc_url=os.getenv("BESU_RPC_URL", "http://besu-node:8545"),
        explorer_base_url=os.getenv(
            "BLOCKCHAIN_EXPLORER_URL", "https://explorer.utnpf.site"
        ).rstrip("/"),
        network_name=os.getenv(
            "BLOCKCHAIN_NETWORK_NAME",
            "UTN Credential Chain (Hyperledger Besu)",
        ),
        admin_bootstrap_token=os.getenv("ADMIN_BOOTSTRAP_TOKEN", ""),
    )
