"""Configuration for the blockchain subsystem.

All values come from environment variables so the configuration surface
is declarative and twelve-factor friendly. Defaults make sense for the
reference VON Network deployment documented in ``backend/README.md``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Tuple


# Canonical credential schema attributes.
#
# Order is significant for ACA-Py's AnonCreds registration. Adding or
# removing an attribute is a breaking change: it requires a new schema
# version (bump ``BLOCKCHAIN_SCHEMA_VERSION``) and a fresh credential
# definition. Keep the list in sync with the credential formatter in
# ``openid4vc/credential_formatters.py`` when Fase 2 lands.
DEFAULT_SCHEMA_ATTRIBUTES: Tuple[str, ...] = (
    "student_id",
    "student_name",
    "student_email",
    "course_id",
    "course_name",
    "completion_date",
    "grade",
    "instructor_name",
    "university_name",
    "issue_date",
    "credential_hash",
)


# Valid values accepted by ACA-Py for the rev_reg_def ``issuance_type``.
ISSUANCE_ON_DEMAND = "ISSUANCE_ON_DEMAND"
ISSUANCE_BY_DEFAULT = "ISSUANCE_BY_DEFAULT"
_VALID_ISSUANCE_TYPES = frozenset({ISSUANCE_ON_DEMAND, ISSUANCE_BY_DEFAULT})


@dataclass(frozen=True)
class BlockchainSettings:
    """Static configuration for the blockchain subsystem."""

    driver: str
    acapy_admin_url: str
    network_name: str
    explorer_url: str
    schema_name: str
    schema_version: str
    cred_def_tag: str
    supports_revocation: bool
    rev_reg_max_cred_num: int
    rev_reg_issuance_type: str
    tails_server_url: str
    admin_bootstrap_token: str
    schema_attributes: Tuple[str, ...] = DEFAULT_SCHEMA_ATTRIBUTES


def _as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: str, *, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_issuance_type(value: str) -> str:
    """Coerce ``value`` to a supported issuance type, defaulting safely."""
    candidate = (value or "").strip().upper()
    if candidate in _VALID_ISSUANCE_TYPES:
        return candidate
    return ISSUANCE_ON_DEMAND


def get_settings() -> BlockchainSettings:
    """Load blockchain settings from the environment.

    Returns a frozen :class:`BlockchainSettings` instance. The function
    is intentionally not cached so tests and CLI scripts can mutate the
    environment before invoking it.
    """
    return BlockchainSettings(
        driver=os.getenv("BLOCKCHAIN_DRIVER", "indy").strip().lower(),
        acapy_admin_url=os.getenv("ACAPY_ADMIN_URL", "http://acapy-agent:8020"),
        network_name=os.getenv(
            "BLOCKCHAIN_NETWORK_NAME", "VON Network (Hyperledger Indy)"
        ),
        explorer_url=os.getenv(
            "BLOCKCHAIN_EXPLORER_URL", "https://ledger.utnpf.site"
        ),
        schema_name=os.getenv("BLOCKCHAIN_SCHEMA_NAME", "UniversityDegree"),
        schema_version=os.getenv("BLOCKCHAIN_SCHEMA_VERSION", "1.0"),
        cred_def_tag=os.getenv("BLOCKCHAIN_CRED_DEF_TAG", "default"),
        supports_revocation=_as_bool(
            os.getenv("BLOCKCHAIN_SUPPORT_REVOCATION", "false")
        ),
        rev_reg_max_cred_num=_as_int(
            os.getenv("BLOCKCHAIN_REV_REG_MAX_CRED_NUM", "1000"), default=1000
        ),
        rev_reg_issuance_type=_normalize_issuance_type(
            os.getenv("BLOCKCHAIN_REV_REG_ISSUANCE_TYPE", ISSUANCE_ON_DEMAND)
        ),
        tails_server_url=os.getenv("TAILS_SERVER_URL", "").rstrip("/"),
        admin_bootstrap_token=os.getenv("ADMIN_BOOTSTRAP_TOKEN", ""),
    )
