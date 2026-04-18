"""ACA-Py admin API wrapper focused on AnonCreds registration.

This module is intentionally thin: it speaks directly to ACA-Py over
HTTP and returns typed dataclasses that the service layer can consume.
No database access, no business rules — just a reliable adapter to a
specific subset of ACA-Py's admin surface.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

import httpx

logger = logging.getLogger(__name__)


# Format expected by Hyperledger Indy:
#   <issuerDID>:3:CL:<schemaSeqNo>:<tag>
_CRED_DEF_SCHEMA_SEQNO_RE = re.compile(r"^[^:]+:3:CL:(\d+):")


class AnonCredsRegistryError(RuntimeError):
    """Raised when ACA-Py returns an unexpected payload or HTTP error."""


@dataclass(frozen=True)
class IssuerIdentity:
    """Public DID of the issuer, as retrieved from ACA-Py's wallet."""

    did: str
    verkey: Optional[str] = None
    endpoint: Optional[str] = None

    @property
    def did_sov(self) -> str:
        return self.did if self.did.startswith("did:") else f"did:sov:{self.did}"


@dataclass(frozen=True)
class SchemaRecord:
    schema_id: str
    name: Optional[str] = None
    version: Optional[str] = None
    attributes: Sequence[str] = field(default_factory=tuple)
    seq_no: Optional[int] = None


@dataclass(frozen=True)
class CredDefRecord:
    cred_def_id: str
    schema_id: Optional[str] = None
    tag: Optional[str] = None
    supports_revocation: bool = False
    schema_seq_no: Optional[int] = None


class AnonCredsRegistry:
    """Adapter that wraps ACA-Py's schema and credential-definition endpoints."""

    DEFAULT_TIMEOUT_SECONDS = 60.0

    def __init__(
        self,
        admin_url: str,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        admin_api_key: Optional[str] = None,
    ) -> None:
        self._admin_url = admin_url.rstrip("/")
        self._timeout = httpx.Timeout(timeout_seconds)
        self._headers = (
            {"X-API-KEY": admin_api_key} if admin_api_key else {}
        )

    # ------------------------------------------------------------------
    # Issuer identity
    # ------------------------------------------------------------------
    async def get_issuer(self) -> IssuerIdentity:
        """Return the public DID currently posted by the ACA-Py wallet."""
        data = await self._get("/wallet/did/public")
        result = (data or {}).get("result") or {}
        did = result.get("did")
        if not did:
            raise AnonCredsRegistryError(
                "ACA-Py did not return a public DID; ensure the wallet is provisioned"
            )
        return IssuerIdentity(
            did=did,
            verkey=result.get("verkey"),
            endpoint=(result.get("metadata") or {}).get("endpoint"),
        )

    # ------------------------------------------------------------------
    # Schemas
    # ------------------------------------------------------------------
    async def list_created_schema_ids(self) -> List[str]:
        """Return schema ids already created by this agent."""
        data = await self._get("/schemas/created")
        return list((data or {}).get("schema_ids") or [])

    async def get_schema(self, schema_id: str) -> Optional[SchemaRecord]:
        """Return a schema by id, or ``None`` when the ledger lookup fails."""
        data = await self._get(f"/schemas/{schema_id}", expected_status=(200, 404))
        if not data:
            return None
        schema = (data or {}).get("schema") or {}
        return SchemaRecord(
            schema_id=schema_id,
            name=schema.get("name"),
            version=schema.get("version"),
            attributes=tuple(schema.get("attrNames") or []),
            seq_no=schema.get("seqNo"),
        )

    async def find_schema(
        self,
        *,
        issuer_did: str,
        name: str,
        version: str,
    ) -> Optional[SchemaRecord]:
        """Return the first schema owned by ``issuer_did`` matching name/version."""
        for schema_id in await self.list_created_schema_ids():
            if not schema_id.startswith(f"{issuer_did}:2:"):
                continue
            record = await self.get_schema(schema_id)
            if record and record.name == name and record.version == version:
                return record
        return None

    async def create_schema(
        self,
        *,
        name: str,
        version: str,
        attributes: Sequence[str],
    ) -> SchemaRecord:
        """Register a new schema on the ledger and return its canonical record."""
        payload = {
            "schema_name": name,
            "schema_version": version,
            "attributes": list(attributes),
        }
        data = await self._post("/schemas", payload)
        schema_id = (data or {}).get("schema_id")
        if not schema_id:
            raise AnonCredsRegistryError(
                f"ACA-Py did not return a schema_id when creating {name} v{version}"
            )
        schema_body = (data or {}).get("schema") or {}
        return SchemaRecord(
            schema_id=schema_id,
            name=name,
            version=version,
            attributes=tuple(attributes),
            seq_no=schema_body.get("seqNo"),
        )

    # ------------------------------------------------------------------
    # Credential definitions
    # ------------------------------------------------------------------
    async def list_created_cred_def_ids(self) -> List[str]:
        """Return credential-definition ids already created by this agent."""
        data = await self._get("/credential-definitions/created")
        return list((data or {}).get("credential_definition_ids") or [])

    async def get_cred_def(self, cred_def_id: str) -> Optional[CredDefRecord]:
        """Return a credential definition by id, or ``None`` when missing."""
        data = await self._get(
            f"/credential-definitions/{cred_def_id}",
            expected_status=(200, 404),
        )
        if not data:
            return None
        body = (data or {}).get("credential_definition") or {}
        schema_seq_no = self._extract_schema_seq_no(cred_def_id)
        return CredDefRecord(
            cred_def_id=cred_def_id,
            schema_id=None,
            tag=body.get("tag"),
            supports_revocation=bool(
                (body.get("value") or {}).get("revocation")
            ),
            schema_seq_no=schema_seq_no,
        )

    async def find_cred_def(
        self,
        *,
        issuer_did: str,
        schema_id: str,
        tag: str,
    ) -> Optional[CredDefRecord]:
        """Return the first cred def owned by the issuer for ``schema_id`` / ``tag``."""
        schema_record = await self.get_schema(schema_id)
        schema_seq_no = schema_record.seq_no if schema_record else None

        for cred_def_id in await self.list_created_cred_def_ids():
            if not cred_def_id.startswith(f"{issuer_did}:3:CL:"):
                continue
            if not cred_def_id.endswith(f":{tag}"):
                continue
            if schema_seq_no is not None and not cred_def_id.startswith(
                f"{issuer_did}:3:CL:{schema_seq_no}:"
            ):
                continue
            record = await self.get_cred_def(cred_def_id)
            if record is not None:
                return CredDefRecord(
                    cred_def_id=record.cred_def_id,
                    schema_id=schema_id,
                    tag=record.tag or tag,
                    supports_revocation=record.supports_revocation,
                    schema_seq_no=record.schema_seq_no or schema_seq_no,
                )
        return None

    async def create_cred_def(
        self,
        *,
        schema_id: str,
        tag: str,
        supports_revocation: bool,
    ) -> CredDefRecord:
        """Register a new credential definition on the ledger."""
        payload = {
            "schema_id": schema_id,
            "tag": tag,
            "support_revocation": supports_revocation,
        }
        data = await self._post("/credential-definitions", payload)
        cred_def_id = (data or {}).get("credential_definition_id")
        if not cred_def_id:
            raise AnonCredsRegistryError(
                "ACA-Py did not return a credential_definition_id "
                f"when creating cred def for {schema_id}"
            )
        return CredDefRecord(
            cred_def_id=cred_def_id,
            schema_id=schema_id,
            tag=tag,
            supports_revocation=supports_revocation,
            schema_seq_no=self._extract_schema_seq_no(cred_def_id),
        )

    # ------------------------------------------------------------------
    # Low-level helpers
    # ------------------------------------------------------------------
    async def _get(
        self,
        path: str,
        *,
        expected_status: Sequence[int] = (200,),
    ) -> Optional[dict]:
        async with httpx.AsyncClient(timeout=self._timeout) as http:
            response = await http.get(
                f"{self._admin_url}{path}", headers=self._headers
            )
        if response.status_code == 404:
            return None
        if response.status_code not in expected_status:
            logger.warning(
                "ACA-Py GET %s returned %s: %s",
                path,
                response.status_code,
                response.text[:500],
            )
            response.raise_for_status()
        return response.json()

    async def _post(self, path: str, payload: dict) -> dict:
        async with httpx.AsyncClient(timeout=self._timeout) as http:
            response = await http.post(
                f"{self._admin_url}{path}",
                json=payload,
                headers=self._headers,
            )
        if response.status_code >= 400:
            logger.warning(
                "ACA-Py POST %s returned %s: %s",
                path,
                response.status_code,
                response.text[:500],
            )
            response.raise_for_status()
        return response.json()

    @staticmethod
    def _extract_schema_seq_no(cred_def_id: str) -> Optional[int]:
        match = _CRED_DEF_SCHEMA_SEQNO_RE.match(cred_def_id)
        return int(match.group(1)) if match else None
