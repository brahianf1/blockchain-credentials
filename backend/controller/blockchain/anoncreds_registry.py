"""ACA-Py admin API wrapper focused on AnonCreds registration.

This module is intentionally thin: it speaks directly to ACA-Py over
HTTP and returns typed dataclasses that the service layer can consume.
No database access, no business rules — just a reliable adapter to a
specific subset of ACA-Py's admin surface.

It covers three AnonCreds artifacts:

* **SCHEMA** — attribute definitions for a credential type.
* **CRED_DEF** — issuer-specific signing keys bound to a schema.
* **REV_REG_DEF** — revocation registry associated with a cred def,
  including publication of the initial accumulator.
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


@dataclass(frozen=True)
class RevRegRecord:
    """Snapshot of a revocation registry published on the ledger."""

    rev_reg_id: str
    cred_def_id: Optional[str] = None
    max_cred_num: Optional[int] = None
    issuance_type: Optional[str] = None
    tails_hash: Optional[str] = None
    tails_location: Optional[str] = None
    state: Optional[str] = None


class AnonCredsRegistry:
    """Adapter that wraps ACA-Py's schema / cred-def / rev-reg endpoints."""

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
    # Revocation registries
    # ------------------------------------------------------------------
    async def list_rev_reg_ids(
        self,
        *,
        cred_def_id: Optional[str] = None,
        state: Optional[str] = None,
    ) -> List[str]:
        """Return revocation registry ids created by this agent."""
        params: List[str] = []
        if cred_def_id:
            params.append(f"cred_def_id={cred_def_id}")
        if state:
            params.append(f"state={state}")
        path = "/revocation/registries/created"
        if params:
            path = f"{path}?{'&'.join(params)}"
        data = await self._get(path)
        return list((data or {}).get("rev_reg_ids") or [])

    async def get_rev_reg(self, rev_reg_id: str) -> Optional[RevRegRecord]:
        """Return the stored revocation registry record, if any."""
        data = await self._get(
            f"/revocation/registry/{rev_reg_id}",
            expected_status=(200, 404),
        )
        if not data:
            return None
        result = (data or {}).get("result") or {}
        rev_reg_def = result.get("revoc_reg_def") or {}
        value = (rev_reg_def.get("value") or {})
        return RevRegRecord(
            rev_reg_id=rev_reg_id,
            cred_def_id=result.get("cred_def_id") or rev_reg_def.get("credDefId"),
            max_cred_num=value.get("maxCredNum"),
            issuance_type=value.get("issuanceType"),
            tails_hash=value.get("tailsHash"),
            tails_location=value.get("tailsLocation")
            or result.get("tails_public_uri"),
            state=result.get("state"),
        )

    async def find_active_rev_reg(
        self, *, cred_def_id: str
    ) -> Optional[RevRegRecord]:
        """Return the first ``active`` registry for ``cred_def_id``."""
        for state in ("active", "finished", "posted"):
            for rev_reg_id in await self.list_rev_reg_ids(
                cred_def_id=cred_def_id, state=state
            ):
                record = await self.get_rev_reg(rev_reg_id)
                if record is not None:
                    return record
        return None

    async def create_rev_reg(
        self,
        *,
        cred_def_id: str,
        max_cred_num: int,
        issuance_type: str,
    ) -> RevRegRecord:
        """Create a revocation registry in the wallet (not yet on the ledger)."""
        payload = {
            "credential_definition_id": cred_def_id,
            "max_cred_num": max_cred_num,
            "issuance_type": issuance_type,
        }
        data = await self._post("/revocation/create-registry", payload)
        result = (data or {}).get("result") or {}
        rev_reg_id = result.get("revoc_reg_id")
        if not rev_reg_id:
            raise AnonCredsRegistryError(
                "ACA-Py did not return a revoc_reg_id when creating the "
                f"rev registry for {cred_def_id}"
            )
        rev_reg_def = result.get("revoc_reg_def") or {}
        value = rev_reg_def.get("value") or {}
        return RevRegRecord(
            rev_reg_id=rev_reg_id,
            cred_def_id=cred_def_id,
            max_cred_num=value.get("maxCredNum") or max_cred_num,
            issuance_type=value.get("issuanceType") or issuance_type,
            tails_hash=value.get("tailsHash"),
            tails_location=value.get("tailsLocation"),
            state=result.get("state") or "init",
        )

    async def upload_tails_file(self, rev_reg_id: str) -> None:
        """Push the generated tails file from ACA-Py to the tails server."""
        await self._put(
            f"/revocation/registry/{rev_reg_id}/tails-file",
        )

    async def publish_rev_reg_def(self, rev_reg_id: str) -> None:
        """Anchor the rev_reg_def on the ledger."""
        await self._post(
            f"/revocation/registry/{rev_reg_id}/definition",
            payload=None,
        )

    async def publish_rev_reg_entry(self, rev_reg_id: str) -> None:
        """Anchor the initial rev_reg_entry (accumulator) on the ledger."""
        await self._post(
            f"/revocation/registry/{rev_reg_id}/entry",
            payload=None,
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

    async def _post(
        self, path: str, payload: Optional[dict]
    ) -> dict:
        async with httpx.AsyncClient(timeout=self._timeout) as http:
            response = await http.post(
                f"{self._admin_url}{path}",
                json=payload if payload is not None else {},
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
        return response.json() if response.content else {}

    async def _put(self, path: str) -> dict:
        async with httpx.AsyncClient(timeout=self._timeout) as http:
            response = await http.put(
                f"{self._admin_url}{path}", headers=self._headers
            )
        if response.status_code >= 400:
            logger.warning(
                "ACA-Py PUT %s returned %s: %s",
                path,
                response.status_code,
                response.text[:500],
            )
            response.raise_for_status()
        return response.json() if response.content else {}

    @staticmethod
    def _extract_schema_seq_no(cred_def_id: str) -> Optional[int]:
        match = _CRED_DEF_SCHEMA_SEQNO_RE.match(cred_def_id)
        return int(match.group(1)) if match else None
