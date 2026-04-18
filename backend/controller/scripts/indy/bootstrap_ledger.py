#!/usr/bin/env python3
"""Provision the institutional AnonCreds registry on Hyperledger Indy.

Thin command-line entry point around
:class:`blockchain.LedgerBootstrapService`. Running it multiple times is
safe: existing schemas and credential definitions are reused and only
missing artifacts are registered on the ledger.

Usage
-----
From the VPS, inside the controller container::

    docker exec -i python-controller python -m scripts.indy.bootstrap_ledger

Configuration is driven entirely by environment variables (see
``blockchain/config.py`` for the full list).
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys

from blockchain import BootstrapResult, get_bootstrap_service, get_settings


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s :: %(message)s",
    )


def _result_to_json(result: BootstrapResult, network: str) -> str:
    payload = {
        "issuer_did": (
            result.issuer_did
            if result.issuer_did.startswith("did:")
            else f"did:sov:{result.issuer_did}"
        ),
        "network": network,
        "schema_id": result.schema_id,
        "cred_def_id": result.cred_def_id,
        "supports_revocation": result.supports_revocation,
        "schema": {
            "kind": result.schema.kind,
            "artifact_id": result.schema.artifact_id,
            "outcome": result.schema.outcome.value,
            "seq_no": result.schema.seq_no,
        },
        "cred_def": {
            "kind": result.cred_def.kind,
            "artifact_id": result.cred_def.artifact_id,
            "outcome": result.cred_def.outcome.value,
            "seq_no": result.cred_def.seq_no,
        },
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


async def _run() -> int:
    settings = get_settings()
    service = get_bootstrap_service()

    logging.getLogger(__name__).info(
        "Running bootstrap against ACA-Py at %s (schema=%s v%s, tag=%s, revocation=%s)",
        settings.acapy_admin_url,
        settings.schema_name,
        settings.schema_version,
        settings.cred_def_tag,
        settings.supports_revocation,
    )

    result = await service.bootstrap(
        schema_name=settings.schema_name,
        schema_version=settings.schema_version,
        schema_attributes=settings.schema_attributes,
        cred_def_tag=settings.cred_def_tag,
        supports_revocation=settings.supports_revocation,
    )

    print(_result_to_json(result=result, network=settings.network_name))
    return 0


def main() -> int:
    _configure_logging()
    try:
        return asyncio.run(_run())
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        logging.getLogger(__name__).exception("Bootstrap failed")
        sys.stderr.write(f"ERROR: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
