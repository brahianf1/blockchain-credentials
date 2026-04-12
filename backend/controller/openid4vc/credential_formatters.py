#!/usr/bin/env python3
"""
Credential Formatters — Strategy Pattern para formatos de credenciales

Cada formato de credencial (``vc+sd-jwt``, ``jwt_vc_json``) tiene su
propia función formateadora.  El credential endpoint despacha al
formateador correcto según lo que la wallet solicita.

Principios de diseño:
    • Strategy Pattern — Cada formateador encapsula la lógica completa de
      un formato específico.  El dispatcher selecciona el correcto.
    • Open/Closed Principle — Agregar un nuevo formato (ej: ``mso_mdoc``,
      ``dc+sd-jwt``) requiere solo:
        1. Escribir una función ``format_<name>(...)``
        2. Agregarla al diccionario ``_FORMATTERS``
      Sin modificar el dispatcher ni los endpoints.
    • Single Responsibility — Cada función hace UNA cosa: construir el
      payload y firmarlo en el formato correcto.

Referencia: OpenID4VCI 1.0 — §7 Credential Response
"""

from __future__ import annotations

import secrets
from datetime import datetime
from typing import Any

import jwt
import structlog

from .credential_registry import CREDENTIAL_CONFIGURATIONS, get_all_config_ids

logger = structlog.get_logger()

# Validez de credenciales: 1 año
_CREDENTIAL_VALIDITY_SECONDS = 365 * 24 * 60 * 60


# ============================================================================
# FORMATEADORES INDIVIDUALES
# ============================================================================

def format_sd_jwt(
    *,
    credential_data: dict[str, Any],
    holder_did: str,
    proof_jwk: dict[str, Any] | None,
    access_token: str,
    private_key: Any,
    issuer_url: str,
    issuer_did: str,
    requires_absolute_vct: bool = False,
) -> tuple[str, str]:
    """
    Genera una credencial en formato ``vc+sd-jwt`` (SD-JWT VC).

    El resultado es un JWT firmado con header ``typ: vc+sd-jwt`` seguido
    del separador de disclosures ``~``.  El payload es plano (flat claims)
    con ``vct`` como tipo de credencial, según IETF SD-JWT VC draft.

    Returns:
        Tupla ``(credential_string, format_name)``.
    """
    now_ts = int(datetime.now().timestamp())
    exp_ts = now_ts + _CREDENTIAL_VALIDITY_SECONDS

    cnf = {"jwk": proof_jwk} if proof_jwk else {"jwk": {}}

    payload = {
        "iss": issuer_url,
        "sub": holder_did,
        "cnf": cnf,
        "iat": now_ts - 5,  # clock skew tolerance
        "exp": exp_ts,
        "jti": f"urn:credential:{access_token[:16]}",
        "vct": f"{issuer_url}/UniversityDegree" if requires_absolute_vct else "UniversityDegree",
        "university": "UTN",
        "student_name": credential_data.get("student_name", "Unknown"),
        "student_email": credential_data.get("student_email", "unknown@example.com"),
        "student_id": credential_data.get("student_id", "unknown"),
        "course_name": credential_data.get("course_name", "N/A"),
        "completion_date": credential_data.get("completion_date", "N/A"),
        "grade": credential_data.get("grade", "N/A"),
    }

    sd_jwt = jwt.encode(
        payload,
        private_key,
        algorithm="ES256",
        headers={
            "kid": f"{issuer_did}#key-1",
            "typ": "vc+sd-jwt",
        },
    )

    # SD-JWT base sin disclosures: JWT seguido del separador ~
    credential = f"{sd_jwt}~"
    logger.info("📦 Credencial formateada como vc+sd-jwt")
    return credential, "vc+sd-jwt"


def format_jwt_vc_json(
    *,
    credential_data: dict[str, Any],
    holder_did: str,
    proof_jwk: dict[str, Any] | None,
    access_token: str,
    private_key: Any,
    issuer_url: str,
    issuer_did: str,
    requires_absolute_vct: bool = False,
) -> tuple[dict[str, Any], str]:
    """
    Genera una credencial en formato ``jwt_vc_json`` (W3C VC Data Model 1.1).

    DIDRoom almacena internamente las credenciales como objetos ``LdpVc``
    (ver ``ForkbombEu/wallet/.../credentials.ts``), lo que significa que
    espera un **JSON object** con ``credentialSubject`` en el top-level,
    NO un JWT string.

    El JWT se genera igualmente para integridad criptográfica y se incluye
    dentro del campo ``proof`` del objeto VC, siguiendo la convención
    ``JwtProof2020``.

    Estructura retornada (compatible con ``LdpVc`` de DIDRoom)::

        {
            "@context": [...],
            "type": ["VerifiableCredential", "UniversityDegree"],
            "credentialSubject": { claims... },
            "issuer": "...",
            "issuanceDate": "...",
            "validUntil": "...",
            "proof": { "type": "JwtProof2020", "jwt": "eyJ..." }
        }

    Returns:
        Tupla ``(credential_object, format_name)``.
    """
    now_ts = int(datetime.now().timestamp())
    exp_ts = now_ts + _CREDENTIAL_VALIDITY_SECONDS

    now_iso = datetime.fromtimestamp(now_ts).isoformat() + "Z"
    exp_iso = datetime.fromtimestamp(exp_ts).isoformat() + "Z"

    # El objeto VC completo (W3C Verifiable Credential Data Model 1.1)
    vc_object = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            f"{issuer_url}/oid4vc/context/v1",
        ],
        "type": ["VerifiableCredential", "UniversityDegree"],
        "id": f"urn:credential:{access_token[:16]}",
        "issuer": issuer_url,
        "issuanceDate": now_iso,
        "validUntil": exp_iso,
        "credentialSubject": {
            "id": holder_did,
            "student_name": credential_data.get("student_name", "Unknown"),
            "student_email": credential_data.get("student_email", "unknown@example.com"),
            "student_id": credential_data.get("student_id", "unknown"),
            "course_name": credential_data.get("course_name", "N/A"),
            "completion_date": credential_data.get("completion_date", "N/A"),
            "grade": credential_data.get("grade", "N/A"),
            "university": "UTN",
        },
    }

    # JWT para integridad criptográfica
    jwt_payload = {
        "iss": issuer_url,
        "sub": holder_did,
        "iat": now_ts - 5,
        "exp": exp_ts,
        "jti": f"urn:credential:{access_token[:16]}",
        "vc": vc_object,
    }

    vc_jwt = jwt.encode(
        jwt_payload,
        private_key,
        algorithm="ES256",
        headers={"kid": f"{issuer_did}#key-1"},
    )

    # Agregar proof JWT al objeto VC (DIDRoom lee esto como LdpVc.proof)
    vc_object["proof"] = {
        "type": "JwtProof2020",
        "jwt": vc_jwt,
    }

    logger.info("📦 Credencial formateada como jwt_vc_json (JSON object con proof)")
    return vc_object, "jwt_vc_json"


# ============================================================================
# DISPATCHER — Mapeo formato → formateadora (Strategy Pattern)
# ============================================================================

_FORMATTERS: dict[str, Any] = {
    "vc+sd-jwt": format_sd_jwt,
    "jwt_vc_json": format_jwt_vc_json,
}

# Alias comunes que algunas wallets envían (normalización)
_FORMAT_ALIASES: dict[str, str] = {
    "jwt_vc": "jwt_vc_json",       # Alias frecuente
    "ldp_vc": "jwt_vc_json",       # Fallback razonable
    "sd-jwt": "vc+sd-jwt",         # Variante sin prefijo
}

# Formatos que retornan un string JWT directamente (no un JSON object)
_STRING_FORMATS = frozenset({"vc+sd-jwt", "jwt_vc_json"})


def resolve_format(
    request_body: dict[str, Any],
    fallback_config_id: str | None = None,
) -> str:
    """
    Determina el formato de credencial que la wallet espera.

    Prioridad de resolución:
        1. Campo ``format`` explícito en el body del request
        2. ``credential_configuration_id`` → formato desde el registry
        3. Formato por defecto del primer config_id registrado

    Args:
        request_body: Body JSON del credential request de la wallet.
        fallback_config_id: Config ID alternativo si no se puede resolver.

    Returns:
        String con el formato normalizado (ej: ``"vc+sd-jwt"``).
    """
    # Prioridad 1: formato explícito en el request
    fmt = request_body.get("format")
    if fmt:
        normalized = _FORMAT_ALIASES.get(fmt, fmt)
        if normalized in _FORMATTERS:
            logger.info(f"🎯 Formato resuelto desde request.format: {normalized}")
            return normalized
        logger.warning(
            f"⚠️ Formato '{fmt}' no soportado, usando fallback",
            requested=fmt,
        )

    # Prioridad 2: credential_configuration_id (Draft 11) o credential_identifier (Draft 13)
    config_id = request_body.get("credential_configuration_id") or request_body.get("credential_identifier")
    if config_id and config_id in CREDENTIAL_CONFIGURATIONS:
        resolved = CREDENTIAL_CONFIGURATIONS[config_id]["format"]
        logger.info(
            f"🎯 Formato resuelto desde config_id ({config_id}): {resolved}"
        )
        return resolved

    # Prioridad 3: fallback
    if fallback_config_id and fallback_config_id in CREDENTIAL_CONFIGURATIONS:
        resolved = CREDENTIAL_CONFIGURATIONS[fallback_config_id]["format"]
        logger.info(f"🎯 Formato resuelto desde fallback config: {resolved}")
        return resolved

    # Default: primer config registrado
    default_id = get_all_config_ids()[0]
    default_format = CREDENTIAL_CONFIGURATIONS[default_id]["format"]
    logger.info(f"🎯 Usando formato por defecto: {default_format}")
    return default_format


def format_credential(
    format_key: str,
    **kwargs: Any,
) -> tuple[Any, str]:
    """
    Dispatcher central — despacha al formateador correcto.

    Args:
        format_key: Formato de credencial (ej: ``"vc+sd-jwt"``).
        **kwargs: Argumentos pasados al formateador (credential_data,
                  holder_did, proof_jwk, access_token, private_key,
                  issuer_url, issuer_did).

    Returns:
        Tupla ``(credential_response, format_name)``.

    Raises:
        ValueError: Si el formato no está registrado.
    """
    normalized = _FORMAT_ALIASES.get(format_key, format_key)
    formatter = _FORMATTERS.get(normalized)

    if formatter is None:
        supported = ", ".join(sorted(_FORMATTERS.keys()))
        raise ValueError(
            f"Formato '{format_key}' no soportado. "
            f"Formatos disponibles: {supported}"
        )

    logger.info(f"📋 Despachando a formateador: {normalized}")
    return formatter(**kwargs)

def build_credential_response(
    credential: Any,
    format_name: str,
) -> dict[str, Any]:
    """
    Construye el objeto de respuesta completo del credential endpoint.
    
    Genera el json exacto esperado para el formato devuelto, cumpliendo las
    draft specs 11 y 13 mediante el re-uso del mismo payload en 'credential'
    y 'credentials'/'credential_responses' (pero strictly del mismo tipo, para
    evitar fallos en arrays híbridos como los que Rompen a Paradym).
    """

    entry = {"credential": credential, "format": format_name}
    array_entries = [entry]

    return {
        # Draft 13+ (OID4VCI 1.0) — Campo singular
        "format": format_name,
        "credential": credential,
        
        # Draft 11/12 — Arrays legacy
        "credentials": array_entries,
        "credential_responses": array_entries,

        # Nonce y notificación
        "c_nonce": secrets.token_urlsafe(32),
        "c_nonce_expires_in": 300,
        "notification_id": f"notif_{secrets.token_urlsafe(16)}",
    }
