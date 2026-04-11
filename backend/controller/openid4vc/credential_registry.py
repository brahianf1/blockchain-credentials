#!/usr/bin/env python3
"""
Credential Configuration Registry — Fuente Única de Verdad (Single Source of Truth)

Define TODAS las configuraciones de credenciales, claims, display y formatos
soportados.  Cada metadata endpoint, offer generation y credential issuance
DERIVA de este registro.  Cero duplicación.

Principios de diseño:
    • Registry Pattern — Las configuraciones se definen una sola vez aquí.
    • Open/Closed Principle — Agregar un nuevo tipo de credencial requiere
      solo agregar una entrada a ``CREDENTIAL_CONFIGURATIONS`` y una función
      formateadora en ``credential_formatters.py``.  Sin tocar endpoints.
    • Hybrid Config — Cada configuración incluye los campos requeridos por
      TODOS los formatos que las wallets podrían esperar (``vct`` para
      SD-JWT, ``credential_definition`` para jwt_vc_json).  Las wallets
      leen los campos que entienden e ignoran los demás.

Referencia: OpenID4VCI 1.0 — §11.2.3 Credential Issuer Metadata
"""

from __future__ import annotations

from typing import Any

# ============================================================================
# ISSUER DISPLAY
# ============================================================================

ISSUER_DISPLAY: list[dict[str, str]] = [
    {
        "name": "Universidad Tecnológica Nacional",
        "locale": "es-AR",
    },
    {
        "name": "National Technological University",
        "locale": "en-US",
    },
]

# ============================================================================
# CLAIM DEFINITIONS (definidos UNA SOLA VEZ)
# ============================================================================

UNIVERSITY_DEGREE_CLAIMS: dict[str, dict[str, Any]] = {
    "student_name": {
        "mandatory": True,
        "display": [{"name": "Nombre / Name"}],
    },
    "student_id": {
        "mandatory": False,
        "display": [{"name": "Identificación / ID"}],
    },
    "student_email": {
        "mandatory": False,
        "display": [{"name": "Correo / Email"}],
    },
    "course_name": {
        "mandatory": True,
        "display": [{"name": "Curso / Course"}],
    },
    "completion_date": {
        "mandatory": True,
        "display": [{"name": "Fecha / Date"}],
    },
    "grade": {
        "mandatory": False,
        "display": [{"name": "Calificación / Grade"}],
    },
    "university": {
        "mandatory": True,
        "display": [{"name": "Universidad / University"}],
    },
}

# ============================================================================
# CREDENTIAL DISPLAY (definido UNA SOLA VEZ, compartido por todas las configs)
# ============================================================================

_CREDENTIAL_LOGO_URI = "https://placehold.co/150x150/1976d2/white?text=UTN"

UNIVERSITY_DEGREE_DISPLAY: list[dict[str, Any]] = [
    {
        "name": "Certificado Universitario",
        "description": "Credencial oficial que certifica la finalización de un curso.",
        "locale": "es-AR",
        "background_color": "#1976d2",
        "text_color": "#FFFFFF",
        "logo": {
            "uri": _CREDENTIAL_LOGO_URI,
            "alt_text": "Logo UTN",
        },
    },
    {
        "name": "University Certificate",
        "description": "Official credential certifying course completion.",
        "locale": "en-US",
        "background_color": "#1976d2",
        "text_color": "#FFFFFF",
        "logo": {
            "uri": _CREDENTIAL_LOGO_URI,
            "alt_text": "UTN Logo",
        },
    },
]

# ============================================================================
# CREDENTIAL CONFIGURATIONS
# ============================================================================
#
# CONFIGURACIÓN HÍBRIDA
# ─────────────────────
# Se incluyen AMBOS campos de formato para compatibilidad con wallets:
#
#   • ``vct``                   → Requerido por wallets vc+sd-jwt (Lissi, EUDI)
#   • ``credential_definition`` → Requerido por wallets jwt_vc_json (DIDRoom)
#
# Cada wallet lee los campos que entiende e ignora los que no reconoce.
# JSON es forward-compatible por diseño (RFC 8259 §4), así que campos
# adicionales no causan errores de parseo.
#
# El ``format`` se declara como ``vc+sd-jwt`` porque es el formato más
# estricto (Lissi lo verifica).  DIDRoom ignora el campo ``format`` y
# busca directamente ``credential_definition.type[0]``.
#
# En el credential endpoint, el formato de RESPUESTA se determina por
# el campo ``format`` que envía la wallet en su credential request,
# NO por el formato declarado aquí en la metadata.
# ============================================================================

CREDENTIAL_CONFIGURATIONS: dict[str, dict[str, Any]] = {
    "UniversityDegree": {
        # Formato primario (Lissi parsea la metadata por este campo)
        "format": "vc+sd-jwt",

        # Scope para authorization_details (OID4VCI §5.1.1)
        "scope": "UniversityDegreeScope",

        # Campo requerido por vc+sd-jwt (OID4VCI §A.3.1)
        "vct": "UniversityDegree",

        # Campo requerido por jwt_vc_json (OID4VCI §A.1.1)
        # Incluido para compatibilidad con DIDRoom que busca este campo.
        # ``credentialSubject`` contiene los claims en la convención jwt_vc_json
        # (DIDRoom lee aquí), mientras que ``claims`` (top-level) es la
        # convención vc+sd-jwt (Lissi lee ahí).  Ambos apuntan a la misma
        # definición — cero duplicación.
        "credential_definition": {
            "type": ["VerifiableCredential", "UniversityDegree"],
            "credentialSubject": UNIVERSITY_DEGREE_CLAIMS,
        },

        # Métodos de binding criptográfico soportados
        "cryptographic_binding_methods_supported": [
            "did:key",
            "did:jwk",
            "jwk",
        ],

        # Algoritmos de firma soportados
        "credential_signing_alg_values_supported": ["ES256"],

        # Display y claims (definidos arriba, referenciados aquí)
        "display": UNIVERSITY_DEGREE_DISPLAY,
        "claims": UNIVERSITY_DEGREE_CLAIMS,
    },
}


# ============================================================================
# FUNCIONES DE ACCESO AL REGISTRO (API del módulo)
# ============================================================================

def get_all_config_ids() -> list[str]:
    """Retorna todos los IDs de configuración de credenciales registrados."""
    return list(CREDENTIAL_CONFIGURATIONS.keys())


def get_config(config_id: str) -> dict[str, Any] | None:
    """Retorna la configuración completa para un ID dado, o ``None``."""
    return CREDENTIAL_CONFIGURATIONS.get(config_id)


def get_configurations_for_metadata() -> dict[str, dict[str, Any]]:
    """
    Retorna el diccionario ``credential_configurations_supported`` listo
    para ser servido por el endpoint de metadata del issuer.

    Es una copia para evitar mutaciones accidentales.
    """
    return {
        config_id: config.copy()
        for config_id, config in CREDENTIAL_CONFIGURATIONS.items()
    }


def get_default_format(config_id: str) -> str:
    """Retorna el formato por defecto de una configuración."""
    config = CREDENTIAL_CONFIGURATIONS.get(config_id)
    if config:
        return config["format"]
    return "vc+sd-jwt"
