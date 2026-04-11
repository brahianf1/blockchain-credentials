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
    • Separación Internal / External — El registro interno almacena datos
      de TODOS los formatos (``vct``, ``credential_definition``).  La
      función ``get_configurations_for_metadata()`` filtra los campos
      según el ``format`` declarado para producir metadata spec-compliant.

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
# CREDENTIAL CONFIGURATIONS (Registro Interno — Datos de TODOS los formatos)
# ============================================================================
#
# REGISTRO INTERNO vs METADATA EXTERNA
# ──────────────────────────────────────
# Este diccionario almacena datos INTERNOS de todos los formatos.
# Incluye campos de vc+sd-jwt (``vct``, ``claims``) y jwt_vc_json
# (``credential_definition``) para que los formateadores en
# ``credential_formatters.py`` puedan generar credenciales en
# cualquier formato sin fuentes de datos separadas.
#
# La función ``get_configurations_for_metadata()`` FILTRA estos campos
# según el ``format`` declarado para producir metadata spec-compliant.
# Esto evita errores de parseo en wallets estrictas (ej: WaltID con
# kotlinx.serialization).
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
    Retorna ``credential_configurations_supported`` spec-compliant.

    Filtra campos que no pertenecen al formato declarado:

        • ``vc+sd-jwt``   → conserva ``vct``, ``claims``.  Elimina ``credential_definition``.
        • ``jwt_vc_json`` → conserva ``credential_definition``.  Elimina ``vct``, ``claims``.

    Esto evita errores de parseo en wallets estrictas (ej: WaltID con
    kotlinx.serialization lanza ``JsonLiteral is not a JsonObject``
    al encontrar campos inesperados para el formato declarado).
    """
    # Campos exclusivos de cada formato (OID4VCI §A)
    _FIELDS_BY_FORMAT: dict[str, frozenset[str]] = {
        "vc+sd-jwt": frozenset({"credential_definition"}),   # eliminar
        "jwt_vc_json": frozenset({"vct", "claims"}),          # eliminar
    }

    result: dict[str, dict[str, Any]] = {}
    for config_id, config in CREDENTIAL_CONFIGURATIONS.items():
        fmt = config.get("format", "vc+sd-jwt")
        fields_to_remove = _FIELDS_BY_FORMAT.get(fmt, frozenset())
        result[config_id] = {
            k: v for k, v in config.items()
            if k not in fields_to_remove
        }
    return result


def get_default_format(config_id: str) -> str:
    """Retorna el formato por defecto de una configuración."""
    config = CREDENTIAL_CONFIGURATIONS.get(config_id)
    if config:
        return config["format"]
    return "vc+sd-jwt"
