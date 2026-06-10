"""Pruebas unitarias de los helpers de OpenID4VC (openid4vc/helpers.py).

Cubren dos cosas: la derivación de identificadores DID a partir de una clave
pública (JWK) y la extracción del DID del holder y del estado del emisor desde
los datos que envían las wallets. Es lógica pura y determinista.
"""
import json

import pytest

from openid4vc.helpers import (
    create_did_jwk_from_jwk,
    create_did_key_from_jwk,
    extract_holder_did_from_proof,
    extract_issuer_state_from_par,
)

# JWK EC P-256 público de ejemplo (vector de prueba fijo).
SAMPLE_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "KCRLFB4KxA1CUjD-8Q_No08l8g1-MS0_RoKIuLZ8DnU",
    "y": "hIGpAvGjg94Pzm96_00s4NUC7dZvlpkfx2F8Sar3a1o",
}


# --- did:jwk -----------------------------------------------------------------

def test_create_did_jwk_tiene_prefijo_y_es_determinista():
    did = create_did_jwk_from_jwk(SAMPLE_JWK)
    assert did.startswith("did:jwk:")
    assert create_did_jwk_from_jwk(SAMPLE_JWK) == did  # mismo input -> mismo did


def test_create_did_jwk_ignora_la_clave_privada():
    # Aunque el JWK traiga la parte privada 'd', el did:jwk debe usar SOLO los
    # campos públicos: no puede filtrar el secreto.
    con_privada = {**SAMPLE_JWK, "d": "valor-secreto-que-no-debe-aparecer"}
    assert create_did_jwk_from_jwk(con_privada) == create_did_jwk_from_jwk(SAMPLE_JWK)


# --- did:key -----------------------------------------------------------------

def test_create_did_key_p256_tiene_prefijo():
    assert create_did_key_from_jwk(SAMPLE_JWK).startswith("did:key:z")


def test_create_did_key_rechaza_clave_no_ec():
    with pytest.raises(ValueError):
        create_did_key_from_jwk({"kty": "RSA", "n": "abc", "e": "AQAB"})


# --- extracción del DID del holder ------------------------------------------

def test_extract_did_desde_iss():
    assert extract_holder_did_from_proof("", {}, {"iss": "did:web:utn.edu"}) == "did:web:utn.edu"


def test_extract_did_desde_kid_quita_fragmento():
    did = extract_holder_did_from_proof("", {"kid": "did:key:z6Mk#key-1"}, {})
    assert did == "did:key:z6Mk"


def test_extract_did_desde_jwk_genera_did_jwk():
    did = extract_holder_did_from_proof("", {"jwk": SAMPLE_JWK}, {})
    assert did.startswith("did:jwk:")


def test_extract_did_sin_datos_devuelve_none():
    assert extract_holder_did_from_proof("", {}, {}) is None


# --- extracción del issuer_state (PAR) --------------------------------------

def test_extract_issuer_state_desde_state():
    assert extract_issuer_state_from_par({"state": "session_abc"}) == "session_abc"


def test_extract_issuer_state_desde_authorization_details():
    par = {"authorization_details": json.dumps([{"issuer_state": "session_x"}])}
    assert extract_issuer_state_from_par(par) == "session_x"


def test_extract_issuer_state_inexistente_devuelve_none():
    assert extract_issuer_state_from_par({"state": "no-es-session"}) is None
