"""Pruebas de integración del flujo de ACEPTACIÓN de credenciales (OpenID4VCI).

Simulan el intercambio que hace la wallet del alumno contra los endpoints reales
`/oid4vc/token` y `/oid4vc/credential`, validando:

  * la aceptación correcta (código pre-autorizado válido -> access token);
  * la gestión de errores (código inválido, grant no soportado, PKCE incorrecto);
  * las puertas de seguridad del endpoint de credencial (token y proof requeridos).

Se usa el `session_manager` real (se siembran sesiones con su API) y el
`PKCEValidator` real. NO se necesita Besu ni firmar credenciales: las pruebas
paran antes del anclaje on-chain.
"""
import pytest
from fastapi.testclient import TestClient

from app import app
from pkce_validator import PKCEValidator
from session_manager import session_manager

PRE_AUTH_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clear_sessions():
    """El session_manager es un singleton en memoria: lo limpiamos por test."""
    for index in (
        session_manager._sessions,
        session_manager._pre_auth_index,
        session_manager._auth_code_index,
        session_manager._access_token_index,
        session_manager._request_uri_index,
    ):
        index.clear()
    yield


# =============================================================================
# /oid4vc/token — aceptación e intercambio de código por token
# =============================================================================

def test_token_pre_autorizado_valido_emite_access_token(client):
    sid = session_manager.create_session({"student_name": "Ada"})
    session_manager.link_pre_auth_code(sid, "pre_auth_TEST_OK")

    r = client.post(
        "/oid4vc/token",
        data={"grant_type": PRE_AUTH_GRANT, "pre-authorized_code": "pre_auth_TEST_OK"},
    )
    assert r.status_code == 200
    assert r.json()["access_token"].startswith("access_")


def test_token_pre_autorizado_invalido_devuelve_400(client):
    r = client.post(
        "/oid4vc/token",
        data={"grant_type": PRE_AUTH_GRANT, "pre-authorized_code": "no-existe"},
    )
    assert r.status_code == 400


def test_token_grant_no_soportado_devuelve_400(client):
    r = client.post("/oid4vc/token", data={"grant_type": "client_credentials"})
    assert r.status_code == 400


def test_token_authorization_code_con_pkce_correcto(client):
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = PKCEValidator.generate_code_challenge(verifier, "S256")

    sid = session_manager.create_session({"student_name": "Ada"})
    session_manager.link_authorization_request(
        sid, {"code_challenge": challenge, "code_challenge_method": "S256"}
    )
    session_manager.link_authorization_code(sid, "auth_code_TEST_OK")

    r = client.post(
        "/oid4vc/token",
        data={
            "grant_type": "authorization_code",
            "code": "auth_code_TEST_OK",
            "code_verifier": verifier,
        },
    )
    assert r.status_code == 200
    assert "access_token" in r.json()


def test_token_authorization_code_con_pkce_incorrecto_devuelve_400(client):
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = PKCEValidator.generate_code_challenge(verifier, "S256")

    sid = session_manager.create_session({"student_name": "Ada"})
    session_manager.link_authorization_request(
        sid, {"code_challenge": challenge, "code_challenge_method": "S256"}
    )
    session_manager.link_authorization_code(sid, "auth_code_TEST_BAD")

    r = client.post(
        "/oid4vc/token",
        data={
            "grant_type": "authorization_code",
            "code": "auth_code_TEST_BAD",
            "code_verifier": "verifier-que-no-corresponde",
        },
    )
    assert r.status_code == 400


# =============================================================================
# /oid4vc/credential — puertas de seguridad de la emisión
# =============================================================================

def test_credential_sin_authorization_devuelve_401(client):
    r = client.post("/oid4vc/credential", json={})
    assert r.status_code == 401


def test_credential_token_invalido_devuelve_401(client):
    r = client.post(
        "/oid4vc/credential",
        headers={"Authorization": "Bearer access_inexistente"},
        json={},
    )
    assert r.status_code == 401


def test_credential_token_valido_sin_proof_devuelve_400(client):
    sid = session_manager.create_session({"student_name": "Ada", "course_name": "BC101"})
    session_manager.link_access_token(sid, "access_TESTTOKEN", "nonce-123")

    r = client.post(
        "/oid4vc/credential",
        headers={"Authorization": "Bearer access_TESTTOKEN"},
        json={},  # sin 'proof' -> debe rechazarse
    )
    assert r.status_code == 400
