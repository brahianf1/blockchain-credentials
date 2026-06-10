"""Pruebas unitarias de la resolución y el despacho de formatos de credencial.

Solo se prueba la lógica PURA de decisión (qué formato usar / despachar), sin
generar credenciales reales (eso requeriría firmar con claves y es territorio
de otra prueba). ``conftest.py`` inyecta claves efímeras para que el import de
``openid4vc`` no falle.
"""
import pytest

from openid4vc.credential_formatters import (
    build_credential_response,
    format_credential,
    resolve_format,
)


def test_resolve_format_explicito_en_request():
    assert resolve_format({"format": "vc+sd-jwt"}) == "vc+sd-jwt"


def test_resolve_format_alias_sd_jwt():
    # 'sd-jwt' es un alias de 'vc+sd-jwt'.
    assert resolve_format({"format": "sd-jwt"}) == "vc+sd-jwt"


def test_resolve_format_alias_jwt_vc():
    # 'jwt_vc' es un alias de 'jwt_vc_json'.
    assert resolve_format({"format": "jwt_vc"}) == "jwt_vc_json"


def test_resolve_format_por_config_id():
    assert resolve_format({"credential_configuration_id": "UniversityDegree"}) == "vc+sd-jwt"


def test_resolve_format_default_cuando_falta_todo():
    # Sin pistas, cae al formato por defecto del registro.
    assert resolve_format({}) == "vc+sd-jwt"


def test_format_credential_formato_invalido_lanza_valueerror():
    with pytest.raises(ValueError):
        format_credential("formato-inexistente")


def test_build_credential_response_estructura():
    resp = build_credential_response("CRED-STR", "vc+sd-jwt")

    # Draft 13: campos planos.
    assert resp["format"] == "vc+sd-jwt"
    assert resp["credential"] == "CRED-STR"
    # Draft 11/12: arrays envoltorio con el mismo contenido.
    assert resp["credentials"][0] == {"credential": "CRED-STR", "format": "vc+sd-jwt"}
    assert resp["credential_responses"][0] == {"credential": "CRED-STR", "format": "vc+sd-jwt"}
    # Nonce de un solo uso presente.
    assert "c_nonce" in resp
    assert resp["c_nonce_expires_in"] == 300


def test_build_credential_response_nonce_es_unico():
    a = build_credential_response("X", "vc+sd-jwt")
    b = build_credential_response("X", "vc+sd-jwt")
    assert a["c_nonce"] != b["c_nonce"]
