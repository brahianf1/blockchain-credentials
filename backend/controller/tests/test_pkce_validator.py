"""Pruebas unitarias del validador PKCE (RFC 7636).

PKCE protege el intercambio de código de autorización en OAuth 2.0 / OpenID4VCI.
Es lógica de seguridad crítica y totalmente determinista: ideal para unitarias.
"""
import pytest

from pkce_validator import PKCEValidator


def test_s256_roundtrip_valido():
    """Un challenge generado desde el verifier valida correctamente (S256)."""
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = PKCEValidator.generate_code_challenge(verifier, "S256")
    assert PKCEValidator.validate(verifier, challenge, "S256") is True


def test_s256_challenge_incorrecto_falla():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert PKCEValidator.validate(verifier, "challenge-que-no-corresponde", "S256") is False


def test_plain_coincide():
    """Método 'plain': verifier == challenge."""
    assert PKCEValidator.validate("abc123", "abc123", "plain") is True
    assert PKCEValidator.validate("abc123", "otro", "plain") is False


def test_verifier_o_challenge_vacio_falla():
    assert PKCEValidator.validate("", "algo", "S256") is False
    assert PKCEValidator.validate("algo", "", "S256") is False


def test_metodo_no_soportado_lanza_valueerror():
    with pytest.raises(ValueError):
        PKCEValidator.validate("abc", "abc", "MD5")


def test_generate_code_challenge_es_determinista():
    verifier = "test-verifier-1234567890"
    a = PKCEValidator.generate_code_challenge(verifier, "S256")
    b = PKCEValidator.generate_code_challenge(verifier, "S256")
    assert a == b
    # El challenge S256 va en base64url SIN padding '='.
    assert "=" not in a
