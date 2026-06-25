"""Pruebas unitarias de las reglas de validación de entrada (portal/schemas.py).

Los esquemas Pydantic son la primera línea de reglas de negocio sobre los datos
que entran al portal: política de contraseñas, formato de email, longitudes.
"""
import pytest
from pydantic import ValidationError

from portal.schemas import (
    LoginRequest,
    MoodleCallbackRequest,
    SetPasswordRequest,
    VisibilityToggleRequest,
)


# --- Política de contraseñas (>=8, al menos 1 mayúscula y 1 número) ---------

def test_password_valida_se_acepta():
    assert SetPasswordRequest(password="Segura123").password == "Segura123"


def test_password_sin_mayuscula_se_rechaza():
    with pytest.raises(ValidationError):
        SetPasswordRequest(password="segura123")


def test_password_sin_numero_se_rechaza():
    with pytest.raises(ValidationError):
        SetPasswordRequest(password="SeguraSinNumero")


def test_password_demasiado_corta_se_rechaza():
    with pytest.raises(ValidationError):
        SetPasswordRequest(password="Ab1")


# --- Login (email válido + contraseña no vacía) -----------------------------

def test_login_acepta_email_valido():
    assert LoginRequest(email="ada@utn.edu", password="x").email == "ada@utn.edu"


def test_login_rechaza_email_invalido():
    with pytest.raises(ValidationError):
        LoginRequest(email="no-es-un-email", password="x")


def test_login_rechaza_password_vacia():
    with pytest.raises(ValidationError):
        LoginRequest(email="ada@utn.edu", password="")


# --- Otras validaciones de entrada ------------------------------------------

def test_moodle_callback_rechaza_token_corto():
    # El token JWT de Moodle debe tener al menos 10 caracteres.
    with pytest.raises(ValidationError):
        MoodleCallbackRequest(token="corto")


def test_visibility_rechaza_hash_demasiado_largo():
    # credential_hash admite como máximo 64 caracteres (largo de un SHA-256 hex).
    with pytest.raises(ValidationError):
        VisibilityToggleRequest(credential_hash="a" * 65, is_public=True)


def test_visibility_acepta_datos_validos():
    req = VisibilityToggleRequest(credential_hash="a" * 64, is_public=True)
    assert req.is_public is True
