"""Pruebas unitarias del registro de configuraciones de credenciales.

`credential_registry.py` es la "fuente única de verdad" de los formatos y
claims soportados. Estas pruebas verifican el acceso al registro y la
transformación de la configuración interna a la metadata pública que exige
la especificación OpenID4VCI (distinta según el formato).
"""
from openid4vc.credential_registry import (
    get_all_config_ids,
    get_config,
    get_configurations_for_metadata,
    get_default_format,
    get_vct_claims,
)


def test_get_all_config_ids_incluye_university_degree():
    assert "UniversityDegree" in get_all_config_ids()


def test_get_config_existente_y_inexistente():
    assert get_config("UniversityDegree") is not None
    assert get_config("NoExiste") is None


def test_get_default_format():
    assert get_default_format("UniversityDegree") == "vc+sd-jwt"
    # Un id desconocido cae al formato por defecto.
    assert get_default_format("NoExiste") == "vc+sd-jwt"


def test_get_vct_claims_tiene_forma_sdjwt():
    claims = get_vct_claims()
    assert isinstance(claims, list) and len(claims) > 0
    for c in claims:
        assert "path" in c
        assert c["sd"] == "allowed"


def test_metadata_sdjwt_quita_campos_de_otro_formato():
    meta = get_configurations_for_metadata("https://issuer.test")["UniversityDegree"]
    # En vc+sd-jwt no deben aparecer campos propios de jwt_vc_json.
    assert "credential_definition" not in meta
    assert "claims" not in meta


def test_metadata_sdjwt_expone_credentialsubject():
    meta = get_configurations_for_metadata("https://issuer.test")["UniversityDegree"]
    assert "credentialSubject" in meta


def test_metadata_vct_se_construye_como_url_absoluta():
    meta = get_configurations_for_metadata("https://issuer.test")["UniversityDegree"]
    assert meta["vct"] == "https://issuer.test/UniversityDegree"
