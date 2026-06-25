"""Pruebas unitarias del generador de códigos QR (qr_generator.py).

El QR codifica la URL de la oferta de credencial (OpenID4VCI) o de la
verificación pública que el alumno escanea con su wallet.
"""
from qr_generator import QRGenerator


def test_validate_qr_content_acepta_http_y_https():
    qr = QRGenerator()
    assert qr.validate_qr_content("http://utn.edu") is True
    assert qr.validate_qr_content("https://utn.edu/verify/abc") is True


def test_validate_qr_content_rechaza_vacio_y_esquemas_no_http():
    qr = QRGenerator()
    assert qr.validate_qr_content("") is False
    assert qr.validate_qr_content("ftp://x") is False
    assert qr.validate_qr_content("javascript:alert(1)") is False


def test_generate_qr_devuelve_data_uri_png():
    qr = QRGenerator()
    img = qr.generate_qr("https://utn.edu/verify/abc")
    assert img.startswith("data:image/png;base64,")
    assert len(img) > 100


def test_generate_qr_distinto_para_urls_distintas():
    qr = QRGenerator()
    assert qr.generate_qr("https://utn.edu/a") != qr.generate_qr("https://utn.edu/b")
