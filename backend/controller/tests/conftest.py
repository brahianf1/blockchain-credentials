"""Configuración compartida de pytest para la suite del controller.

Hace tres cosas, todas necesarias para poder importar los módulos del backend
(y la app completa, para los tests de integración) sin secretos reales:

1. Agrega ``backend/controller/`` al ``sys.path`` para que funcionen los
   imports absolutos del proyecto (``from utils.hashing import ...``).

2. Inyecta un par de claves ES256 (P-256) efímero en variables de entorno.
   ``openid4vc/config.py`` carga las claves criptográficas EN EL MOMENTO DE
   IMPORTARSE y lanza excepción si no están presentes; sin esto, cualquier
   test que toque ``openid4vc.*`` fallaría al importar. Generar claves de
   usar y tirar para los tests es, además, una buena práctica: la prueba
   provee su propia configuración descartable y no depende de secretos reales.

3. Setea los secretos JWT del portal (vacíos por defecto en ``portal/config.py``)
   ANTES de importar la app, para que la firma/validación de tokens funcione en
   los tests de integración.
"""
import os
import sys
from pathlib import Path

# 1) Hacer importables los módulos del controller.
_CONTROLLER_DIR = Path(__file__).resolve().parent.parent
if str(_CONTROLLER_DIR) not in sys.path:
    sys.path.insert(0, str(_CONTROLLER_DIR))

# 3) Secretos JWT del portal para los tests de integración (respeta el entorno).
#    Largo >= 32 bytes para no disparar avisos de clave HMAC débil de PyJWT.
os.environ.setdefault("PORTAL_JWT_SECRET", "test-portal-jwt-secret-0123456789abcdef")
os.environ.setdefault("MOODLE_PORTAL_JWT_SECRET", "test-moodle-portal-jwt-secret-0123456789abcdef")


def _inject_ephemeral_es256_keys() -> None:
    """Setea OPENID_PRIVATE_KEY / OPENID_PUBLIC_KEY con un par P-256 efímero."""
    if os.getenv("OPENID_PRIVATE_KEY") and os.getenv("OPENID_PUBLIC_KEY"):
        return  # Respetar claves ya provistas por el entorno.

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    private_key = ec.generate_private_key(ec.SECP256R1())
    os.environ["OPENID_PRIVATE_KEY"] = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    os.environ["OPENID_PUBLIC_KEY"] = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


# 2) Debe ejecutarse al cargar conftest (antes de importar los módulos de test).
_inject_ephemeral_es256_keys()
