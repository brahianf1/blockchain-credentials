"""Pruebas unitarias de la normalización de DIDs.

``did_utils`` es un módulo puro (sin dependencias), pero importarlo como
``blockchain.did_utils`` dispararía ``blockchain/__init__.py``, que arrastra
SQLAlchemy / psycopg2 / web3. Para mantener esta prueba liviana y autocontenida
cargamos el archivo directamente por ruta, sin ejecutar el ``__init__`` del
paquete. (Es una técnica útil para testear lógica pura aislándola de los
efectos secundarios de su paquete.)
"""
import importlib.util
from pathlib import Path

_DID_UTILS_PATH = Path(__file__).resolve().parent.parent / "blockchain" / "did_utils.py"
_spec = importlib.util.spec_from_file_location("did_utils_isolated", _DID_UTILS_PATH)
_did_utils = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_did_utils)

to_raw_did = _did_utils.to_raw_did
to_sov_did = _did_utils.to_sov_did


def test_to_raw_quita_prefijo_sov():
    assert to_raw_did("did:sov:5yUty") == "5yUty"


def test_to_raw_deja_valor_crudo_intacto():
    assert to_raw_did("0xfe3b557e") == "0xfe3b557e"


def test_to_raw_maneja_none():
    assert to_raw_did(None) is None


def test_to_sov_agrega_prefijo_a_valor_crudo():
    assert to_sov_did("5yUty") == "did:sov:5yUty"


def test_to_sov_no_duplica_prefijo_existente():
    assert to_sov_did("did:sov:5yUty") == "did:sov:5yUty"


def test_to_sov_deja_pasar_otros_metodos_did():
    # Un método DID desconocido (ej. did:ethr) no debe ser tocado.
    assert to_sov_did("did:ethr:0xabc") == "did:ethr:0xabc"


def test_roundtrip_raw_sov_raw_es_idempotente():
    raw = "5yUty"
    assert to_raw_did(to_sov_did(raw)) == raw
