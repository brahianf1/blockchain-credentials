"""Pruebas unitarias de las reglas de negocio del estado de la credencial.

`blockchain/base.py` define el ciclo de vida de una credencial respecto al
ledger y la **regla central de verificación**: decidir si está válida,
revocada o no emitida a partir del estado on-chain. Es lógica pura, sin
acceso a la blockchain ni a la base de datos.
"""
import pytest

from blockchain.base import AnchorStatus, CredentialAnchor, state_to_anchor_status


# --- Regla central: estado on-chain -> válida / revocada / no emitida -------

def test_estado_valido_es_anchored():
    # 1 = Valid en el smart contract.
    assert state_to_anchor_status(1) == AnchorStatus.ANCHORED


def test_estado_revocado_es_revoked():
    # 2 = Revoked.
    assert state_to_anchor_status(2) == AnchorStatus.REVOKED


def test_estado_no_emitido_es_none():
    # 0 = NotIssued -> la credencial no existe en el ledger.
    assert state_to_anchor_status(0) is None


def test_estado_desconocido_es_unavailable():
    # Cualquier estado inesperado se trata como "no disponible" (defensivo).
    assert state_to_anchor_status(99) == AnchorStatus.UNAVAILABLE


# --- Ciclo de vida: constructores de CredentialAnchor -----------------------

def test_pending_tiene_estado_pending_anchoring():
    anchor = CredentialAnchor.pending(network="UTN Chain")
    assert anchor.status == AnchorStatus.PENDING_ANCHORING
    assert anchor.network == "UTN Chain"


def test_unavailable_tiene_estado_unavailable():
    anchor = CredentialAnchor.unavailable(network="UTN Chain")
    assert anchor.status == AnchorStatus.UNAVAILABLE


def test_credential_anchor_es_inmutable():
    # frozen dataclass: la evidencia de una credencial no se puede alterar.
    anchor = CredentialAnchor.pending(network="UTN Chain")
    with pytest.raises(Exception):
        anchor.status = AnchorStatus.ANCHORED


def test_valores_serializados_del_ciclo_de_vida():
    # Los valores string que consume el frontend para mostrar el estado.
    assert AnchorStatus.ANCHORED.value == "anchored"
    assert AnchorStatus.REVOKED.value == "revoked"
    assert AnchorStatus.PENDING_ANCHORING.value == "pending_anchoring"
    assert AnchorStatus.UNAVAILABLE.value == "unavailable"
