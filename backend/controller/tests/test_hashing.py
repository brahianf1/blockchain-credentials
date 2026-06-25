"""Pruebas unitarias del hash canónico de credencial.

``compute_credential_hash`` es la FUENTE DE VERDAD del sistema: el mismo hash
se ancla on-chain en Hyperledger Besu y también lo calcula, por separado, el
plugin de Moodle (PHP). Por eso ``EXPECTED_HASH`` está replicado idéntico en
``moodle/moodle-plugin/credenciales/tests/lib_test.php``: ambos lenguajes DEBEN
producir el mismo valor o la verificación on-chain falla. Es un "contrato"
entre Python y PHP que cada lado verifica por su cuenta.
"""
from utils.hashing import compute_credential_hash

# --- Fixture compartido con el test de PHP (lib_test.php) -------------------
# NO modificar sin actualizar también el lado PHP.
FIXTURE = {
    "student_id": "42",
    "course_id": "7",
    "completion_date": "2026-06-10T12:00:00+00:00",
    "grade": "Aprobado",
}
EXPECTED_HASH = "f05c5a74f693c09731b130a39dcbeec9904a1e2ea366b8a5a61176596403dbea"


def test_hash_vector_conocido_contrato_con_moodle():
    """El hash del fixture coincide con la constante compartida con Moodle/PHP."""
    assert compute_credential_hash(**FIXTURE) == EXPECTED_HASH


def test_hash_es_determinista():
    """La misma entrada produce siempre el mismo hash."""
    assert compute_credential_hash(**FIXTURE) == compute_credential_hash(**FIXTURE)


def test_hash_tiene_64_caracteres_hex():
    """SHA-256 en hexadecimal siempre tiene 64 caracteres [0-9a-f]."""
    h = compute_credential_hash(**FIXTURE)
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_hash_sensible_a_la_nota():
    """Cambiar la nota cambia el hash (sin colisiones triviales)."""
    otra = {**FIXTURE, "grade": "10.0"}
    assert compute_credential_hash(**otra) != EXPECTED_HASH


def test_hash_sensible_al_curso():
    """Cambiar el curso cambia el hash."""
    otro = {**FIXTURE, "course_id": "8"}
    assert compute_credential_hash(**otro) != EXPECTED_HASH
