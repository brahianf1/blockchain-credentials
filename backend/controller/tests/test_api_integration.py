"""Pruebas de INTEGRACIÓN de la API del portal (FastAPI TestClient).

Simulan las peticiones que hace el frontend a los endpoints reales y validan los
tres objetivos del plan de pruebas del proyecto:

  * Seguridad de la API: autenticación (401), autorización por rol (403) y la
    regla de privacidad de la verificación pública.
  * Robustez del backend: respuestas correctas ante entradas válidas e inválidas
    (200 / 401 / 403 / 404 / 409 / 422).
  * Correcta comunicación con la red blockchain: la API expone fielmente lo que
    devuelve el ledger, usando un ledger SIMULADO (no requiere un nodo Besu).

Todo corre sin Postgres ni Besu: la base del portal es SQLite en memoria, la base
de Moodle se reemplaza por mocks de ``moodle_queries`` y el ledger por un
``FakeLedger``. Las dependencias inyectadas se sustituyen con
``app.dependency_overrides``; lo que no es dependencia, con ``monkeypatch``.
"""
from datetime import datetime, timezone

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import app
from blockchain import get_ledger_client
from blockchain.base import (
    AnchorStatus,
    CredentialAnchor,
    LedgerClient,
    LedgerHealth,
    LedgerStatus,
)
from blockchain.web3_client import besu_client
from portal import moodle_queries
from portal.auth import create_portal_jwt, hash_password
from portal.config import MOODLE_PORTAL_JWT_SECRET
from portal.database import Base
from portal.dependencies import get_moodle_db, get_portal_db
from portal.models import CredentialAnchor as CredentialAnchorModel
from portal.models import CredentialVisibility, PortalStudent, RevocationAudit
from utils.hashing import compute_credential_hash

# --- Base de datos SQLite en memoria (una sola conexión compartida) ----------
engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


# --- Ledger simulado (implementa el puerto LedgerClient) ---------------------
class FakeLedger(LedgerClient):
    """Ledger de mentira y configurable: no toca ningún nodo Besu."""

    def __init__(self):
        self.anchor = None
        self.status = LedgerStatus(
            name="Fake Besu Net",
            health=LedgerHealth.HEALTHY,
            issuer_did="did:ethr:0xFAKEISSUER",
            explorer_url="https://explorer.test",
        )

    async def get_status(self):
        return self.status

    async def resolve_anchor(self, credential_hash):
        return self.anchor


_fake_ledger = FakeLedger()


# --- Fixtures ----------------------------------------------------------------
@pytest.fixture
def db_session():
    """BD limpia por test; la MISMA sesión la usan el test y los endpoints."""
    Base.metadata.create_all(bind=engine)
    _fake_ledger.anchor = None  # reset del ledger entre tests
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def fake_ledger():
    return _fake_ledger


@pytest.fixture
def client(db_session):
    """TestClient con las dependencias sustituidas. Sin ``with`` para no disparar
    el evento startup (que tocaría Postgres)."""

    def _portal_db():
        yield db_session

    def _moodle_db():
        yield None  # las queries a Moodle se mockean; la sesión no se usa

    app.dependency_overrides[get_portal_db] = _portal_db
    app.dependency_overrides[get_moodle_db] = _moodle_db
    app.dependency_overrides[get_ledger_client] = lambda: _fake_ledger
    yield TestClient(app)
    app.dependency_overrides.clear()


# --- Helpers -----------------------------------------------------------------
def make_student(db, *, role="student", email="ada@utn.edu", moodle_user_id=42, password=None):
    student = PortalStudent(
        moodle_user_id=moodle_user_id,
        email=email,
        full_name="Ada Lovelace",
        role=role,
        is_active=True,
        password_hash=hash_password(password) if password else None,
    )
    db.add(student)
    db.commit()
    db.refresh(student)
    return student


def auth_headers(student):
    token = create_portal_jwt(student.id, student.email)
    return {"Authorization": f"Bearer {token}"}


def moodle_row(**over):
    """Fila canónica como la que devolvería ``moodle_queries`` desde la BD de Moodle."""
    row = {
        "id": 1, "userid": 42, "courseid": 7,
        "connection_id": "conn-1", "invitation_url": None, "qr_code_base64": None,
        "status": "issued", "timecreated": 1749556800, "timemodified": None,
        "course_name": "Curso de Blockchain", "course_shortname": "BC101",
        "firstname": "Ada", "lastname": "Lovelace",
        "student_email": "ada@utn.edu", "email": "ada@utn.edu",
    }
    row.update(over)
    return row


def expected_hash(row, grade="Aprobado"):
    completion = datetime.fromtimestamp(row["timecreated"], tz=timezone.utc).isoformat()
    return compute_credential_hash(
        student_id=str(row["userid"]),
        course_id=str(row["courseid"]),
        completion_date=completion,
        grade=grade,
    )


# =============================================================================
# A. SEGURIDAD DE LA API
# =============================================================================

def test_me_sin_token_devuelve_401(client):
    assert client.get("/api/portal/auth/me").status_code == 401


def test_me_con_token_invalido_devuelve_401(client):
    r = client.get("/api/portal/auth/me", headers={"Authorization": "Bearer no-es-un-jwt"})
    assert r.status_code == 401


def test_login_password_incorrecta_devuelve_401(client, db_session):
    make_student(db_session, password="Correcta123")
    r = client.post("/api/portal/auth/login", json={"email": "ada@utn.edu", "password": "Incorrecta1"})
    assert r.status_code == 401


def test_login_cuenta_sin_password_devuelve_401(client, db_session):
    make_student(db_session, password=None)
    r = client.post("/api/portal/auth/login", json={"email": "ada@utn.edu", "password": "Loquesea1"})
    assert r.status_code == 401


def test_admin_endpoint_con_usuario_no_admin_devuelve_403(client, db_session):
    student = make_student(db_session, role="student")
    r = client.get("/api/admin/credentials", headers=auth_headers(student))
    assert r.status_code == 403


def test_revoke_con_usuario_no_admin_devuelve_403(client, db_session):
    student = make_student(db_session, role="student")
    r = client.post(
        "/api/admin/credentials/revoke",
        headers=auth_headers(student),
        json={"credential_hash": "a" * 64, "reason": "motivo de prueba"},
    )
    assert r.status_code == 403


def test_moodle_callback_token_invalido_devuelve_401(client):
    r = client.post("/api/portal/auth/moodle-callback", json={"token": "token-invalido-xxxxx"})
    assert r.status_code == 401


def test_public_verify_credencial_privada_oculta_el_nombre(client, db_session, fake_ledger, monkeypatch):
    row = moodle_row()
    monkeypatch.setattr(moodle_queries, "get_all_credential_hashes", lambda *_a, **_k: [row])
    monkeypatch.setattr(moodle_queries, "get_user_grade", lambda *_a, **_k: None)
    fake_ledger.anchor = CredentialAnchor(status=AnchorStatus.ANCHORED, network="Fake Besu Net")

    r = client.get(f"/api/public/verify/{expected_hash(row)}")
    data = r.json()

    assert r.status_code == 200
    assert data["valid"] is True
    assert data["verdict"] == "valid"
    assert data["student_name"] is None              # privada => sin datos personales
    assert data["course_name"] == "Curso de Blockchain"


def test_public_verify_credencial_publica_muestra_el_nombre(client, db_session, fake_ledger, monkeypatch):
    row = moodle_row()
    monkeypatch.setattr(moodle_queries, "get_all_credential_hashes", lambda *_a, **_k: [row])
    monkeypatch.setattr(moodle_queries, "get_user_grade", lambda *_a, **_k: None)
    fake_ledger.anchor = CredentialAnchor(status=AnchorStatus.ANCHORED, network="Fake Besu Net")

    h = expected_hash(row)
    db_session.add(
        CredentialVisibility(moodle_user_id=row["userid"], credential_hash=h, is_public=True)
    )
    db_session.commit()

    data = client.get(f"/api/public/verify/{h}").json()
    assert data["valid"] is True
    assert data["verdict"] == "valid"
    assert data["student_name"] == "Ada Lovelace"     # pública => nombre visible


def test_public_verify_credencial_revocada_no_es_valida(client, db_session, fake_ledger, monkeypatch):
    """Regla central para terceros: una credencial revocada on-chain NO es
    válida, aunque exista en el registro institucional y sea pública."""
    row = moodle_row()
    monkeypatch.setattr(moodle_queries, "get_all_credential_hashes", lambda *_a, **_k: [row])
    monkeypatch.setattr(moodle_queries, "get_user_grade", lambda *_a, **_k: None)
    fake_ledger.anchor = CredentialAnchor(
        status=AnchorStatus.REVOKED,
        network="Fake Besu Net",
        ledger_timestamp="2026-06-20T10:00:00+00:00",
    )

    h = expected_hash(row)
    db_session.add(
        CredentialVisibility(moodle_user_id=row["userid"], credential_hash=h, is_public=True)
    )
    db_session.commit()

    data = client.get(f"/api/public/verify/{h}").json()
    assert data["valid"] is False                    # revocada => NO válida
    assert data["verdict"] == "revoked"
    assert data["student_name"] is None              # revocada => no se exponen datos personales
    assert data["revoked_at"] == "2026-06-20T10:00:00+00:00"


def test_public_verify_sin_anclaje_confirmado_no_es_valida(client, db_session, fake_ledger, monkeypatch):
    """Si no hay prueba on-chain confirmada, el veredicto es NOT_ANCHORED y la
    credencial no se reporta como válida."""
    row = moodle_row()
    monkeypatch.setattr(moodle_queries, "get_all_credential_hashes", lambda *_a, **_k: [row])
    monkeypatch.setattr(moodle_queries, "get_user_grade", lambda *_a, **_k: None)
    fake_ledger.anchor = None  # el ledger no tiene registro del hash

    data = client.get(f"/api/public/verify/{expected_hash(row)}").json()
    assert data["valid"] is False
    assert data["verdict"] == "not_anchored"


# =============================================================================
# B. ROBUSTEZ DEL BACKEND
# =============================================================================

def test_login_correcto_devuelve_token(client, db_session):
    make_student(db_session, password="Correcta123")
    r = client.post("/api/portal/auth/login", json={"email": "ada@utn.edu", "password": "Correcta123"})
    body = r.json()
    assert r.status_code == 200
    assert body["access_token"]
    assert body["student"]["email"] == "ada@utn.edu"


def test_moodle_callback_crea_y_actualiza_sin_duplicar(client, db_session):
    token = jwt.encode(
        {"moodle_user_id": 99, "email": "neo@utn.edu", "full_name": "Neo Anderson", "is_admin": False},
        MOODLE_PORTAL_JWT_SECRET,
        algorithm="HS256",
    )
    r1 = client.post("/api/portal/auth/moodle-callback", json={"token": token})
    assert r1.status_code == 200
    assert r1.json()["student"]["moodle_user_id"] == 99

    r2 = client.post("/api/portal/auth/moodle-callback", json={"token": token})
    assert r2.status_code == 200
    assert db_session.query(PortalStudent).filter(PortalStudent.moodle_user_id == 99).count() == 1


def test_me_con_token_valido_devuelve_perfil(client, db_session):
    student = make_student(db_session)
    r = client.get("/api/portal/auth/me", headers=auth_headers(student))
    assert r.status_code == 200
    assert r.json()["email"] == "ada@utn.edu"


def test_listar_credenciales_calcula_hash(client, db_session, monkeypatch):
    student = make_student(db_session)
    monkeypatch.setattr(moodle_queries, "get_credentials_for_user", lambda *_a, **_k: [moodle_row()])
    monkeypatch.setattr(moodle_queries, "get_user_grade", lambda *_a, **_k: None)

    r = client.get("/api/portal/credentials", headers=auth_headers(student))
    creds = r.json()
    assert r.status_code == 200
    assert len(creds) == 1
    assert len(creds[0]["credential_hash"]) == 64


def test_get_credencial_inexistente_devuelve_404(client, db_session, monkeypatch):
    student = make_student(db_session)
    monkeypatch.setattr(moodle_queries, "get_credential_by_id", lambda *_a, **_k: None)
    r = client.get("/api/portal/credentials/999", headers=auth_headers(student))
    assert r.status_code == 404


def test_public_verify_hash_desconocido_devuelve_invalido(client, db_session, monkeypatch):
    monkeypatch.setattr(moodle_queries, "get_all_credential_hashes", lambda *_a, **_k: [])
    r = client.get("/api/public/verify/" + "f" * 64)
    assert r.status_code == 200
    assert r.json()["valid"] is False
    assert r.json()["verdict"] == "not_found"


def test_set_password_debil_devuelve_422(client, db_session):
    student = make_student(db_session)
    r = client.post("/api/portal/auth/set-password", headers=auth_headers(student), json={"password": "debil"})
    assert r.status_code == 422


def test_set_password_fuerte_devuelve_200(client, db_session):
    student = make_student(db_session)
    r = client.post("/api/portal/auth/set-password", headers=auth_headers(student), json={"password": "Fuerte123"})
    assert r.status_code == 200
    assert r.json()["has_password"] is True


def test_toggle_visibility_crea_la_fila(client, db_session):
    student = make_student(db_session)
    h = "a" * 64
    r = client.patch(
        "/api/portal/credentials/visibility",
        headers=auth_headers(student),
        json={"credential_hash": h, "is_public": True},
    )
    assert r.status_code == 200
    row = (
        db_session.query(CredentialVisibility)
        .filter(CredentialVisibility.credential_hash == h)
        .first()
    )
    assert row is not None and row.is_public is True


def test_stats_devuelve_totales(client, db_session, monkeypatch):
    student = make_student(db_session)
    monkeypatch.setattr(
        moodle_queries,
        "count_credentials_by_status",
        lambda *_a, **_k: {"pending": 1, "issued": 2, "claimed": 3},
    )
    r = client.get("/api/portal/stats", headers=auth_headers(student))
    assert r.status_code == 200
    assert r.json()["total_credentials"] == 6


def test_revoke_hash_inexistente_devuelve_404(client, db_session):
    admin = make_student(db_session, role="admin")
    r = client.post(
        "/api/admin/credentials/revoke",
        headers=auth_headers(admin),
        json={"credential_hash": "b" * 64, "reason": "fraude"},
    )
    assert r.status_code == 404


def test_revoke_credencial_ya_revocada_devuelve_409(client, db_session):
    admin = make_student(db_session, role="admin")
    h = "c" * 64
    db_session.add(CredentialAnchorModel(credential_hash=h, revoked=True))
    db_session.commit()
    r = client.post(
        "/api/admin/credentials/revoke",
        headers=auth_headers(admin),
        json={"credential_hash": h, "reason": "fraude"},
    )
    assert r.status_code == 409


# =============================================================================
# C. CORRECTA COMUNICACIÓN CON LA RED BLOCKCHAIN (ledger simulado)
# =============================================================================

def test_verify_credencial_refleja_estado_anchored(client, db_session, fake_ledger, monkeypatch):
    student = make_student(db_session)
    monkeypatch.setattr(moodle_queries, "get_credential_by_id", lambda *_a, **_k: moodle_row())
    monkeypatch.setattr(moodle_queries, "get_user_grade", lambda *_a, **_k: None)
    fake_ledger.anchor = CredentialAnchor(
        status=AnchorStatus.ANCHORED,
        network="Fake Besu Net",
        txn_id="0xabc",
        explorer_url="https://explorer.test/tx/0xabc",
    )

    r = client.get("/api/portal/credentials/1/verify", headers=auth_headers(student))
    bc = r.json()["blockchain"]
    assert r.status_code == 200
    assert bc["status"] == "anchored"
    assert bc["txn_id"] == "0xabc"


def test_verify_credencial_refleja_estado_revoked(client, db_session, fake_ledger, monkeypatch):
    student = make_student(db_session)
    monkeypatch.setattr(moodle_queries, "get_credential_by_id", lambda *_a, **_k: moodle_row())
    monkeypatch.setattr(moodle_queries, "get_user_grade", lambda *_a, **_k: None)
    fake_ledger.anchor = CredentialAnchor(status=AnchorStatus.REVOKED, network="Fake Besu Net")

    r = client.get("/api/portal/credentials/1/verify", headers=auth_headers(student))
    assert r.json()["blockchain"]["status"] == "revoked"


def test_public_verify_incluye_evidencia_blockchain(client, db_session, fake_ledger, monkeypatch):
    row = moodle_row()
    monkeypatch.setattr(moodle_queries, "get_all_credential_hashes", lambda *_a, **_k: [row])
    monkeypatch.setattr(moodle_queries, "get_user_grade", lambda *_a, **_k: None)
    fake_ledger.anchor = CredentialAnchor(
        status=AnchorStatus.ANCHORED,
        network="Fake Besu Net",
        explorer_url="https://explorer.test/tx/0x1",
    )

    bc = client.get(f"/api/public/verify/{expected_hash(row)}").json()["blockchain"]
    assert bc is not None
    assert bc["status"] == "anchored"
    assert bc["explorer_url"] == "https://explorer.test/tx/0x1"


def test_public_blockchain_registry_usa_el_ledger(client, db_session, fake_ledger):
    r = client.get("/api/public/blockchain/registry")
    assert r.status_code == 200
    assert r.json()["network"] == "Fake Besu Net"


def test_revoke_ok_marca_revocada_y_devuelve_tx(client, db_session, monkeypatch):
    admin = make_student(db_session, role="admin")
    h = "d" * 64
    db_session.add(CredentialAnchorModel(credential_hash=h, revoked=False))
    db_session.commit()

    async def fake_revoke(_hash):
        return "0xTXHASH"

    monkeypatch.setattr(besu_client, "revoke_credential_hash", fake_revoke)

    r = client.post(
        "/api/admin/credentials/revoke",
        headers=auth_headers(admin),
        json={"credential_hash": h, "reason": "fraude comprobado"},
    )
    body = r.json()
    assert r.status_code == 200
    assert body["success"] is True
    assert body["tx_hash"] == "0xTXHASH"

    anchor = (
        db_session.query(CredentialAnchorModel)
        .filter(CredentialAnchorModel.credential_hash == h)
        .first()
    )
    assert anchor.revoked is True
    assert anchor.revocation_txn_id == "0xTXHASH"

    # La revocación deja un registro de auditoría inmutable (quién/por qué/tx).
    audit = (
        db_session.query(RevocationAudit)
        .filter(RevocationAudit.credential_hash == h)
        .first()
    )
    assert audit is not None
    assert audit.reason == "fraude comprobado"
    assert audit.revoked_by_email == "ada@utn.edu"
    assert audit.revocation_txn_id == "0xTXHASH"


def test_listar_auditoria_revocaciones_requiere_admin(client, db_session):
    student = make_student(db_session, role="student")
    r = client.get("/api/admin/credentials/revocations", headers=auth_headers(student))
    assert r.status_code == 403


def test_listar_auditoria_revocaciones_devuelve_registros(client, db_session):
    admin = make_student(db_session, role="admin")
    db_session.add(
        RevocationAudit(
            credential_hash="d" * 64,
            reason="fraude comprobado",
            revocation_txn_id="0xTXHASH",
            revoked_by_id=admin.id,
            revoked_by_email=admin.email,
        )
    )
    db_session.commit()

    r = client.get("/api/admin/credentials/revocations", headers=auth_headers(admin))
    body = r.json()
    assert r.status_code == 200
    assert len(body) == 1
    assert body[0]["credential_hash"] == "d" * 64
    assert body[0]["reason"] == "fraude comprobado"
    assert body[0]["revoked_by_email"] == "ada@utn.edu"


def test_revoke_falla_si_la_blockchain_no_responde_devuelve_502(client, db_session, monkeypatch):
    """Gestión de errores en la comunicación con la blockchain: si el nodo no
    devuelve transacción, la API responde 502 y NO marca la credencial revocada."""
    admin = make_student(db_session, role="admin")
    h = "e" * 64
    db_session.add(CredentialAnchorModel(credential_hash=h, revoked=False))
    db_session.commit()

    async def fake_revoke_sin_respuesta(_hash):
        return None  # la blockchain no responde / no ancló la credencial

    monkeypatch.setattr(besu_client, "revoke_credential_hash", fake_revoke_sin_respuesta)

    r = client.post(
        "/api/admin/credentials/revoke",
        headers=auth_headers(admin),
        json={"credential_hash": h, "reason": "fraude comprobado"},
    )
    assert r.status_code == 502

    anchor = (
        db_session.query(CredentialAnchorModel)
        .filter(CredentialAnchorModel.credential_hash == h)
        .first()
    )
    assert anchor.revoked is False  # no se revoca si falló el on-chain
