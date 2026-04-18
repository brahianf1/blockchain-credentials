# Backend — Microcredenciales UTN

Emisión y verificación de credenciales W3C/OpenID4VC para microcredenciales
académicas, con anclaje público en Hyperledger Indy (VON Network).

## Componentes

| Servicio | Descripción | Puerto interno |
| --- | --- | --- |
| `python-controller` | API FastAPI. Orquesta Moodle, ACA-Py y el ledger. | 3000 |
| `acapy-agent` | Aries Cloud Agent (ACA-Py). Firma credenciales y publica el DID del emisor en Indy. | 8020 admin / 8021 público |
| `portal-db` | PostgreSQL 15 del portal de alumnos. | 5432 |
| `moodle-app` + `moodle-db` | LMS y su base de datos. | 80 / 5432 |

La red blockchain pública se mantiene fuera de este `docker-compose.yml`: los
4 nodos de VON Network y su browser web se despliegan una sola vez en el VPS
mediante los scripts de `backend/config_examples/`. El agente ACA-Py se
conecta a ella a través de la red Docker externa `von_von`.

## Arquitectura interna del controller

```
backend/controller/
├── app.py                      # Entry point FastAPI + wiring de routers
├── blockchain/                 # Abstracción de ledger (port/adapter)
│   ├── base.py                 #   LedgerClient, LedgerStatus, CredentialAnchor
│   ├── indy_client.py          #   IndyLedgerClient (ACA-Py admin API)
│   ├── null_client.py          #   NullLedgerClient (tests/dev)
│   └── factory.py              #   get_ledger_client() — selector singleton
├── openid4vc/                  # Routers y lógica OpenID4VCI (SD-JWT / JWT-VC)
├── portal/                     # Portal de alumnos (auth JWT + endpoints)
│   ├── auth_endpoints.py
│   ├── credential_endpoints.py
│   ├── public_endpoints.py     # Verificación pública (no requiere auth)
│   ├── stats_endpoints.py
│   ├── moodle_queries.py       # Lectura READ-ONLY a la BD de Moodle
│   ├── models.py               # SQLAlchemy (portal_students, etc.)
│   └── schemas.py              # Pydantic
├── utils/hashing.py            # Hash canónico SHA-256 de credencial
├── qr_endpoints.py / qr_generator.py
├── storage.py, session_manager.py, pkce_validator.py
└── alembic/                    # Migraciones de la BD del portal
```

## Capa blockchain (`blockchain/`)

Toda interacción con el ledger pasa por la interfaz `LedgerClient`, lo que
deja al resto del código agnóstico al stack subyacente.

- `BLOCKCHAIN_DRIVER=indy` (por defecto) usa `IndyLedgerClient`, que consulta
  la admin API de ACA-Py (`ACAPY_ADMIN_URL`) para resolver salud del ledger
  y DID del emisor.
- `BLOCKCHAIN_DRIVER=null` devuelve `UNAVAILABLE` en todas las consultas; se
  usa en tests y entornos sin ledger.

El `CredentialAnchor` expone el ciclo de vida de una credencial respecto al
ledger público mediante `AnchorStatus`:

```
PENDING_ANCHORING  ──▶  ANCHORED  ──▶  REVOKED
       │                              │
       └──────────▶ UNAVAILABLE ◀─────┘
```

El pipeline completo de anclaje on-ledger (schemas, cred-defs, revocation
registry entries por emisión) se incorpora progresivamente en fases
posteriores; en la fase actual `IndyLedgerClient.resolve_anchor()` reporta
`PENDING_ANCHORING` de forma honesta.

## Flujo de emisión (resumen)

1. Un alumno finaliza un curso en Moodle.
2. El plugin de Moodle dispara `POST /api/credenciales` (compat) o el flujo
   OpenID4VCI al controller.
3. El controller genera la oferta (QR), arma la credencial firmada y delega
   en ACA-Py la emisión al wallet del alumno.
4. La verificación pública (`GET /api/public/verify/{hash}`) resuelve la
   credencial por hash consultando Moodle y adjunta la evidencia on-ledger
   devuelta por el `LedgerClient` activo.

## Variables de entorno

Ver `.env.example` en la raíz del repositorio.

## Scripts de bootstrap del VPS

Se encuentran en `backend/config_examples/` y se ejecutan UNA sola vez en el
host del VPS antes del primer despliegue con Dokploy:

- `setup-von-network.sh` — crea la red Indy local (4 nodos + browser).
- `generate_openid_keys.sh` — genera el par ECDSA P-256 para OpenID4VC.
- `cleanup-von.sh` — destruye la red Indy para redespliegues limpios.
