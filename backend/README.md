# Backend — Microcredenciales Blockchain (UTN)

Emisión y verificación de credenciales W3C Verificables (SD-JWT) vía
OpenID4VCI, con anclaje criptográfico en **Hyperledger Besu** (Smart
Contracts EVM) y exploración pública mediante **Blockscout**.

## Componentes

| Servicio | Descripción | Puerto interno |
| --- | --- | --- |
| `python-controller` | API FastAPI. Orquesta Moodle, OpenID4VCI y la capa blockchain. | 3000 |
| `besu-node` | Nodo Hyperledger Besu (EVM). Ejecuta el `CredentialRegistry` smart contract. | 8545 |
| `blockscout-*` | Explorador de bloques Blockscout (backend + frontend + proxy). | 80 (proxy) |
| `portal-db` | PostgreSQL 15 del portal de alumnos. | 5432 |
| `moodle-app` + `moodle-db` | LMS y su base de datos. | 80 / 5432 |

## Arquitectura interna del controller

```
backend/controller/
├── app.py                      # Entry point FastAPI + wiring de routers
├── blockchain/                 # Abstracción de ledger (port/adapter)
│   ├── base.py                 #   LedgerClient, LedgerStatus, CredentialAnchor
│   ├── besu_ledger_client.py   #   BesuLedgerClient (consulta CredentialRegistry)
│   ├── web3_client.py          #   BesuWeb3Client (deploy + anchor)
│   ├── config.py               #   BlockchainSettings
│   ├── factory.py              #   get_ledger_client() — selector singleton
│   ├── repository.py           #   Persistencia de anchors en portal-db
│   └── did_utils.py            #   Normalización de DIDs
├── openid4vc/                  # Routers y lógica OpenID4VCI (SD-JWT / JWT-VC)
├── portal/                     # Portal de alumnos (auth JWT + endpoints)
│   ├── auth_endpoints.py
│   ├── credential_endpoints.py
│   ├── public_endpoints.py     # Verificación pública (no requiere auth)
│   ├── blockchain_endpoints.py # Estado público del registry on-chain
│   ├── admin_endpoints.py      # Bootstrap y estado del smart contract
│   ├── stats_endpoints.py
│   ├── moodle_queries.py       # Lectura READ-ONLY a la BD de Moodle
│   ├── models.py               # SQLAlchemy (portal_students, anchors, etc.)
│   └── schemas.py              # Pydantic
├── utils/hashing.py            # Hash canónico SHA-256 de credencial
├── qr_generator.py             # QR para ofertas OpenID4VCI
├── storage.py, session_manager.py, pkce_validator.py
└── alembic/                    # Migraciones de la BD del portal
```

## Capa blockchain (`blockchain/`)

Toda interacción con el ledger pasa por la interfaz abstracta `LedgerClient`,
lo que mantiene al resto del código agnóstico al stack subyacente.

- `BesuLedgerClient` — cliente de producción que consulta el smart contract
  `CredentialRegistry.sol` desplegado en Hyperledger Besu. Lee el estado
  on-chain de cada credencial (`Valid` / `Revoked` / `NotIssued`) y construye
  URLs del explorador Blockscout para verificación transparente.

- `BesuWeb3Client` — singleton de bajo nivel que gestiona la conexión Web3
  al nodo Besu, el despliegue perezoso del contrato y la firma de transacciones
  de anclaje (`issueCredential`).

El `CredentialAnchor` expone el ciclo de vida de una credencial respecto al
ledger público mediante `AnchorStatus`:

```
PENDING_ANCHORING  ──▶  ANCHORED  ──▶  REVOKED
       │                              │
       └──────────▶ UNAVAILABLE ◀─────┘
```

## Flujo de emisión (resumen)

1. Un alumno finaliza un curso en Moodle.
2. El plugin de Moodle dispara el flujo OpenID4VCI al controller.
3. El controller genera la oferta (QR), arma la credencial SD-JWT firmada con
   ECDSA P-256 y ancla el hash SHA-256 en el smart contract de Besu.
4. La verificación pública (`GET /api/public/verify/{hash}`) resuelve la
   credencial por hash consultando Moodle y adjunta la evidencia on-chain
   devuelta por el `BesuLedgerClient`, incluyendo un enlace al explorador
   Blockscout para auditoría independiente.

## Variables de entorno

Ver `.env.example` en la raíz del repositorio.

## Scripts de bootstrap del VPS

Se encuentran en `backend/config_examples/` y se ejecutan UNA sola vez en el
host del VPS antes del primer despliegue con Dokploy:

- `generate_openid_keys.sh` — genera el par ECDSA P-256 para OpenID4VC.
