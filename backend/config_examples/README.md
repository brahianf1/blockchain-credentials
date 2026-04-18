# Guía de Despliegue (Fase de Bootstrap del Servidor)

## Introducción al Ecosistema

Este proyecto es un sistema de Identidad Descentralizada (SSI) para la emisión y verificación de microcredenciales académicas. La arquitectura interconecta:

1. **Moodle (LMS)** — fuente de verdad académica y disparador de emisiones.
2. **Controller Python (FastAPI)** — orquestador: recibe webhooks de Moodle, firma credenciales OpenID4VC y conversa con ACA-Py.
3. **ACA-Py** — agente Aries que administra el DID del emisor, firma credenciales AnonCreds y habla con el ledger Indy.
4. **VON Network (Hyperledger Indy)** — blockchain pública del sistema. Provee un ledger inmutable y un explorador web oficial.
5. **Portal Frontend (React + Vite)** — SPA pública para alumnos y verificación de terceros.

Los scripts de este directorio configuran la **capa base de confianza** del servidor antes de desplegar la aplicación vía Dokploy. Su ejecución produce:

1. **La red blockchain (Ledger Indy):** red local VON Network con 4 nodos validadores y un browser web.
2. **Las claves criptográficas:** par ECDSA P-256 para que el controller firme credenciales W3C / OpenID4VC.

---

## Soporte Multi-Arquitectura (ARM & x86_64)

Los scripts son agnósticos a la arquitectura del host:

- En **x86_64** (Intel/AMD) las imágenes Docker se descargan nativas.
- En **ARM64** (Oracle Ampere, AWS Graviton) la red VON se ejecuta con emulación QEMU `binfmt` cuando alguna imagen no ofrece build ARM.

---

## Prerrequisitos

El VPS debe contar con:

- Docker y Docker Compose.
- Herramientas básicas de Linux: `curl`, `jq`, `unzip`, `openssl` (los scripts intentan instalar lo que falte).
- QEMU (si usás ARM64): `qemu-user-static`, `binfmt-support` (integrados por Docker moderno).

---

## FASE 1 — Inicialización del Servidor (orden estricto)

### 1. Levantar el Ledger Indy (VON Network)

**Script:** `./setup-von-network.sh`

- Detecta IP interna del VPS (`hostname -I`) para evitar problemas de Hairpin NAT.
- Clona y construye VON Network, arranca los 4 nodos Indy + webserver.
- Registra el DID del emisor (ACA-Py) con rol `ENDORSER`.
- Al finalizar imprime `ACAPY_GENESIS_URL` y la `ACAPY_DID_SEED` generada; copialos para la Fase 2.

### 2. Generar claves OpenID4VC

**Script:** `./generate_openid_keys.sh`

Genera el par ECDSA P-256 (`openid_private_key.pem`, `openid_public_key.pem`) usado por el controller para firmar credenciales. Los archivos quedan en `/srv/dokploy-data/blockchain-secrets`.

---

## FASE 2 — Despliegue en Dokploy

1. Crear la App en Dokploy apuntando al repositorio y al `docker-compose.yml` raíz.
2. Cargar en la pestaña de variables de entorno (ver `.env.example` para la lista completa), como mínimo:
   - `ACAPY_GENESIS_URL=http://von-webserver:8000/genesis`
   - `ACAPY_DID_SEED=<32-caracteres>`
   - `OPENID_PRIVATE_KEY_PATH=/srv/dokploy-data/blockchain-secrets/openid_private_key.pem`
   - `OPENID_PUBLIC_KEY_PATH=/srv/dokploy-data/blockchain-secrets/openid_public_key.pem`
   - `BLOCKCHAIN_DRIVER=indy`
   - `BLOCKCHAIN_EXPLORER_URL=https://ledger.utnpf.site`
3. Presionar **Deploy**.

---

## Herramientas Adicionales

- **Limpieza total de VON Network:** `./cleanup-von.sh` destruye la red Indy y sus volúmenes para permitir redespliegues limpios.

---

## Nota sobre Hyperledger Fabric

Versiones previas del proyecto contemplaban Hyperledger Fabric como ledger adicional. La integración actual **usa Indy como único ledger público** por las siguientes razones:

- VON Network ya provee un browser web accesible públicamente (`ledger.utnpf.site`), que funciona como explorador oficial.
- ACA-Py emite credenciales AnonCreds con revocación, lo que genera transacciones reales verificables sobre Indy por cada emisión.
- Mantener dos ledgers duplicaba complejidad operativa sin aportar diferencial técnico para el caso de uso.

El directorio `hyperledger-fabric/` del repositorio conserva los samples originales a modo de referencia, pero **ya no se utilizan en tiempo de ejecución** ni forman parte del `docker-compose.yml`. Los scripts `generate_crypto.sh` y cualquier otro artefacto de crypto-material Fabric están obsoletos y fueron eliminados.
