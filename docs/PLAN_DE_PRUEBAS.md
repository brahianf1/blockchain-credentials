# Pruebas del proyecto — Microcredenciales Blockchain (UTN)

> Documento de pruebas: detalla la batería de pruebas automatizadas —**unitarias, de integración
> y funcionales**— implementada en el proyecto, **organizada por los dos ambientes** en que se
> divide el trabajo, y cómo ejecutarla.

---

## 1. Resumen

El sistema emite y verifica microcredenciales digitales y las "ancla" en una blockchain
(Hyperledger Besu) para que cualquiera pueda comprobar que son auténticas.

El proyecto se divide en **dos ambientes** (un *paper* por cada uno):

- **Ambiente Backend** — el controlador **Python / FastAPI** que emite, firma, ancla y verifica,
  más la capa blockchain.
- **Ambiente Frontend** — la cara visible para los usuarios, que incluye **dos piezas**:
  - el **plugin de Moodle** (PHP), que dispara la emisión cuando un alumno termina un curso;
  - el **portal del alumno** (React / JavaScript), donde el alumno ve y comparte sus credenciales.

| Ambiente | Pieza | Herramienta | Pruebas |
| --- | --- | --- | --- |
| **Backend** | Controlador (Python) | pytest | **101** |
| **Frontend** | Plugin de Moodle (PHP) | PHPUnit | 19 |
| **Frontend** | Portal del alumno (JavaScript) | Vitest + Testing Library | 39 |
| | **Frontend — subtotal** | | **58** |
| | **Total** | | **159** |

```
  +===========================+    +===================================+
  |  AMBIENTE BACKEND         |    |  AMBIENTE FRONTEND                 |
  |  Python -- 101            |    |  (plugin + portal) -- 58           |
  |                           |    |                                    |
  |  Unitarias (66):          |    |  PLUGIN MOODLE (PHP) -- 19         |
  |   logica de negocio       |    |   base64url, JWT, URL de ingreso, |
  |   (hash, estado, ciclo    |    |   consistencia de hash, y         |
  |    de vida, validaciones) |    |   activacion (course_completed)   |
  |   + protocolo/infra       |    |                                    |
  |   (DID, PKCE, OpenID4VCI,  |    |  PORTAL (JavaScript) -- 39        |
  |    QR)                     |    |   unitarias (estados, cliente API)|
  |                           |    |   + de componente (pagina de      |
  |  Integracion API (35):    |    |   verificacion, guard de rutas,   |
  |   portal API + flujo      |    |   contexto de auth, tarjeta)      |
  |   OpenID4VCI + blockchain |    |                                    |
  +===========================+    +===================================+
            \                                      /
             \____ contrato compartido: hash _____/
                   (mismo SHA-256 en ambos)
```

---

## 2. Tipos de prueba

- **Unitaria** — verifica una sola función de forma aislada (entrada conocida → salida esperada).
  Rápida, simple; es la base de la estrategia.
- **De integración** — ejercita varias piezas juntas a través de un endpoint real: simula una
  petición del cliente con `TestClient`, reemplaza base de datos y blockchain por dobles de prueba,
  y verifica la respuesta completa de la API. No requiere Postgres ni un nodo Besu.
- **Funcional / de flujo** — recorre un flujo crítico completo (ver §6) en el nivel automatizable.

---

## 3. Ambiente Backend — Python (pytest) · 101 pruebas

Carpeta: `backend/controller/tests/`.

### 3.1 Unitarias — lógica de negocio y protocolo · 66 pruebas

**Reglas de negocio del core:**

| Archivo | Qué verifica |
| --- | --- |
| `test_hashing.py` | El cálculo del hash de la credencial (la "huella" que se ancla en la blockchain): determinista, formato correcto y sensible a los datos. Es la identidad de la credencial. |
| `test_anchor_lifecycle.py` | La regla central: el estado on-chain se traduce a **válida / revocada / no emitida**, y el ciclo de vida (pendiente → anclada → revocada / no disponible). |
| `test_schemas.py` | Validaciones de entrada del portal: **política de contraseñas** (mínimo 8, mayúscula y número), email y longitudes. |

**Protocolo e infraestructura (diálogo con wallets y Moodle):**

| Archivo | Qué verifica |
| --- | --- |
| `test_did_utils.py` | Normalización de identificadores DID (prefijos, valores vacíos). |
| `test_helpers.py` | Derivación de DID desde la clave (`did:jwk`, `did:key`, sin filtrar la privada) y extracción del DID del holder. |
| `test_pkce_validator.py` | Validación de seguridad PKCE (RFC 7636): válidos, inválidos y métodos no soportados. |
| `test_credential_formatters.py` | Elección del formato de credencial según la wallet y armado de la respuesta. |
| `test_credential_registry.py` | Registro de configuraciones y metadata pública OpenID4VCI. |
| `test_qr_generator.py` | Validación de la URL del QR y generación de la imagen. |

Apoyo: `conftest.py`, `pytest.ini`, `requirements-dev.txt`.

### 3.2 Integración de la API · 35 pruebas

Archivos: `test_api_integration.py` (API del portal) y `test_credential_flow.py` (flujo OpenID4VCI).
Levantan la API con `TestClient` y simulan peticiones reales a `/api/portal/...`, `/api/public/...`,
`/api/admin/...` y `/oid4vc/...`. Sin infraestructura: **SQLite en memoria**, Moodle reemplazado por
datos de prueba, **ledger simulado** y sesiones OpenID4VCI en memoria.

| Objetivo | Qué se verifica |
| --- | --- |
| **Seguridad de la API** | Sin token o token inválido → 401; no admin → 403; login incorrecto / sin contraseña → 401; token de Moodle inválido → 401; y **privacidad**: credencial privada válida pero **sin** datos personales, pública sí los muestra. |
| **Robustez del backend** | Respuestas correctas: login OK (200 + token), alta/actualización por Moodle sin duplicar, listado/detalle, inexistente (404), hash desconocido (válido=false), contraseña débil (422), visibilidad, estadísticas, revocación inexistente (404) o ya revocada (409). |
| **Comunicación con la blockchain** | Con ledger simulado: la verificación devuelve `anchored`/`revoked`, la verificación pública adjunta la evidencia on-chain, el registro público refleja la red, la revocación devuelve el hash de transacción, y si la blockchain **no responde** → **502** sin revocar. |
| **Aceptación de credenciales (OpenID4VCI)** | `/oid4vc/token`: pre-autorizado válido → access token, inválido → 400, grant no soportado → 400, **PKCE** correcto/incorrecto. `/oid4vc/credential`: sin token → 401, token inválido → 401, sin *proof* → 400. |

---

## 4. Ambiente Frontend — Plugin de Moodle + Portal · 58 pruebas

### 4.1 Plugin de Moodle — PHP (PHPUnit) · 19 pruebas

Archivos: `moodle/moodle-plugin/credenciales/tests/lib_test.php` y `phpunit.xml`. Todo sin levantar
un entorno Moodle.

- **Funciones puras** (PHP nativo, sin mocks):
  - `base64url` (vector conocido, URL-safe sin padding, vacío, round-trip).
  - Generación del **JWT firmado**: estructura, firma válida, determinismo, firmas distintas con
    secretos distintos y preservación de acentos / campos anidados.
  - **Consistencia de hash con el backend** (ver §5), con dos vectores conocidos.
- **`get_portal_url`** (URL de ingreso al portal con JWT de 5 min), con *stubs* livianos de Moodle:
  sin secreto → URL plana, con secreto → token correcto, refleja si es admin, separador correcto.
- **Activación del plugin al finalizar un curso** (`build_payload` del observer `course_completed`):
  payload con las claves correctas, IDs como string, **fecha en UTC**, y que produzca **el mismo
  hash que el backend** (contrato extremo a extremo).

### 4.2 Portal del alumno — JavaScript (Vitest + Testing Library) · 39 pruebas

**Unitarias (lógica y cliente de API):**

| Archivo | Qué verifica |
| --- | --- |
| `src/utils/blockchain.test.js` | Textos y estados visuales por cada estado de la credencial ("Verificada", "Pendiente", "Revocada", "No disponible"), estado desconocido y cobertura de todos los estados. |
| `src/api/client.test.js` | El cliente que habla con el backend: agrega la cabecera de autenticación cuando hay sesión y la omite en endpoints públicos, ante un **401 cierra la sesión y redirige**, traduce los errores HTTP a mensajes y arma bien la URL y el cuerpo de cada endpoint. |

**De componente (UI, con React Testing Library):**

| Archivo | Qué verifica |
| --- | --- |
| `VerificacionPublica.test.jsx` | La **página de verificación pública**: verifica automáticamente el hash de la URL y muestra "Credencial Reconocida" (con alumno, curso y evidencia blockchain), "Credencial No Encontrada" o el mensaje de error según la respuesta de la API. |
| `ProtectedRoute.test.jsx` | El **guard de rutas**: muestra "Cargando" mientras resuelve la sesión, redirige al login sin usuario, exige configurar contraseña si falta, y renderiza el contenido cuando el usuario está autenticado. |
| `AuthContext.test.jsx` | El **estado de autenticación**: arranque sin token, `login` guarda el token y setea el usuario, `logout` lo limpia. |
| `CredentialCard.test.jsx` | La **tarjeta de credencial**: muestra curso / emisor / fecha, el badge según el estado y dispara los callbacks de "Ver Detalles" y "Compartir". |

---

## 5. Contrato entre ambientes: consistencia de hash

El hash que identifica una credencial se calcula en **los dos ambientes**: en el **frontend**
(plugin de Moodle, PHP) y en el **backend** (Python). Ambos **deben producir exactamente el mismo
valor**, porque ese hash es el que se ancla en la blockchain y se usa para verificar.

```
f05c5a74f693c09731b130a39dcbeec9904a1e2ea366b8a5a61176596403dbea
```

La constante vive a la vez en `test_hashing.py` (backend) y en `lib_test.php` (plugin). Es un
"contrato" entre ambientes que garantiza que la verificación on-chain siempre funcione.

---

## 6. Flujos críticos (verificación funcional / E2E)

> **Sobre "de extremo a extremo":** un test E2E estricto corre **todo el stack junto**
> (Moodle → backend → Besu → wallet → portal). Acá cada flujo se valida en el nivel automatizable;
> el E2E completo con sistemas externos se cubre con el **checklist manual** del final.

La columna **Ambiente** indica a qué *paper* pertenece cada parte del flujo:

| Flujo crítico | Ambiente | Cómo se verifica (automatizado) |
| --- | --- | --- |
| 1 · Activación del plugin al finalizar un curso | **Frontend** (plugin) | El observer `course_completed` arma el payload correcto: IDs string, fecha en **UTC** y el mismo hash que el backend. (`lib_test.php`) |
| 2 · Gestión de errores en la comunicación con la API | **Frontend** (portal) + Backend | Portal: ante 401 cierra sesión y redirige, y traduce errores HTTP (`client.test.js`). Backend: 401/403/404/409/422 y error con la blockchain → 502 (`test_api_integration.py`). |
| 3 · Aceptación de credenciales por el alumno | **Backend** + wallet | Ocurre entre la wallet y el backend (el portal no la implementa): `/oid4vc/token` + `/oid4vc/credential` (`test_credential_flow.py`). |
| 4 · Verificación pública | **Frontend** (portal) + Backend | Backend: pública vs privada, hash desconocido, evidencia on-chain (`test_api_integration.py`). Portal: la **página** de verificación (`VerificacionPublica.test.jsx`) y la llamada `publicVerify` (`client.test.js`). |

> **Nota conceptual:** el flujo 3 (aceptación) es propio del **backend + la wallet**, no del portal,
> por eso se valida en el ambiente Backend. Los flujos 1, 2 y 4 sí tienen cobertura en el frontend
> (plugin y/o portal), incluida la página de verificación pública.

**Checklist de E2E manual** (necesita el stack completo corriendo; no se automatiza):

1. Completar un curso real en Moodle → confirmar que el plugin dispara y el backend recibe los datos.
2. Escanear el QR con una wallet (Lissi / DIDRoom) → aceptar y almacenar la credencial.
3. Confirmar el anclaje real en Besu (transacción visible en Blockscout).
4. Verificar públicamente la credencial por su hash en el portal.

---

## 7. Cómo ejecutar las pruebas

Requisitos: **Python 3.12+**, **Node.js 18+** y **PHP 8.2+**.

### Ambiente Backend — Python (101 pruebas)

Unitarias e integración corren juntas; **no requieren** Postgres, Besu ni una wallet.

```bash
cd backend/controller
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

### Ambiente Frontend — Plugin de Moodle (PHP, 19 pruebas)

Requiere **PHPUnit 11** (como `phpunit.phar` desde <https://phar.phpunit.de/phpunit-11.phar> o con
`composer require phpunit/phpunit`).

```bash
cd moodle/moodle-plugin/credenciales
phpunit -c tests/phpunit.xml --testdox
```

Salida esperada:

```
PHPUnit 11.5.55 by Sebastian Bergmann and contributors.
Runtime:       PHP 8.3.31
...................                                   19 / 19 (100%)
OK (19 tests, 45 assertions)
```

### Ambiente Frontend — Portal (JavaScript, 39 pruebas)

```bash
cd microcredenciales-frontend
npm install
npm test
```

---

## 8. Resultado

| Ambiente | Pieza | Herramienta | Pruebas | Estado |
| --- | --- | --- | --- | --- |
| **Backend** | Unitarias (lógica de negocio) | pytest | 66 | Pasan |
| **Backend** | Integración de la API | pytest + TestClient | 35 | Pasan |
| **Frontend** | Plugin de Moodle | PHPUnit | 19 | Pasan |
| **Frontend** | Portal del alumno | Vitest + Testing Library | 39 | Pasan |
| | **Total** | | **159** | |

**Pendiente opcional** (no implementado): el manejo de errores cURL del plugin de Moodle requiere un
entorno Moodle real, por lo que se cubre en el **checklist de E2E manual** (§6). El resto de cada
flujo crítico ya está cubierto.

---

*Documento de pruebas del proyecto.*
