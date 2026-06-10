# Pruebas del proyecto — Microcredenciales Blockchain (UTN)

> Documento de pruebas: detalla la batería de pruebas automatizadas —**unitarias y de
> integración**— implementada en el proyecto y cómo ejecutarla.

---

## 1. Resumen

El sistema emite y verifica microcredenciales digitales y las "ancla" en una blockchain
(Hyperledger Besu) para que cualquiera pueda comprobar que son auténticas. Está formado por
tres piezas que se comunican entre sí:

- **Backend** (Python / FastAPI) — emite, firma, ancla y verifica.
- **Plugin de Moodle** (PHP) — dispara la emisión cuando un alumno termina un curso.
- **Portal del alumno** (React / JavaScript) — el alumno ve y comparte sus credenciales.

Se implementó una **batería de pruebas automatizadas —unitarias y de integración—** sobre las
tres piezas:

| Pieza | Tipo | Herramienta | Pruebas |
| --- | --- | --- | --- |
| Backend (Python) | Unitarias (lógica de negocio) | pytest | 66 |
| Backend (Python) | Integración de la API | pytest + TestClient | 26 |
| Portal (JavaScript) | Unitarias | Vitest | 22 |
| Plugin de Moodle (PHP) | Unitarias | PHPUnit | 15 |
| **Total** | | | **129** |

**Cómo se cubre el requisito del proyecto:**

| Lo pedido | Dónde se cubre |
| --- | --- |
| Pruebas unitarias de la lógica de negocio | Backend unitarias (§3.1), Portal (§3.2), Plugin (§3.3) |
| Pruebas de integración de la API, simulando peticiones del frontend | Backend integración (§3.4) |
| Validar la **robustez del backend** | §3.4 — respuestas correctas: 200 / 401 / 403 / 404 / 409 / 422 |
| Validar la **seguridad de la API** | §3.4 — autenticación, autorización por rol y privacidad |
| Validar la **comunicación con la red blockchain** | §3.4 — la API expone fielmente el estado del ledger (simulado) |

```
  BACKEND  (Python, pytest) -- 92
    Unitarias (66):
      Reglas de negocio:  hash, estado valida/revocada/no emitida, ciclo de
                          vida, validaciones y contrasena.
      Protocolo / infra:  DID (jwk/key), PKCE (OAuth), formato y metadata
                          OpenID4VCI, generacion de QR.
    Integracion de la API (26):
      Seguridad (auth / roles / privacidad), robustez (200..422) y
      comunicacion con la blockchain (ledger simulado).

  PORTAL  (JavaScript, Vitest) -- 22
    Estados visuales de la credencial y cliente de API
    (autenticacion, manejo de sesion 401, errores, construccion de endpoints).

  PLUGIN MOODLE  (PHP, PHPUnit) -- 15
    base64url, generacion de JWT, URL de ingreso al portal (SSO + JWT),
    consistencia de hash con el backend.
```

---

## 2. Tipos de prueba implementadas

Una **prueba unitaria** verifica una sola función de forma aislada: le entrega una entrada
conocida y comprueba que devuelve la salida esperada. Son rápidas, simples y forman la base de
cualquier estrategia de pruebas.

Una **prueba de integración** ejercita varias piezas trabajando juntas a través de un endpoint
real: simula una petición del frontend con `TestClient`, reemplaza la base de datos y la
blockchain por dobles de prueba, y verifica la respuesta completa de la API (código de estado,
cuerpo y efectos). No requiere levantar Postgres ni un nodo Besu.

---

## 3. Pruebas implementadas

### 3.1 Backend — Python (pytest) · 66 pruebas

Carpeta: `backend/controller/tests/`

**Reglas de negocio del core de las microcredenciales:**

| Archivo | Qué verifica |
| --- | --- |
| `test_hashing.py` | El cálculo del hash de la credencial (la "huella" que se ancla en la blockchain): que sea determinista, tenga el formato correcto y cambie si cambian los datos. Es la identidad de la credencial. |
| `test_anchor_lifecycle.py` | La regla central de verificación —el estado on-chain se traduce a **válida / revocada / no emitida**— y el ciclo de vida de la credencial (pendiente → anclada → revocada / no disponible). |
| `test_schemas.py` | Las validaciones de entrada del portal: **política de contraseñas** (mínimo 8, con mayúscula y número), formato de email y longitudes de los campos. |

**Protocolo e infraestructura (cómo el sistema dialoga con wallets y Moodle):**

| Archivo | Qué verifica |
| --- | --- |
| `test_did_utils.py` | La normalización de identificadores DID: agregar o quitar prefijos y manejar valores vacíos. |
| `test_helpers.py` | La derivación de identificadores DID a partir de la clave (`did:jwk`, `did:key`) —incluida la garantía de no filtrar la clave privada— y la extracción del DID del holder y del estado del emisor. |
| `test_pkce_validator.py` | La validación de seguridad PKCE del login (RFC 7636): casos válidos, inválidos y métodos no soportados. |
| `test_credential_formatters.py` | La elección del formato de credencial según lo que pide la wallet y el armado de la respuesta del endpoint. |
| `test_credential_registry.py` | El registro de configuraciones de credenciales y la transformación a la metadata pública que exige OpenID4VCI. |
| `test_qr_generator.py` | La validación de la URL del QR y la generación de la imagen del código QR. |

Archivos de apoyo: `conftest.py` (configuración de la suite), `pytest.ini` y `requirements-dev.txt`.

### 3.2 Portal — JavaScript (Vitest) · 22 pruebas

| Archivo | Qué verifica |
| --- | --- |
| `src/utils/blockchain.test.js` | Los textos y estados visuales que ve el alumno para cada estado de la credencial en la blockchain ("Verificada", "Pendiente", "Revocada", "No disponible"), el comportamiento ante un estado desconocido y la cobertura de todos los estados. |
| `src/api/client.test.js` | El cliente que habla con el backend: que agregue la cabecera de autenticación cuando hay sesión y la omita en los endpoints públicos, que ante un 401 cierre la sesión y redirija al login, que traduzca los errores HTTP a mensajes y que arme correctamente la URL y el cuerpo de cada endpoint. |

### 3.3 Plugin de Moodle — PHP (PHPUnit) · 15 pruebas

Archivos: `moodle/moodle-plugin/credenciales/tests/lib_test.php` y `phpunit.xml`

Cubre dos grupos de funciones, ambos sin levantar un entorno Moodle:

- **Funciones puras** (solo PHP nativo, sin mocks):
  - La codificación `base64url` (vector conocido, URL-safe sin padding, cadena vacía, round-trip).
  - La generación del token JWT firmado: estructura correcta, firma válida, resultado determinista,
    firmas distintas con secretos distintos y preservación de datos con acentos y campos anidados.
  - La **consistencia de hash con el backend** (ver sección 4), con dos vectores conocidos.
- **`get_portal_url`** (la URL de ingreso al portal con su JWT de 5 minutos), probada con *stubs*
  livianos de las dos funciones de Moodle que usa: que sin secreto devuelva la URL plana, que con
  secreto incluya el token, que el contenido del token sea el correcto, que refleje si el usuario
  es administrador y que arme bien el separador de la URL.

### 3.4 Backend — Pruebas de integración de la API · 26 pruebas

Archivo: `backend/controller/tests/test_api_integration.py`

Estas pruebas levantan la API con `TestClient` y **simulan las mismas peticiones que hace el
frontend** a los endpoints reales (`/api/portal/...`, `/api/public/...`, `/api/admin/...`). Para
correr sin infraestructura, la base del portal es **SQLite en memoria**, la base de Moodle se
reemplaza por datos de prueba y la blockchain por un **ledger simulado** (no se necesita Postgres
ni un nodo Besu). Cubren los tres objetivos del requisito:

| Objetivo | Qué se verifica |
| --- | --- |
| **Seguridad de la API** | Endpoints protegidos rechazan peticiones sin token o con token inválido (401); endpoints de administración rechazan a un usuario no admin (403); login con contraseña incorrecta o cuenta sin contraseña (401); token de Moodle inválido (401); y la **privacidad**: una credencial privada se verifica como válida pero **sin** datos personales, una pública sí los muestra. |
| **Robustez del backend** | Respuestas correctas a entradas válidas e inválidas: login correcto (200 + token), alta/actualización por Moodle sin duplicar, listado y detalle de credenciales, credencial inexistente (404), hash desconocido (válido = false), contraseña débil (422), cambio de visibilidad, estadísticas, y revocación de hash inexistente (404) o ya revocada (409). |
| **Comunicación con la blockchain** | Con un ledger simulado, la API expone fielmente su estado: la verificación devuelve `anchored` / `revoked` según el ledger, la verificación pública adjunta la evidencia on-chain (con enlace al explorador), el registro público refleja la red, y la revocación marca la credencial y devuelve el hash de transacción. |

---

## 4. Prueba destacada: consistencia de hash Moodle ↔ Backend

El hash que identifica a una credencial se calcula en **dos lenguajes**: en el plugin de Moodle
(PHP) y en el backend (Python). Ambos **deben producir exactamente el mismo valor**, porque ese
hash es el que se ancla en la blockchain y se usa para verificar.

Esta prueba fija unos datos de ejemplo y comprueba —en cada lenguaje por separado— que ambos
generan el mismo hash:

```
f05c5a74f693c09731b130a39dcbeec9904a1e2ea366b8a5a61176596403dbea
```

Vive a la vez en `test_hashing.py` (Python) y en `lib_test.php` (PHP). Es un "contrato" entre las
dos piezas que garantiza que la verificación en la blockchain siempre funcione.

---

## 5. Cómo ejecutar las pruebas

Requisitos: **Python 3.12+**, **Node.js 18+** y **PHP 8.2+**. Cada suite se ejecuta por separado.

### Backend — Python (92 pruebas: 66 unitarias + 26 de integración)

Las unitarias y las de integración corren juntas con el mismo comando. Las de integración
**no requieren** Postgres ni un nodo Besu (usan SQLite en memoria y un ledger simulado).

```bash
cd backend/controller
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

### Portal — JavaScript (22 pruebas)

```bash
cd microcredenciales-frontend
npm install
npm test
```

### Plugin de Moodle — PHP (15 pruebas)

Requiere **PHPUnit 11**, que se obtiene como `phpunit.phar`
(<https://phar.phpunit.de/phpunit-11.phar>) o con `composer require phpunit/phpunit`.

```bash
cd moodle/moodle-plugin/credenciales
phpunit -c tests/phpunit.xml --testdox
```

La opción `--testdox` lista cada prueba con su nombre legible (útil para documentar).
Salida esperada:

```
PHPUnit 11.5.55 by Sebastian Bergmann and contributors.
Runtime:       PHP 8.3.31
...............                                       15 / 15 (100%)
OK (15 tests, 34 assertions)
```

---

## 6. Resultado

| Pieza | Herramienta | Pruebas | Estado |
| --- | --- | --- | --- |
| Backend — unitarias | pytest | 66 | Pasan |
| Backend — integración API | pytest + TestClient | 26 | Pasan |
| Portal | Vitest | 22 | Pasan |
| Plugin de Moodle | PHPUnit | 15 | Pasan |
| **Total** | | **129** | |

---

*Documento de pruebas del proyecto.*
