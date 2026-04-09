# Guía Definitiva de Despliegue Multi-Arquitectura (ARM & x86_64)

## Introducción al Ecosistema

Este proyecto constituye un ecosistema integral de Identidad Descentralizada (Self-Sovereign Identity o SSI) diseñado para la emisión y verificación de Credenciales Criptográficas institucionales (ejemplo: diplomas y certificaciones universitarias). La arquitectura completa interconecta una plataforma LMS (Moodle), un middleware orquestador de identidad (Controlador Python Modular), un Agente Criptográfico (ACA-Py) y un registro Blockchain inmutable.

**¿Para qué sirven estos scripts?**
Antes de poder levantar y conectar las aplicaciones de emisión mediante plataformas como Dokploy, el servidor requiere de una "Capa Base de Confianza". Los scripts contenidos en este directorio son los responsables de realizar la configuración de bajo nivel o *Bootstrapping* del servidor. Su ejecución produce dependencias vitales del ecosistema:
1.  **La Red Blockchain (Ledger):** Construye y despliega el registro público descentralizado local (VON Network) donde las identidades institucionales serán ancladas públicamente.
2.  **El Material Criptográfico:** Descarga las herramientas de Hyperledger y genera los certificados de seguridad (MSP) y llaves bajo curvas elípticas (ECDSA P-256) que los servicios utilizarán para firmar digitalmente los documentos W3C/OpenID4VC.

Esta etapa preparatoria es la piedra angular del despliegue; sin ella, los sistemas superiores carecerían de anclaje criptográfico válido.

## Soporte Universal de Arquitectura (ARM & x86)

Los scripts aquí presentes son **Arquitecturalmente Agnósticos (Multi-Arch)**:
* Si ejecutas estos scripts en servidores **Intel/AMD (x86_64)**, los binarios e imágenes de Docker nativas se descargarán automáticamente y el uso de CPU será sumamente eficiente (Nativo).
* Si utilizas servidores **ARM64** (ej. Oracle Ampere, AWS Graviton), Docker emulará la red VON (VON Network) utilizando QEMU `binfmt`, mientras que la generación de criptografía de Fabric descargará automáticamente los binarios para ARM de forma nativa. Esto permite desarrollar y testear sin importar el proveedor de infraestructura subyacente.

---

## Prerrequisitos

Tu VPS (nuevo o migrado) debe contar con:
- Docker y Docker Compose
- Herramientas básicas de Linux: `curl`, `jq`, `unzip`, `openssl` (los scripts intentarán instalar lo que falte automáticamente).
- El emulador QEMU si usas ARM (`qemu-user-static`, `binfmt-support` integrados en Docker).

---

## FASE 1: Inicialización del Servidor (Orden Estricto)

Para garantizar un entorno estable a prueba de fallos de red (Hairpin NAT, etc.), ejecuta los siguientes scripts en desde tu consola del VPS:

### 1. Levantar el Ledger Local (VON Network)
**Script:** `./setup-von-network.sh`

*   **Comportamiento Multi-Arch:** Delega la construcción y/o emulación directamente a Docker (`./manage build`).
*   **Seguridad de Red:** Se ancla de manera inteligente a la **IP Privada/Interna** de la máquina (`hostname -I`) para evadir los bloqueos de Firewall y problemas de NAT Hairpin de los proveedores de nube (ej. Oracle).
*   **Resultados Críticos:** Al finalizar, inyectará en pantalla la **URL del Genesis** y generará automáticamente la **SEED de 32 caracteres** requerida por ACA-Py.
> IMPORTANTE: Copia `ACAPY_GENESIS_URL` y `ACAPY_DID_SEED` generados por este script; los necesitarás para la Fase 2.

### 2. Generar Cripto-Material de Hyperledger Fabric
**Script:** `./generate_crypto.sh`

*   **Comportamiento Multi-Arch:** Descarga dinámicamente usando `install-fabric.sh`, la cual detecta si el host es ARM64 o AMD64 y baja los binarios criptográficos correctos.
*   **Comportamiento Falla-Seguro:** Crea automáticamente el directorio maestro en `/srv/dokploy-data/blockchain-secrets` antes de operar. Genera los MSP y `.yaml` para Org1, Org2 y el Orderer.

### 3. Generar Claves OpenID4VC (Controlador Python)
**Script:** `./generate_openid_keys.sh`

*   **Propósito:** Genera el par de llaves ECDSA P-256 (`openid_private_key.pem`, `openid_public_key.pem`) universales, necesarias para emitir credenciales estandarizadas por la W3C.
*   **Destino Seguro:** Todo queda resguardado físicamente en `/srv/dokploy-data/blockchain-secrets` en el *Host*.

---

## FASE 2: Despliegue en Dokploy

Una vez que la Terminal (SSH) haya terminado de ejecutar exitosamente la Fase 1, cierra la consola y dirígete al panel web de Dokploy:

1. Crea la App del repositorio apuntando al archivo `docker-compose.yml`.
2. Dirígete a la pestaña de Variables de Entorno.
3. Asegúrate de inyectar las siguientes variables vitales basándote en los datos que te entregó la Fase 1:
   * `ACAPY_GENESIS_URL=http://von-webserver:8000/genesis`
   * `ACAPY_DID_SEED=<tu-seed-de-32-caracteres>`
   * `OPENID_PRIVATE_KEY_PATH=/srv/dokploy-data/blockchain-secrets/openid_private_key.pem`
   * `OPENID_PUBLIC_KEY_PATH=/srv/dokploy-data/blockchain-secrets/openid_public_key.pem`
   * `CRYPTO_CONFIG_PATH=/srv/dokploy-data/blockchain-secrets`
4. Presiona **Deploy**.

Exceptuando a VON Network, todos los sistemas pesados (Moodle, ACA-Py, Postgres, y el Controller) son imágenes Multi-Arch modernas que se ejecutarán de manera nativa en tu entorno.

---

## Herramientas Adicionales

*   **Limpieza Total:** `./cleanup-von.sh` destruirá la red Indy y los volúmenes, permitiendo redesplegar el Sandbox de forma limpia en caso de errores en la red blockchain.
