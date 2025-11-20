# Guía de Despliegue del Proyecto Blockchain

Este directorio contiene los scripts necesarios para preparar el entorno de despliegue en tu VPS antes de levantar los servicios con Docker Compose.

## 📋 Prerrequisitos

Asegúrate de tener instalado en tu VPS:
- Docker
- Docker Compose
- Git
- `jq` (utilidad JSON, usada por algunos scripts)

## 🚀 Orden de Ejecución de Scripts

Para un despliegue exitoso, debes ejecutar los scripts en el siguiente orden estricto.

### 1. Configurar la Red Indy (VON Network)
**Script:** `setup-von-network.sh`

Este script descarga y levanta una instancia local de VON Network (Indy Ledger).
- **Qué hace:**
  - Clona el repositorio de VON Network en `/opt/von-network`.
  - Levanta los contenedores del ledger (4 nodos + webserver).
  - Crea la red de Docker externa `von_von`.
  - Registra un DID público para el agente ACA-Py.
- **Por qué es el primero:** El `docker-compose.yml` espera que la red externa `von_von` ya exista.

```bash
./setup-von-network.sh
```

### 2. Generar Cripto-Material de Hyperledger Fabric
**Script:** `generate_crypto.sh`

Este script genera los certificados y configuraciones para la red Fabric.
- **Qué hace:**
  - Descarga los binarios de Fabric.
  - Genera los certificados MSP para las organizaciones (Org1, Org2, Orderer).
  - Crea los archivos `core.yaml` personalizados para los peers.
  - Coloca todo en `/srv/dokploy-data/blockchain-secrets`.
- **Por qué es necesario:** Los contenedores de Fabric (Peers y Orderer) no iniciarán sin estos certificados montados en sus volúmenes.

```bash
./generate_crypto.sh
```

### 3. Generar Claves OpenID4VC
**Script:** `generate_openid_keys.sh`

Este script genera las claves criptográficas para el controlador de identidad.
- **Qué hace:**
  - Genera un par de claves ECDSA P-256 (privada y pública).
  - Las guarda en `/srv/dokploy-data/blockchain-secrets`.
- **Por qué es necesario:** El servicio `python-controller` necesita estas claves para firmar credenciales verificables y tokens OpenID4VC.

```bash
./generate_openid_keys.sh
```

## 🏁 Despliegue Final

Una vez ejecutados los 3 scripts anteriores, puedes levantar el proyecto completo desde la raíz del repositorio:

```bash
docker-compose up -d
```

## 🧹 Limpieza (Opcional)

Si necesitas reiniciar desde cero la red Indy (borrar el ledger y empezar de nuevo), usa:

**Script:** `cleanup-von.sh`
- **Advertencia:** Esto borrará todos los datos del ledger Indy.

```bash
./cleanup-von.sh
```

---
**Nota:** El archivo `nginx-ssl-config.conf` es solo una referencia para configuraciones manuales de Nginx y no necesita ser ejecutado.
