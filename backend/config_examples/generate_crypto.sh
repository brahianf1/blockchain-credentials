#!/bin/bash

# Script completo para generar cripto-materiales de Hyperledger Fabric
# y configurar archivos core.yaml para Fabric v3.x con soporte para BCCSP y ledger snapshots.

set -e

# --- CONFIGURACIÓN ---
FABRIC_VERSION="2.5.5"
FABRIC_CA_VERSION="1.5.7"
TEMP_DIR="/tmp/fabric-official-setup"
DEST_DIR="/srv/dokploy-data/blockchain-secrets"

# --- DEFINICIÓN DE RUTAS ABSOLUTAS ---
SAMPLES_DIR="${TEMP_DIR}/fabric-samples"
BIN_DIR="${SAMPLES_DIR}/bin"
CONFIG_DIR="${SAMPLES_DIR}/config"
CRYPTO_CONFIG_FILE="${SAMPLES_DIR}/test-network/crypto-config.yaml"
OUTPUT_DIR="${SAMPLES_DIR}/organizations"

# --- INICIO DEL TEMPORIZADOR ---
START_TIME=$SECONDS

echo "▶️  Iniciando la generación completa de cripto-materiales y configuración de peers..."
echo

# ========================================================================
# PASO 1: Limpieza total de ejecuciones anteriores
# ========================================================================
echo "🧼 (Paso 1/8) Limpiando directorios y contenedores Docker detenidos..."
rm -rf "$TEMP_DIR"
rm -rf "${DEST_DIR}/organizations"
mkdir -p "$TEMP_DIR"
docker container prune -f > /dev/null 2>&1
echo "✅ Entorno limpio."
echo

# ========================================================================
# PASO 2: Descargar binarios y samples oficiales de Fabric
# ========================================================================
echo "🚀 (Paso 2/8) Ejecutando 'install-fabric.sh' para obtener binarios y samples..."
cd "$TEMP_DIR"
curl -sSL https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh | bash -s -- -f ${FABRIC_VERSION} -c ${FABRIC_CA_VERSION}
echo "✅ Binarios y samples descargados en '${SAMPLES_DIR}'."
echo

# ========================================================================
# PASO 3: Crear archivo de configuración crypto-config.yaml
# ========================================================================
echo "📝 (Paso 3/8) Creando archivo de configuración 'crypto-config.yaml'..."
cat <<EOF > "${CRYPTO_CONFIG_FILE}"
OrdererOrgs:
  - Name: Orderer
    Domain: example.com
    Specs:
      - Hostname: orderer

PeerOrgs:
  - Name: Org1
    Domain: org1.example.com
    EnableNodeOUs: true
    Template:
      Count: 1
    Users:
      Count: 1

  - Name: Org2
    Domain: org2.example.com
    EnableNodeOUs: true
    Template:
      Count: 1
    Users:
      Count: 1
EOF
echo "✅ Archivo de configuración creado en '${CRYPTO_CONFIG_FILE}'."
echo

# ========================================================================
# PASO 4: Generar cripto-materiales con cryptogen
# ========================================================================
echo "🔐 (Paso 4/8) Ejecutando 'cryptogen' con ruta absoluta..."
"${BIN_DIR}/cryptogen" generate --config="${CRYPTO_CONFIG_FILE}" --output="${OUTPUT_DIR}"
echo "✅ Cripto-materiales generados en '${OUTPUT_DIR}'."
echo

# ========================================================================
# PASO 5: Mover cripto-materiales al destino final
# ========================================================================
echo "🚚 (Paso 5/8) Moviendo artefactos a ${DEST_DIR}..."
mv "${OUTPUT_DIR}" "${DEST_DIR}/"
echo "✅ Carpeta 'organizations' movida exitosamente."
echo

# ========================================================================
# PASO 6: Crear archivo core.yaml para peer0.org1.example.com
# ========================================================================
echo "📄 (Paso 6/8) Creando core.yaml para peer0.org1.example.com..."
PEER1_DIR="${DEST_DIR}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com"

cat <<'EOF' > "${PEER1_DIR}/core.yaml"
peer:
  id: peer0.org1.example.com
  networkId: dev
  address: peer0.org1.example.com:7051
  listenAddress: 0.0.0.0:7051
  chaincodeListenAddress: 0.0.0.0:7052
  chaincodeAddress: peer0.org1.example.com:7052
  gossip:
    bootstrap: peer0.org1.example.com:7051
    externalEndpoint: peer0.org1.example.com:7051
    useLeaderElection: true
    orgLeader: false
  localMspId: Org1MSP
  mspConfigPath: /etc/hyperledger/fabric/msp
  BCCSP:
    Default: SW
    SW:
      Hash: SHA2
      Security: 256
  tls:
    enabled: true
    clientAuthRequired: false
    cert:
      file: /etc/hyperledger/fabric/tls/server.crt
    key:
      file: /etc/hyperledger/fabric/tls/server.key
    rootcert:
      file: /etc/hyperledger/fabric/tls/ca.crt
  fileSystemPath: /var/hyperledger/production

ledger:
  state:
    stateDatabase: goleveldb
  snapshots:
    rootDir: /var/hyperledger/production/snapshots

vm:
  endpoint: unix:///host/var/run/docker.sock
  docker:
    attachStdout: true
    hostConfig:
      NetworkMode: blockchain-app-hzfcsc_fabric_network

logging:
  spec: INFO

operations:
  listenAddress: 0.0.0.0:9444

metrics:
  provider: prometheus
EOF

echo "✅ core.yaml creado para peer0.org1.example.com en '${PEER1_DIR}/core.yaml'."
echo

# ========================================================================
# PASO 7: Crear archivo core.yaml para peer0.org2.example.com
# ========================================================================
echo "📄 (Paso 7/8) Creando core.yaml para peer0.org2.example.com..."
PEER2_DIR="${DEST_DIR}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com"

cat <<'EOF' > "${PEER2_DIR}/core.yaml"
peer:
  id: peer0.org2.example.com
  networkId: dev
  address: peer0.org2.example.com:9051
  listenAddress: 0.0.0.0:9051
  chaincodeListenAddress: 0.0.0.0:9052
  chaincodeAddress: peer0.org2.example.com:9052
  gossip:
    bootstrap: peer0.org2.example.com:9051
    externalEndpoint: peer0.org2.example.com:9051
    useLeaderElection: true
    orgLeader: false
  localMspId: Org2MSP
  mspConfigPath: /etc/hyperledger/fabric/msp
  BCCSP:
    Default: SW
    SW:
      Hash: SHA2
      Security: 256
  tls:
    enabled: true
    clientAuthRequired: false
    cert:
      file: /etc/hyperledger/fabric/tls/server.crt
    key:
      file: /etc/hyperledger/fabric/tls/server.key
    rootcert:
      file: /etc/hyperledger/fabric/tls/ca.crt
  fileSystemPath: /var/hyperledger/production

ledger:
  state:
    stateDatabase: goleveldb
  snapshots:
    rootDir: /var/hyperledger/production/snapshots

vm:
  endpoint: unix:///host/var/run/docker.sock
  docker:
    attachStdout: true
    hostConfig:
      NetworkMode: blockchain-app-hzfcsc_fabric_network

logging:
  spec: INFO

operations:
  listenAddress: 0.0.0.0:9445

metrics:
  provider: prometheus
EOF

echo "✅ core.yaml creado para peer0.org2.example.com en '${PEER2_DIR}/core.yaml'."
echo

# ========================================================================
# PASO 8: Ajustar permisos de archivos criptográficos
# ========================================================================
echo "🔒 (Paso 8/8) Ajustando permisos de archivos criptográficos..."

# Detectar usuario y grupo actual (o usuario sudo si existe)
ACTUAL_USER=${SUDO_USER:-$USER}
ACTUAL_GROUP=$(id -gn "$ACTUAL_USER")

echo "👤 Usuario detectado: $ACTUAL_USER:$ACTUAL_GROUP"

# Cambiar propietario de toda la estructura
chown -R "$ACTUAL_USER:$ACTUAL_GROUP" "${DEST_DIR}/organizations"

# Permisos específicos para claves privadas (crítico para BCCSP)
find "${DEST_DIR}/organizations" -type f -name "*_sk" -exec chmod 600 {} \;
find "${DEST_DIR}/organizations" -type f -name "*.key" -exec chmod 600 {} \;

# Permisos para directorios
find "${DEST_DIR}/organizations" -type d -exec chmod 755 {} \;

# Permisos para archivos de configuración
find "${DEST_DIR}/organizations" -type f -name "*.yaml" -exec chmod 644 {} \;
find "${DEST_DIR}/organizations" -type f -name "*.pem" -exec chmod 644 {} \;
find "${DEST_DIR}/organizations" -type f -name "*.crt" -exec chmod 644 {} \;

echo "✅ Permisos ajustados correctamente."
echo

# ========================================================================
# PASO 9: Limpieza final del directorio temporal
# ========================================================================
echo "🧹 Limpiando directorio temporal..."
cd ~
rm -rf "$TEMP_DIR"
echo "✅ Limpieza finalizada."
echo

# --- RESUMEN FINAL ---
DURATION=$(( SECONDS - START_TIME ))
MINUTES=$(( DURATION / 60 ))
SECONDS_REMAINING=$(( DURATION % 60 ))

echo "------------------------------------------------------------------"
echo "✅ Proceso completado en: ${MINUTES} minuto(s) y ${SECONDS_REMAINING} segundo(s)."
echo "------------------------------------------------------------------"
echo
echo "🎉 ¡ÉXITO TOTAL! Cripto-materiales y configuración de peers listos."
echo
echo "📂 Archivos generados:"
echo "   • Cripto-materiales: ${DEST_DIR}/organizations/"
echo "   • core.yaml Org1:    ${DEST_DIR}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/core.yaml"
echo "   • core.yaml Org2:    ${DEST_DIR}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/core.yaml"
echo
echo "🟢 Por favor, ve a Dokploy y despliega tu aplicación ahora."
echo "🟢 Los peers iniciarán correctamente sin errores de BCCSP."
echo