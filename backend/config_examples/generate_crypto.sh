#!/bin/bash

# Este script automatiza la generación de los cripto-materiales de Hyperledger Fabric
# utilizando el método oficial y rutas absolutas para máxima robustez.
set -e

# --- CONFIGURACIÓN ---
FABRIC_VERSION="2.5.5"
FABRIC_CA_VERSION="1.5.7"
TEMP_DIR="/tmp/fabric-official-setup"
DEST_DIR="/srv/dokploy-data/blockchain-secrets"

# --- DEFINICIÓN DE RUTAS ABSOLUTAS ---
# Se definen las rutas clave al principio para evitar cualquier ambigüedad.
SAMPLES_DIR="${TEMP_DIR}/fabric-samples"
BIN_DIR="${SAMPLES_DIR}/bin"
CONFIG_DIR="${SAMPLES_DIR}/config"
CRYPTO_CONFIG_FILE="${SAMPLES_DIR}/test-network/crypto-config.yaml"
OUTPUT_DIR="${SAMPLES_DIR}/organizations"

# --- EJECUCIÓN ---

# --- INICIO DEL TEMPORIZADOR ---
START_TIME=$SECONDS
echo "▶️ Iniciando la generación de cripto-materiales (Método Final y Robusto)..."
echo

# 1. Limpieza total de ejecuciones anteriores.
echo "🧼 (Paso 1/6) Limpiando directorios y contenedores Docker detenidos..."
rm -rf "$TEMP_DIR"
rm -rf "${DEST_DIR}/organizations"
mkdir -p "$TEMP_DIR"
docker container prune -f > /dev/null 2>&1
echo "✅ Entorno limpio."
echo

# 2. Descargar todo lo necesario usando el script oficial.
echo "🚀 (Paso 2/6) Ejecutando 'install-fabric.sh' para obtener binarios y samples..."
cd "$TEMP_DIR"
curl -sSL https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh | bash -s -- -f ${FABRIC_VERSION} -c ${FABRIC_CA_VERSION}
echo "✅ Binarios y samples descargados en '${SAMPLES_DIR}'."
echo

# 3. Crear el archivo de configuración para cryptogen.
echo "📝 (Paso 3/6) Creando archivo de configuración 'crypto-config.yaml'..."
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

# 4. Generar los cripto-materiales usando la ruta absoluta.
echo "🔐 (Paso 4/6) Ejecutando 'cryptogen' con ruta absoluta..."
"${BIN_DIR}/cryptogen" generate --config="${CRYPTO_CONFIG_FILE}" --output="${OUTPUT_DIR}"
echo "✅ Cripto-materiales generados en '${OUTPUT_DIR}'."
echo

# 5. Mover la carpeta 'organizations' al destino final.
echo "🚚 (Paso 5/6) Moviendo artefactos a ${DEST_DIR}..."
mv "${OUTPUT_DIR}" "${DEST_DIR}/"
echo "✅ Carpeta 'organizations' movida exitosamente."
echo

# 6. Limpieza final del directorio temporal.
echo "🧹 (Paso 6/6) Limpiando directorio temporal..."
cd ~
rm -rf "$TEMP_DIR"
echo "✅ Limpieza finalizada."
echo

# --- FINAL ---
DURATION=$(( SECONDS - START_TIME ))
MINUTES=$(( DURATION / 60 ))
SECONDS_REMAINING=$(( DURATION % 60 ))

echo "------------------------------------------------------------------"
echo "✅ Proceso completado en: ${MINUTES} minuto(s) y ${SECONDS_REMAINING} segundo(s)."
echo "------------------------------------------------------------------"
echo
echo "🎉 ¡ÉXITO DEFINITIVO! Los cripto-materiales están listos."
echo "🟢 Por favor, ve a Dokploy y redespliega tu aplicación ahora."
