#!/bin/bash

# Script para generar claves ECDSA P-256 para OpenID4VC
# Estas claves son requeridas por el python-controller para firmar credenciales y tokens.

set -e

# Directorio de destino (Hardcoded para coincidir con .env y generate_crypto.sh)
DEST_DIR="/srv/dokploy-data/blockchain-secrets"

echo "🔑 Generando claves OpenID4VC (ECDSA P-256)..."
echo "📂 Directorio destino: ${DEST_DIR}"

# Crear directorio si no existe
if [ ! -d "$DEST_DIR" ]; then
    echo "   Creando directorio ${DEST_DIR}..."
    mkdir -p "$DEST_DIR"
fi

# Generar clave privada
openssl ecparam -name prime256v1 -genkey -noout -out "${DEST_DIR}/openid_private_key.pem"

# Generar clave pública a partir de la privada
openssl ec -in "${DEST_DIR}/openid_private_key.pem" -pubout -out "${DEST_DIR}/openid_public_key.pem"

# Ajustar permisos (lectura solo para el dueño en la privada)
chmod 600 "${DEST_DIR}/openid_private_key.pem"
chmod 644 "${DEST_DIR}/openid_public_key.pem"

echo "✅ Claves generadas exitosamente en: ${DEST_DIR}"
echo "   - Privada: ${DEST_DIR}/openid_private_key.pem"
echo "   - Pública: ${DEST_DIR}/openid_public_key.pem"
echo
echo "ℹ️  Estas rutas coinciden con las configuradas en tu archivo .env:"
echo "   OPENID_PRIVATE_KEY_PATH=${DEST_DIR}/openid_private_key.pem"
echo "   OPENID_PUBLIC_KEY_PATH=${DEST_DIR}/openid_public_key.pem"
