#!/bin/bash
################################################################################
# Script de reparación de Traefik para VON Network
#
# Reemplaza el contenedor ``von-webserver`` existente con el mismo estado
# (imagen, volúmenes, variables de entorno y redes) pero con labels
# Traefik corregidas, de modo que:
#
#   1. Se use el resolver TLS ``letsencrypt`` (el que Dokploy tiene
#      configurado) en lugar de ``myresolver``.
#   2. Se exponga un router HTTP (entrypoint ``web``) con el middleware
#      ``redirect-to-https@file``. Esto es imprescindible para que
#      Let's Encrypt pueda completar el challenge HTTP-01 y emitir el
#      certificado público.
#   3. El contenedor quede conectado simultáneamente a la red del ledger
#      (``von_von``) y a la red del proxy de Dokploy (``dokploy-network``).
#
# El ledger (nodos Indy y sus volúmenes) NO se toca: los 4 nodos siguen
# corriendo y los datos persistidos en volúmenes se re-montan al recrear
# el ``von-webserver``.
#
# Ejecución (VPS como root):
#     chmod +x fix-von-traefik.sh
#     sudo ./fix-von-traefik.sh
################################################################################

set -euo pipefail

CONTAINER_NAME="von-webserver"
PROXY_NETWORK="dokploy-network"
DOMAIN="${VON_NETWORK_DOMAIN:-ledger.utnpf.site}"
HOST_PORT="${VON_NETWORK_HOST_PORT:-9000}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; }
section() { echo -e "\n${BLUE}============================================================${NC}\n${BLUE}  $1${NC}\n${BLUE}============================================================${NC}"; }

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error "Este script requiere ejecutarse como root (sudo)."
        exit 1
    fi
}

require_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        error "Docker no está instalado."
        exit 1
    fi
    if ! docker info >/dev/null 2>&1; then
        error "El daemon de Docker no responde. ¿El usuario tiene permisos?"
        exit 1
    fi
}

require_container() {
    if ! docker inspect "${CONTAINER_NAME}" >/dev/null 2>&1; then
        error "El contenedor '${CONTAINER_NAME}' no existe. Ejecutá primero 'setup-von-network.sh'."
        exit 1
    fi
}

require_proxy_network() {
    if ! docker network inspect "${PROXY_NETWORK}" >/dev/null 2>&1; then
        error "La red '${PROXY_NETWORK}' no existe. ¿Dokploy está desplegado?"
        exit 1
    fi
}

################################################################################
require_root
require_docker
require_container
require_proxy_network

section "Inspeccionando '${CONTAINER_NAME}'"

IMAGE=$(docker inspect "${CONTAINER_NAME}" --format='{{.Config.Image}}')
info "Imagen actual:        ${IMAGE}"

PRIMARY_NETWORK=$(
    docker inspect "${CONTAINER_NAME}" \
      --format='{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' \
    | grep -v -E "^(${PROXY_NETWORK}|)$" \
    | head -n 1
)

if [[ -z "${PRIMARY_NETWORK}" ]]; then
    PRIMARY_NETWORK="$(docker network ls --format '{{.Name}}' | grep '^von_von$' | head -n 1 || true)"
fi

if [[ -z "${PRIMARY_NETWORK}" ]]; then
    error "No se pudo detectar la red principal del ledger (esperado 'von_von' o similar)."
    exit 1
fi

info "Red principal (ledger): ${PRIMARY_NETWORK}"
info "Red proxy (Traefik):    ${PROXY_NETWORK}"

# Variables de entorno actuales (necesarias para preservar comportamiento)
mapfile -t ENV_VARS < <(
    docker inspect "${CONTAINER_NAME}" \
      --format='{{range .Config.Env}}{{println .}}{{end}}' \
    | grep -E '^(DOCKERHOST|LOG_LEVEL|RUST_LOG|REGISTER_NEW_DIDS|LEDGER_SEED)=' || true
)

if [[ ${#ENV_VARS[@]} -eq 0 ]]; then
    warn "No se detectaron las variables VON esperadas; se aplicarán defaults."
    PUBLIC_IP="$(hostname -I | awk '{print $1}')"
    ENV_VARS=(
        "DOCKERHOST=${PUBLIC_IP}"
        "LOG_LEVEL=INFO"
        "RUST_LOG=warning"
        "REGISTER_NEW_DIDS=True"
        "LEDGER_SEED=000000000000000000000000Trustee1"
    )
fi

info "Variables de entorno preservadas: ${#ENV_VARS[@]}"

# Volúmenes: preservamos los mismos name:destination montajes.
mapfile -t MOUNT_SPECS < <(
    docker inspect "${CONTAINER_NAME}" \
      --format='{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}:{{.Destination}}{{println}}{{end}}{{end}}'
)

MOUNT_ARGS=()
for spec in "${MOUNT_SPECS[@]}"; do
    if [[ -n "${spec}" ]]; then
        MOUNT_ARGS+=("-v" "${spec}")
    fi
done
info "Volúmenes preservados: ${#MOUNT_ARGS[@]}"

# Puerto interno real del proceso Python
INTERNAL_PORT=$(
    docker exec "${CONTAINER_NAME}" bash -lc "ss -tlnp 2>/dev/null | awk '/python/ {print \$4}' | awk -F: '{print \$NF}' | head -n 1" \
      2>/dev/null || true
)

if [[ -z "${INTERNAL_PORT}" ]]; then
    INTERNAL_PORT=8000
    warn "No se pudo detectar el puerto interno; asumiendo ${INTERNAL_PORT}."
else
    info "Puerto interno detectado: ${INTERNAL_PORT}"
fi

################################################################################
section "Deteniendo el contenedor actual (el ledger sigue corriendo)"

docker stop "${CONTAINER_NAME}" >/dev/null
docker rm "${CONTAINER_NAME}" >/dev/null
info "Contenedor eliminado. Volúmenes y nodos del ledger intactos."

################################################################################
section "Recreando '${CONTAINER_NAME}' con labels Traefik correctas"

ENV_FLAGS=()
for var in "${ENV_VARS[@]}"; do
    ENV_FLAGS+=("-e" "${var}")
done

docker run -d \
    --name "${CONTAINER_NAME}" \
    --network "${PRIMARY_NETWORK}" \
    -p "${HOST_PORT}:${INTERNAL_PORT}" \
    "${ENV_FLAGS[@]}" \
    "${MOUNT_ARGS[@]}" \
    --restart unless-stopped \
    --label "traefik.enable=true" \
    --label "traefik.docker.network=${PROXY_NETWORK}" \
    --label "traefik.http.services.von-network.loadbalancer.server.port=${INTERNAL_PORT}" \
    --label "traefik.http.routers.von-network-web.rule=Host(\`${DOMAIN}\`)" \
    --label "traefik.http.routers.von-network-web.entrypoints=web" \
    --label "traefik.http.routers.von-network-web.middlewares=redirect-to-https@file" \
    --label "traefik.http.routers.von-network-web.service=von-network" \
    --label "traefik.http.routers.von-network.rule=Host(\`${DOMAIN}\`)" \
    --label "traefik.http.routers.von-network.entrypoints=websecure" \
    --label "traefik.http.routers.von-network.tls.certresolver=letsencrypt" \
    --label "traefik.http.routers.von-network.service=von-network" \
    "${IMAGE}" \
    bash -c "cd /home/indy && python -m server.server" \
    >/dev/null

info "Conectando '${CONTAINER_NAME}' a '${PROXY_NETWORK}'..."
docker network connect "${PROXY_NETWORK}" "${CONTAINER_NAME}"

info "Esperando 25 segundos a que el webserver arranque..."
sleep 25

################################################################################
section "Verificando acceso local"

HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:${HOST_PORT}/status" || true)
if [[ "${HTTP_CODE}" == "200" ]]; then
    info "Webserver responde en http://localhost:${HOST_PORT} (HTTP ${HTTP_CODE})"
else
    warn "El webserver no respondió con 200 (actual: ${HTTP_CODE}). Revisá 'docker logs ${CONTAINER_NAME}'."
fi

################################################################################
section "Listo"

cat <<EOF

  El contenedor se recreó con labels Traefik válidas.
  Let's Encrypt debería emitir el certificado automáticamente en 1-3 minutos.

  Verificá el estado público:
      curl -I https://${DOMAIN}/genesis
      curl -I https://${DOMAIN}/browse/domain

  Si seguís viendo el error SSL tras 5 minutos:
      docker logs dokploy-traefik 2>&1 | grep -Ei "${DOMAIN}|acme|letsencrypt" | tail -40

EOF
