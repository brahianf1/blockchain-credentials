#!/bin/bash
################################################################################
# Script de Limpieza Completa de VON Network
# ADVERTENCIA: Este script SOLO elimina VON Network, NO toca Dokploy
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_message() {
    echo -e "${GREEN}[LIMPIEZA]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[ADVERTENCIA]${NC} $1"
}

echo -e "\n${RED}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║     LIMPIEZA COMPLETA DE VON NETWORK                           ║${NC}"
echo -e "${RED}║     (NO afecta a Dokploy ni otros servicios)                   ║${NC}"
echo -e "${RED}╚════════════════════════════════════════════════════════════════╝${NC}\n"

read -p "¿Estás seguro de que deseas eliminar VON Network? (s/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Ss]$ ]]; then
    echo "Operación cancelada."
    exit 0
fi

print_message "Iniciando limpieza de VON Network..."

# 1. Detener y eliminar contenedores de VON Network
print_message "Deteniendo contenedores de VON Network..."
docker stop $(docker ps -a | grep "von-" | awk '{print $1}') 2>/dev/null || true

print_message "Eliminando contenedores de VON Network..."
docker rm $(docker ps -a | grep "von-" | awk '{print $1}') 2>/dev/null || true

# 2. Eliminar volúmenes de VON Network
print_message "Eliminando volúmenes de VON Network..."
docker volume rm $(docker volume ls -q | grep "von_") 2>/dev/null || true

# 3. Eliminar redes de VON Network (solo si no están en uso)
print_message "Eliminando redes de VON Network..."
docker network rm $(docker network ls | grep "von" | grep -v "dokploy" | awk '{print $2}') 2>/dev/null || true

# 4. Eliminar imágenes de VON Network
print_message "Eliminando imágenes de VON Network..."
docker rmi von-network-base 2>/dev/null || true
docker rmi $(docker images | grep "von-" | awk '{print $3}') 2>/dev/null || true

# 5. Eliminar directorio de VON Network
if [[ -d "/opt/von-network" ]]; then
    print_message "Eliminando directorio /opt/von-network..."
    rm -rf /opt/von-network
fi

# 6. Eliminar archivos de información
if [[ -f "/opt/von-network-info.txt" ]]; then
    print_message "Eliminando archivo de información..."
    rm -f /opt/von-network-info.txt
fi

if [[ -f "/opt/von-network-genesis.json" ]]; then
    print_message "Eliminando archivo genesis..."
    rm -f /opt/von-network-genesis.json
fi

# Verificar limpieza
print_message "Verificando limpieza..."

REMAINING_CONTAINERS=$(docker ps -a | grep "von-" | wc -l)
REMAINING_VOLUMES=$(docker volume ls -q | grep "von_" | wc -l)
REMAINING_NETWORKS=$(docker network ls | grep "von" | grep -v "dokploy" | wc -l)

if [[ $REMAINING_CONTAINERS -eq 0 && $REMAINING_VOLUMES -eq 0 && $REMAINING_NETWORKS -eq 0 ]]; then
    echo -e "\n${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     VON Network eliminado completamente                        ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}\n"
else
    print_warning "Algunos recursos no pudieron eliminarse:"
    echo "  - Contenedores restantes: $REMAINING_CONTAINERS"
    echo "  - Volúmenes restantes: $REMAINING_VOLUMES"
    echo "  - Redes restantes: $REMAINING_NETWORKS"
fi

print_message "Limpieza completada."
