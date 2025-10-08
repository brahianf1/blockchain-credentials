#!/bin/bash
################################################################################
# Script de Instalación Automática de VON Network v6.0 DEFINITIVO
# Incluye: Puerto interno correcto, registro de DIDs habilitado, 
# seed configurada y registro automático del DID de ACA-Py
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_step() {
    echo -e "\n${BLUE}===================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===================================================${NC}\n"
}

print_highlight() {
    echo -e "${CYAN}$1${NC}"
}

get_public_ip() {
    local ip=""
    for service in "ifconfig.me" "icanhazip.com" "ipecho.net/plain" "api.ipify.org"; do
        ip=$(curl -s --max-time 5 "$service" 2>/dev/null | grep -oE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$')
        if [[ -n "$ip" ]]; then
            echo "$ip"
            return 0
        fi
    done
    ip=$(hostname -I | awk '{print $1}')
    if [[ -n "$ip" ]]; then
        echo "$ip"
        return 0
    fi
    return 1
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

check_docker() {
    if ! command_exists docker; then
        print_error "Docker no está instalado."
        exit 1
    fi
    if ! docker ps >/dev/null 2>&1; then
        print_error "No tienes permisos para ejecutar Docker."
        exit 1
    fi
    print_message "Docker está instalado y funcionando correctamente."
}

cleanup_von_network() {
    print_warning "Limpiando instalación previa de VON Network..."
    
    # Detener y eliminar contenedores
    for container in $(docker ps -a --format '{{.Names}}' | grep "von-"); do
        docker stop "$container" 2>/dev/null || true
        docker rm "$container" 2>/dev/null || true
    done
    
    # AGREGADO: Eliminar volúmenes DEL LEDGER (datos persistentes)
    print_message "Eliminando datos persistentes del ledger..."
    for volume in $(docker volume ls -q | grep "von_"); do
        docker volume rm "$volume" 2>/dev/null || true
    done
    
    # Eliminar redes (excepto dokploy)
    for network in $(docker network ls --format '{{.Name}}' | grep "von" | grep -v "dokploy"); do
        docker network rm "$network" 2>/dev/null || true
    done
    
    # Eliminar directorio y archivos
    rm -rf /opt/von-network /opt/von-network-*.* 2>/dev/null || true
    
    print_message "Limpieza completada (incluidos datos del ledger)."
}

################################################################################
print_step "PASO 0: Limpieza Automática Completa"
################################################################################

if docker ps -a --format '{{.Names}}' | grep -q "von-" || [[ -d "/opt/von-network" ]]; then
    print_warning "Detectada instalación previa de VON Network."
    cleanup_von_network
    sleep 3
fi

################################################################################
print_step "PASO 1: Verificación de Requisitos"
################################################################################

if [[ $EUID -ne 0 ]]; then
   print_error "Este script debe ejecutarse como root o con sudo."
   exit 1
fi

check_docker

if ! command_exists unzip; then
    print_message "Instalando dependencias..."
    apt-get update -qq
    apt-get install -y unzip curl net-tools jq
fi

print_message "Detectando IP pública del servidor..."
PUBLIC_IP=$(get_public_ip)

if [[ -z "$PUBLIC_IP" ]]; then
    print_error "No se pudo detectar la IP pública."
    read -p "Ingresa la IP pública manualmente: " PUBLIC_IP
    if [[ -z "$PUBLIC_IP" ]]; then
        print_error "IP pública requerida. Abortando."
        exit 1
    fi
fi

print_message "IP pública detectada: $PUBLIC_IP"

################################################################################
print_step "PASO 2: Descarga de VON Network"
################################################################################

print_message "Descargando VON Network desde GitHub..."
cd /opt

if [[ -f "von-network.zip" ]]; then
    rm -f von-network.zip
fi

curl -L https://github.com/bcgov/von-network/archive/main.zip > von-network.zip
unzip -q von-network.zip
mv von-network-main von-network
cd von-network
chmod a+w ./server/
chmod +x ./manage

################################################################################
print_step "PASO 3: Construcción de Imágenes Docker"
################################################################################

print_message "Construyendo imágenes de VON Network (esto puede tardar 10-15 minutos)..."
./manage build

if [[ $? -ne 0 ]]; then
    print_error "Error al construir las imágenes de VON Network."
    exit 1
fi

print_message "Imágenes construidas exitosamente."

################################################################################
print_step "PASO 4: Inicio de VON Network"
################################################################################

print_message "Iniciando VON Network en $PUBLIC_IP..."
./manage start "$PUBLIC_IP" WEB_SERVER_HOST_PORT=9000 "LEDGER_INSTANCE_NAME=UTN PF Ledger"

print_message "Esperando inicialización de contenedores (30 segundos)..."
sleep 30

################################################################################
print_step "PASO 5: Análisis y Verificación del Contenedor"
################################################################################

WEBSERVER_CONTAINER=$(docker ps --format '{{.Names}}' | grep "webserver" | head -n 1)

if [[ -z "$WEBSERVER_CONTAINER" ]]; then
    print_error "Contenedor webserver no encontrado."
    docker ps --format "table {{.Names}}\t{{.Status}}"
    exit 1
fi

print_message "Contenedor webserver encontrado: $WEBSERVER_CONTAINER"

# Detectar puerto interno
print_message "Detectando puerto interno del webserver..."
sleep 10

WEBSERVER_PORT=""
for i in {1..15}; do
    WEBSERVER_PORT=$(docker exec "$WEBSERVER_CONTAINER" netstat -tlnp 2>/dev/null | grep python | awk '{print $4}' | cut -d: -f2 | head -n 1)
    
    if [[ -z "$WEBSERVER_PORT" ]]; then
        WEBSERVER_PORT=$(docker exec "$WEBSERVER_CONTAINER" ss -tlnp 2>/dev/null | grep python | awk '{print $5}' | cut -d: -f2 | head -n 1)
    fi
    
    if [[ -n "$WEBSERVER_PORT" ]]; then
        break
    fi
    
    print_message "Intento $i/15: Esperando a que el webserver inicie..."
    sleep 5
done

if [[ -z "$WEBSERVER_PORT" ]]; then
    print_warning "No se pudo detectar el puerto. Usando 8000 por defecto."
    WEBSERVER_PORT="8000"
fi

print_message "? Puerto interno detectado: $WEBSERVER_PORT"

################################################################################
print_step "PASO 6: Verificación del Ledger"
################################################################################

print_message "Verificando sincronización del ledger..."
RETRIES=15
LEDGER_OK=false

for i in $(seq 1 $RETRIES); do
    if docker logs "$WEBSERVER_CONTAINER" 2>&1 | grep -q "POOL ledger synced"; then
        LEDGER_OK=true
        break
    fi
    print_message "Intento $i/$RETRIES: Esperando sincronización..."
    sleep 5
done

if [[ "$LEDGER_OK" == "false" ]]; then
    print_error "El ledger no se sincronizó."
    docker logs "$WEBSERVER_CONTAINER" --tail 30
    exit 1
fi

print_message "? Ledger sincronizado correctamente."

################################################################################
print_step "PASO 7: Verificación de Red de Dokploy"
################################################################################

if ! docker network ls | grep -q "dokploy-network"; then
    print_error "La red 'dokploy-network' no existe."
    print_message "Asegúrate de que Dokploy esté instalado correctamente."
    exit 1
fi

print_message "? Red dokploy-network encontrada."

################################################################################
print_step "PASO 8: Recreación del Webserver con Configuración Completa"
################################################################################

print_message "Preparando recreación del contenedor con todas las configuraciones..."

VON_IMAGE=$(docker inspect "$WEBSERVER_CONTAINER" --format='{{.Config.Image}}')
VON_NETWORK=$(docker network ls --format '{{.Name}}' | grep "von_von" | head -n 1)

if [[ -z "$VON_NETWORK" ]]; then
    print_error "Red von_von no encontrada."
    exit 1
fi

# Obtener los volúmenes montados
VOLUME_MOUNTS=""
for vol in $(docker inspect "$WEBSERVER_CONTAINER" --format='{{range .Mounts}}{{.Name}}:{{.Destination}} {{end}}'); do
    vol_name=$(echo $vol | cut -d: -f1)
    vol_dest=$(echo $vol | cut -d: -f2)
    if [[ "$vol_name" != "" ]]; then
        VOLUME_MOUNTS="$VOLUME_MOUNTS -v $vol_name:$vol_dest"
    fi
done

print_message "Volúmenes detectados: $VOLUME_MOUNTS"

# Detener y eliminar contenedor original
docker stop "$WEBSERVER_CONTAINER"
docker rm "$WEBSERVER_CONTAINER"

# Recrear con configuración completa
print_message "Recreando contenedor con:"
print_message "  - Traefik habilitado"
print_message "  - Registro de DIDs habilitado (REGISTER_NEW_DIDS=True)"
print_message "  - Seed del Trust Anchor configurada"
print_message "  - Mapeo de puertos correcto: 9000:${WEBSERVER_PORT}"

docker run -d \
  --name von-webserver \
  --network "$VON_NETWORK" \
  -p 9000:${WEBSERVER_PORT} \
  -e "DOCKERHOST=$PUBLIC_IP" \
  -e "LOG_LEVEL=INFO" \
  -e "RUST_LOG=warning" \
  -e "REGISTER_NEW_DIDS=True" \
  -e "LEDGER_SEED=000000000000000000000000Trustee1" \
  $VOLUME_MOUNTS \
  --restart unless-stopped \
  --label "traefik.enable=true" \
  --label "traefik.http.routers.von-network.rule=Host(\`ledger.utnpf.site\`)" \
  --label "traefik.http.routers.von-network.entrypoints=websecure" \
  --label "traefik.http.routers.von-network.tls.certresolver=myresolver" \
  --label "traefik.http.services.von-network.loadbalancer.server.port=${WEBSERVER_PORT}" \
  --label "traefik.docker.network=dokploy-network" \
  "$VON_IMAGE" \
  bash -c "cd /home/indy && python -m server.server"

print_message "Esperando a que el contenedor inicie (25 segundos)..."
sleep 25

print_message "Conectando a dokploy-network..."
docker network connect dokploy-network von-webserver

print_message "? Contenedor recreado exitosamente."

################################################################################
print_step "PASO 9: Verificación de Configuración"
################################################################################

print_message "Verificando que el registro de DIDs esté habilitado..."
sleep 10

RETRIES=10
CONFIG_OK=false

for i in $(seq 1 $RETRIES); do
    STATUS=$(curl -s http://localhost:9000/status)
    
    if echo "$STATUS" | grep -q '"register_new_dids": true'; then
        CONFIG_OK=true
        print_message "? Registro de DIDs habilitado correctamente."
        break
    fi
    
    print_message "Intento $i/$RETRIES: Esperando configuración..."
    sleep 5
done

if [[ "$CONFIG_OK" == "false" ]]; then
    print_error "El registro de DIDs no está habilitado correctamente."
    curl -s http://localhost:9000/status | jq
    exit 1
fi

################################################################################
print_step "PASO 10: Solicitud de DID Seed de ACA-Py"
################################################################################

print_highlight "\n+----------------------------------------------------------------+"
print_highlight "¦  IMPORTANTE: Configuración del DID de ACA-Py                   ¦"
print_highlight "+----------------------------------------------------------------+\n"

echo -e "${YELLOW}Para completar la instalación, necesitas configurar la seed del DID"
echo -e "que usará ACA-Py. Esta seed debe ser EXACTAMENTE 32 caracteres.${NC}\n"

echo -e "${CYAN}Opciones:${NC}"
echo -e "  1. Generar una seed aleatoria automáticamente (recomendado)"
echo -e "  2. Ingresar una seed manualmente"
echo -e "  3. Saltar este paso (puedes hacerlo después)\n"

read -p "Selecciona una opción (1/2/3): " SEED_OPTION

ACAPY_DID_SEED=""

case "$SEED_OPTION" in
    1)
        print_message "Generando seed aleatoria de 32 caracteres..."
        ACAPY_DID_SEED=$(openssl rand -hex 16)
        print_message "Seed generada: $ACAPY_DID_SEED"
        ;;
    2)
        while true; do
            read -p "Ingresa la seed (32 caracteres): " ACAPY_DID_SEED
            if [[ ${#ACAPY_DID_SEED} -eq 32 ]]; then
                break
            else
                print_error "La seed debe tener exactamente 32 caracteres. Tiene ${#ACAPY_DID_SEED}."
            fi
        done
        ;;
    3)
        print_warning "Saltando configuración del DID. Deberás hacerlo manualmente después."
        ACAPY_DID_SEED=""
        ;;
    *)
        print_error "Opción inválida. Generando seed automáticamente..."
        ACAPY_DID_SEED=$(openssl rand -hex 16)
        print_message "Seed generada: $ACAPY_DID_SEED"
        ;;
esac

if [[ -n "$ACAPY_DID_SEED" ]]; then
    ################################################################################
    print_step "PASO 11: Registro del DID de ACA-Py en el Ledger"
    ################################################################################
    
    print_message "Registrando DID en VON Network..."
    
    REGISTER_RESPONSE=$(curl -s -X POST http://localhost:9000/register \
      -H "Content-Type: application/json" \
      -d "{
        \"seed\": \"$ACAPY_DID_SEED\",
        \"role\": \"ENDORSER\",
        \"alias\": \"ACA-Py Agent\"
      }")
    
    if echo "$REGISTER_RESPONSE" | grep -q '"did"'; then
        REGISTERED_DID=$(echo "$REGISTER_RESPONSE" | jq -r '.did')
        REGISTERED_VERKEY=$(echo "$REGISTER_RESPONSE" | jq -r '.verkey')
        
        print_message "? DID registrado exitosamente en el ledger:"
        echo -e "  ${GREEN}DID:${NC} $REGISTERED_DID"
        echo -e "  ${GREEN}Verkey:${NC} $REGISTERED_VERKEY"
        
        # Guardar información del DID
        cat > /opt/von-network-acapy-did.json <<EOF
{
  "did": "$REGISTERED_DID",
  "verkey": "$REGISTERED_VERKEY",
  "seed": "$ACAPY_DID_SEED",
  "role": "ENDORSER",
  "registered_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
        print_message "? Información del DID guardada en /opt/von-network-acapy-did.json"
    else
        print_error "Error al registrar el DID. Respuesta:"
        echo "$REGISTER_RESPONSE"
        print_warning "Deberás registrar el DID manualmente después."
    fi
fi

################################################################################
print_step "PASO 12: Verificación Final Completa"
################################################################################

print_message "Verificando respuesta del webserver..."
sleep 5

RETRIES=10
GENESIS_OK=false

for i in $(seq 1 $RETRIES); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9000/genesis 2>/dev/null)
    
    if [[ "$HTTP_CODE" == "200" ]]; then
        GENESIS_OK=true
        break
    fi
    
    print_message "Intento $i/$RETRIES: HTTP $HTTP_CODE - Esperando..."
    sleep 5
done

if [[ "$GENESIS_OK" == "false" ]]; then
    print_error "El webserver no responde en el puerto 9000."
    print_message "\nLogs del contenedor:"
    docker logs von-webserver --tail 50
    exit 1
fi

print_message "? Webserver respondiendo correctamente (HTTP 200)."

curl -s http://localhost:9000/genesis > /opt/von-network-genesis.json
print_message "? Genesis guardado en /opt/von-network-genesis.json"

################################################################################
print_step "RESUMEN DE INSTALACIÓN"
################################################################################

echo -e "\n${GREEN}+----------------------------------------------------------------+${NC}"
echo -e "${GREEN}¦          VON Network Instalado Correctamente                   ¦${NC}"
echo -e "${GREEN}+----------------------------------------------------------------+${NC}\n"

echo -e "${BLUE}Configuración del Sistema:${NC}"
echo -e "  • Ubicación: ${GREEN}/opt/von-network${NC}"
echo -e "  • IP Pública: ${GREEN}$PUBLIC_IP${NC}"
echo -e "  • Puerto Interno: ${GREEN}$WEBSERVER_PORT${NC}"
echo -e "  • Puerto Externo: ${GREEN}9000${NC}"
echo -e "  • Imagen: ${GREEN}$VON_IMAGE${NC}"
echo -e "  • Registro de DIDs: ${GREEN}Habilitado${NC}"

echo -e "\n${BLUE}URLs de Acceso a VON Network:${NC}"
echo -e "  • Local: ${GREEN}http://localhost:9000${NC}"
echo -e "  • Pública: ${GREEN}http://$PUBLIC_IP:9000${NC}"
echo -e "  • HTTPS (Traefik): ${GREEN}https://ledger.utnpf.site${NC}"

echo -e "\n${BLUE}IMPORTANTE - Genesis URL para ACA-Py:${NC}"
echo -e "  ${CYAN}+---------------------------------------------------------+${NC}"
echo -e "  ${CYAN}¦${NC} Para comunicación INTERNA entre contenedores (Docker): ${CYAN}¦${NC}"
echo -e "  ${CYAN}¦${NC}   ${YELLOW}http://von-webserver:${WEBSERVER_PORT}/genesis${NC}                  ${CYAN}¦${NC}"
echo -e "  ${CYAN}+---------------------------------------------------------¦${NC}"
echo -e "  ${CYAN}¦${NC} Para acceso EXTERNO (debugging/testing):               ${CYAN}¦${NC}"
echo -e "  ${CYAN}¦${NC}   ${YELLOW}http://$PUBLIC_IP:9000/genesis${NC}                ${CYAN}¦${NC}"
echo -e "  ${CYAN}+---------------------------------------------------------+${NC}"

if [[ -n "$ACAPY_DID_SEED" ]]; then
    echo -e "\n${BLUE}DID de ACA-Py Registrado:${NC}"
    echo -e "  • DID: ${GREEN}$REGISTERED_DID${NC}"
    echo -e "  • Verkey: ${GREEN}$REGISTERED_VERKEY${NC}"
    echo -e "  • Seed: ${YELLOW}$ACAPY_DID_SEED${NC} ${RED}(¡Guárdala de forma segura!)${NC}"
fi

echo -e "\n${BLUE}Variables de Entorno para Dokploy:${NC}"
echo -e "  ${CYAN}+---------------------------------------------------------+${NC}"
echo -e "  ${CYAN}¦${NC} ${YELLOW}ACAPY_GENESIS_URL=http://von-webserver:${WEBSERVER_PORT}/genesis${NC}  ${CYAN}¦${NC}"
if [[ -n "$ACAPY_DID_SEED" ]]; then
echo -e "  ${CYAN}¦${NC} ${YELLOW}ACAPY_DID_SEED=$ACAPY_DID_SEED${NC}        ${CYAN}¦${NC}"
fi
echo -e "  ${CYAN}+---------------------------------------------------------+${NC}"

echo -e "\n${BLUE}Estado de Contenedores:${NC}"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep "von" | sed 's/^/  /'

echo -e "\n${BLUE}Comandos Útiles:${NC}"
echo -e "  • Logs del webserver: ${YELLOW}docker logs von-webserver -f${NC}"
echo -e "  • Logs de un nodo: ${YELLOW}docker logs von-node1-1 -f${NC}"
echo -e "  • Reiniciar webserver: ${YELLOW}docker restart von-webserver${NC}"
echo -e "  • Genesis (local): ${YELLOW}curl http://localhost:9000/genesis${NC}"
echo -e "  • Verificar desde ACA-Py: ${YELLOW}docker exec acapy-agent curl http://von-webserver:${WEBSERVER_PORT}/genesis${NC}"
echo -e "  • Ver DIDs registrados: ${YELLOW}curl http://localhost:9000/browse/domain${NC}"

echo -e "\n${BLUE}Próximos Pasos:${NC}"
echo -e "  ${CYAN}1.${NC} Actualiza las variables en Dokploy con los valores de arriba"
echo -e "  ${CYAN}2.${NC} Haz commit y push de tu docker-compose.yml actualizado"
echo -e "  ${CYAN}3.${NC} Redeploy en Dokploy para aplicar los cambios"

echo -e "\n${GREEN}¡Instalación completada exitosamente!${NC}\n"

# Guardar información completa
cat > /opt/von-network-info.txt <<EOF
VON Network Installation - Complete Information
================================================
Installation Date: $(date)
Installation Directory: /opt/von-network
Public IP: $PUBLIC_IP
Internal Port: $WEBSERVER_PORT
External Port: 9000
Image: $VON_IMAGE

Configuration:
- Register New DIDs: Enabled
- Trust Anchor Seed: 000000000000000000000000Trustee1

URLs:
- Local: http://localhost:9000
- Public: http://$PUBLIC_IP:9000
- HTTPS: https://ledger.utnpf.site

Genesis URL:
- Internal (for ACA-Py): http://von-webserver:$WEBSERVER_PORT/genesis
- External (debugging): http://$PUBLIC_IP:9000/genesis

CRITICAL NOTES:
- Use port $WEBSERVER_PORT for internal container communication
- Use port 9000 for external host access
- ACA-Py must use: ACAPY_GENESIS_URL=http://von-webserver:$WEBSERVER_PORT/genesis
- DID Seed must be EXACTLY 32 characters

$(if [[ -n "$ACAPY_DID_SEED" ]]; then
echo "ACA-Py DID Registration:
- DID: $REGISTERED_DID
- Verkey: $REGISTERED_VERKEY
- Seed: $ACAPY_DID_SEED
- Role: ENDORSER
- Registered: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
"
fi)

Containers:
$(docker ps --format "{{.Names}} - {{.Status}}" | grep "von")

Docker Commands:
- View webserver logs: docker logs von-webserver -f
- View node logs: docker logs von-node1-1 -f
- Restart webserver: docker restart von-webserver
- Verify genesis: curl http://localhost:9000/genesis
- Check from ACA-Py: docker exec acapy-agent curl http://von-webserver:$WEBSERVER_PORT/genesis

Dokploy Environment Variables:
ACAPY_GENESIS_URL=http://von-webserver:$WEBSERVER_PORT/genesis
$(if [[ -n "$ACAPY_DID_SEED" ]]; then
echo "ACAPY_DID_SEED=$ACAPY_DID_SEED"
fi)
EOF

print_message "Información completa guardada en: /opt/von-network-info.txt"

if [[ -n "$ACAPY_DID_SEED" ]]; then
    print_highlight "\n${RED}??  IMPORTANTE: Guarda la seed de forma segura:${NC}"
    print_highlight "${YELLOW}$ACAPY_DID_SEED${NC}\n"
fi

exit 0