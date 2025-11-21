from typing import Dict, Any

# Almacenamiento temporal de QRs (en producción usar base de datos)
# Estructura: connection_id -> {qr_code_base64, invitation_url, student_name, ...}
qr_storage: Dict[str, Dict[str, Any]] = {}
