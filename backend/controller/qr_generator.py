#!/usr/bin/env python3
"""
QR Generator - Generador de códigos QR para invitaciones de conexión
Para wallets de credenciales verificables W3C
"""

import qrcode
import base64
from io import BytesIO
from PIL import Image
import logging

logger = logging.getLogger(__name__)

class QRGenerator:
    """Generador de códigos QR para invitaciones DIDComm"""
    
    def __init__(self):
        self.qr_config = {
            'version': 1,
            'error_correction': qrcode.constants.ERROR_CORRECT_L,
            'box_size': 10,
            'border': 4,
        }
    
    def generate_qr(self, invitation_url: str) -> str:
        """
        Generar código QR en base64 para invitación de conexión
        
        Args:
            invitation_url: URL de invitación DIDComm de ACA-Py
            
        Returns:
            str: Imagen QR en formato base64
        """
        try:
            logger.info("🔳 Generando código QR para invitación...")
            
            # Crear código QR
            qr = qrcode.QRCode(**self.qr_config)
            qr.add_data(invitation_url)
            qr.make(fit=True)
            
            # Generar imagen del QR
            qr_img = qr.make_image(fill_color="black", back_color="white")
            
            # Convertir a base64
            buffer = BytesIO()
            qr_img.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode()
            
            logger.info("✅ Código QR generado exitosamente")
            
            return f"data:image/png;base64,{img_str}"
            
        except Exception as e:
            logger.error(f"❌ Error generando QR: {e}")
            raise Exception(f"Error generando código QR: {e}")
    
    def generate_qr_with_logo(self, invitation_url: str, logo_path: str = None) -> str:
        """
        Generar código QR con logo de la universidad
        
        Args:
            invitation_url: URL de invitación
            logo_path: Ruta al logo de la universidad
            
        Returns:
            str: Imagen QR con logo en base64
        """
        try:
            # Generar QR base
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_H,  # Mayor corrección para permitir logo
                box_size=10,
                border=4,
            )
            qr.add_data(invitation_url)
            qr.make(fit=True)
            
            # Crear imagen QR
            qr_img = qr.make_image(fill_color="black", back_color="white").convert('RGB')
            
            # Agregar logo si existe
            if logo_path and os.path.exists(logo_path):
                try:
                    logo = Image.open(logo_path)
                    
                    # Calcular tamaño del logo (10% del QR)
                    qr_width, qr_height = qr_img.size
                    logo_size = int(qr_width * 0.1)
                    
                    # Redimensionar logo
                    logo = logo.resize((logo_size, logo_size), Image.Resampling.LANCZOS)
                    
                    # Posición central
                    logo_pos = ((qr_width - logo_size) // 2, (qr_height - logo_size) // 2)
                    
                    # Pegar logo en el centro
                    qr_img.paste(logo, logo_pos)
                    
                    logger.info("✅ Logo agregado al código QR")
                    
                except Exception as logo_error:
                    logger.warning(f"⚠️ No se pudo agregar logo: {logo_error}")
            
            # Convertir a base64
            buffer = BytesIO()
            qr_img.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode()
            
            return f"data:image/png;base64,{img_str}"
            
        except Exception as e:
            logger.error(f"❌ Error generando QR con logo: {e}")
            # Fallback a QR simple
            return self.generate_qr(invitation_url)
    
    def validate_qr_content(self, invitation_url: str) -> bool:
        """
        Validar que el contenido del QR sea una invitación válida
        
        Args:
            invitation_url: URL a validar
            
        Returns:
            bool: True si es válida
        """
        try:
            # Validaciones básicas
            if not invitation_url:
                return False
            
            # Debe ser una URL válida
            if not (invitation_url.startswith('http://') or invitation_url.startswith('https://')):
                return False
            
            # Debe contener parámetros de invitación DIDComm
            required_params = ['c_i=', 'oob=']  # Parámetros típicos de ACA-Py
            has_invitation_param = any(param in invitation_url for param in required_params)
            
            if not has_invitation_param:
                logger.warning("⚠️ URL no parece ser una invitación DIDComm válida")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Error validando contenido QR: {e}")
            return False
    
    def generate_qr_for_wallet_testing(self, test_data: dict) -> str:
        """
        Generar QR para pruebas con wallets específicos
        Incluye metadatos adicionales para compatibilidad
        """
        try:
            # Formato de invitación extendido para mejor compatibilidad
            invitation_data = {
                "type": "https://didcomm.org/out-of-band/1.1/invitation",
                "id": test_data.get("invitation_id", "test-invitation"),
                "label": test_data.get("label", "Universidad - Credencial"),
                "goal_code": "issue-vc",
                "goal": "Emisión de Credencial Universitaria",
                "services": test_data.get("services", []),
                "requests~attach": test_data.get("attachments", [])
            }
            
            # Si hay URL de invitación, usarla directamente
            if "invitation_url" in test_data:
                return self.generate_qr(test_data["invitation_url"])
            
            # Sino, generar del objeto JSON
            import json
            invitation_json = json.dumps(invitation_data)
            return self.generate_qr(invitation_json)
            
        except Exception as e:
            logger.error(f"❌ Error generando QR de prueba: {e}")
            raise

# Funciones de utilidad
def create_university_qr(invitation_url: str, university_name: str = "Universidad") -> str:
    """Función de conveniencia para generar QR universitario"""
    generator = QRGenerator()
    
    # Validar URL
    if not generator.validate_qr_content(invitation_url):
        raise ValueError("URL de invitación inválida")
    
    return generator.generate_qr(invitation_url)

def test_qr_generation():
    """Función de prueba para verificar generación de QR"""
    try:
        generator = QRGenerator()
        
        # URL de prueba (formato típico de ACA-Py)
        test_url = "http://localhost:8021/invite?c_i=eyJ0eXBlIjogImh0dHBzOi8vZGlkY29tbS5vcmcvb3V0LW9mLWJhbmQvMS4xL2ludml0YXRpb24iLCAiaWQiOiAiMTIzNDUiLCAibGFiZWwiOiAiVGVzdCJ9"
        
        qr_code = generator.generate_qr(test_url)
        
        print("✅ QR generado exitosamente")
        print(f"Tamaño: {len(qr_code)} caracteres")
        print(f"Formato: {qr_code[:50]}...")
        
        return True
        
    except Exception as e:
        print(f"❌ Error en prueba: {e}")
        return False

if __name__ == "__main__":
    # Ejecutar prueba si se llama directamente
    test_qr_generation()