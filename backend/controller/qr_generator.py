#!/usr/bin/env python3
"""
QR Generator — Generador de códigos QR para credenciales verificables.

Genera códigos QR para ofertas de credenciales OpenID4VCI que los
alumnos escanean con wallets compatibles (Lissi, WaltID, EUDI, etc.).
"""

import base64
import logging
from io import BytesIO

import qrcode
from PIL import Image

logger = logging.getLogger(__name__)


class QRGenerator:
    """Generador de códigos QR para ofertas de credenciales."""

    def __init__(self):
        self.qr_config = {
            'version': 1,
            'error_correction': qrcode.constants.ERROR_CORRECT_L,
            'box_size': 10,
            'border': 4,
        }

    def generate_qr(self, url: str) -> str:
        """Generar código QR en base64 para una URL de oferta.

        Args:
            url: URL de oferta OpenID4VCI o de verificación pública.

        Returns:
            str: Imagen QR en formato data URI (``data:image/png;base64,...``).
        """
        try:
            logger.info("🔳 Generando código QR...")

            qr = qrcode.QRCode(**self.qr_config)
            qr.add_data(url)
            qr.make(fit=True)

            qr_img = qr.make_image(fill_color="black", back_color="white")

            buffer = BytesIO()
            qr_img.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode()

            logger.info("✅ Código QR generado exitosamente")

            return f"data:image/png;base64,{img_str}"

        except Exception as e:
            logger.error(f"❌ Error generando QR: {e}")
            raise Exception(f"Error generando código QR: {e}")

    def generate_qr_with_logo(self, url: str, logo_path: str = None) -> str:
        """Generar código QR con logo de la universidad.

        Args:
            url: URL a codificar en el QR.
            logo_path: Ruta al logo de la universidad.

        Returns:
            str: Imagen QR con logo en data URI base64.
        """
        try:
            import os

            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_H,
                box_size=10,
                border=4,
            )
            qr.add_data(url)
            qr.make(fit=True)

            qr_img = qr.make_image(
                fill_color="black", back_color="white"
            ).convert('RGB')

            if logo_path and os.path.exists(logo_path):
                try:
                    logo = Image.open(logo_path)

                    qr_width, qr_height = qr_img.size
                    logo_size = int(qr_width * 0.1)

                    logo = logo.resize(
                        (logo_size, logo_size), Image.Resampling.LANCZOS
                    )

                    logo_pos = (
                        (qr_width - logo_size) // 2,
                        (qr_height - logo_size) // 2,
                    )

                    qr_img.paste(logo, logo_pos)
                    logger.info("✅ Logo agregado al código QR")

                except Exception as logo_error:
                    logger.warning(f"⚠️ No se pudo agregar logo: {logo_error}")

            buffer = BytesIO()
            qr_img.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode()

            return f"data:image/png;base64,{img_str}"

        except Exception as e:
            logger.error(f"❌ Error generando QR con logo: {e}")
            return self.generate_qr(url)

    def validate_qr_content(self, url: str) -> bool:
        """Validar que el contenido del QR sea una URL válida.

        Args:
            url: URL a validar.

        Returns:
            bool: ``True`` si es una URL HTTPS válida.
        """
        try:
            if not url:
                return False

            if not (url.startswith('http://') or url.startswith('https://')):
                return False

            return True

        except Exception as e:
            logger.error(f"❌ Error validando contenido QR: {e}")
            return False