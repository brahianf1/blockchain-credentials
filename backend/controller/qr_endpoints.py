from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
import structlog
from storage import qr_storage

logger = structlog.get_logger()
router = APIRouter()

@router.get("/qr/{connection_id}", response_class=HTMLResponse)
async def show_qr_page(connection_id: str):
    """
    Mostrar página HTML con QR Code escaneables para conexión DIDComm
    """
    try:
        # Buscar QR en storage temporal
        if connection_id not in qr_storage:
            raise HTTPException(status_code=404, detail="QR Code no encontrado o expirado")
        
        qr_data = qr_storage[connection_id]
        
        # Página HTML simple con QR
        html_content = f"""
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Credencial W3C - Universidad</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    margin: 0;
                    padding: 20px;
                    min-height: 100vh;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                }}
                .container {{
                    background: white;
                    border-radius: 20px;
                    padding: 40px;
                    box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                    text-align: center;
                    max-width: 500px;
                    width: 100%;
                }}
                h1 {{
                    color: #333;
                    margin-bottom: 10px;
                    font-size: 2em;
                }}
                .subtitle {{
                    color: #666;
                    margin-bottom: 30px;
                    font-size: 1.1em;
                }}
                .qr-container {{
                    background: #f8f9fa;
                    border-radius: 15px;
                    padding: 20px;
                    margin: 20px 0;
                    border: 3px solid #e9ecef;
                }}
                .qr-code {{
                    max-width: 280px;
                    width: 100%;
                    height: auto;
                }}
                .course-info {{
                    background: #e3f2fd;
                    border-radius: 10px;
                    padding: 15px;
                    margin: 20px 0;
                    border-left: 4px solid #2196f3;
                }}
                .student-name {{
                    font-weight: bold;
                    color: #1976d2;
                    font-size: 1.2em;
                }}
                .course-name {{
                    color: #424242;
                    margin-top: 5px;
                }}
                .instructions {{
                    background: #fff3e0;
                    border-radius: 10px;
                    padding: 15px;
                    margin: 20px 0;
                    border-left: 4px solid #ff9800;
                    text-align: left;
                }}
                .instructions h3 {{
                    color: #e65100;
                    margin-top: 0;
                }}
                .instructions ol {{
                    color: #bf360c;
                    line-height: 1.6;
                }}
                .wallet-list {{
                    display: flex;
                    justify-content: center;
                    gap: 10px;
                    margin: 15px 0;
                    flex-wrap: wrap;
                }}
                .wallet {{
                    background: #4caf50;
                    color: white;
                    padding: 5px 12px;
                    border-radius: 20px;
                    font-size: 0.9em;
                    font-weight: bold;
                }}
                .timestamp {{
                    color: #999;
                    font-size: 0.9em;
                    margin-top: 20px;
                }}
                .url-link {{
                    background: #f5f5f5;
                    border-radius: 5px;
                    padding: 10px;
                    margin: 10px 0;
                    font-family: monospace;
                    font-size: 0.8em;
                    word-break: break-all;
                    color: #555;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🎓 Credencial Universitaria</h1>
                <p class="subtitle">Credencial Verificable W3C</p>
                
                <div class="course-info">
                    <div class="student-name">👤 {qr_data['student_name']}</div>
                    <div class="course-name">📚 {qr_data['course_name']}</div>
                </div>
                
                <div class="qr-container">
                    <img src="{qr_data['qr_code_base64']}" 
                         alt="QR Code para Wallet" 
                         class="qr-code">
                </div>
                
                <div class="instructions">
                    <h3>📱 Instrucciones:</h3>
                    <ol>
                        <li>Abre tu wallet de credenciales en tu móvil</li>
                        <li>Busca la opción "Escanear QR" o "Recibir Credencial"</li>
                        <li>Escanea el código QR de arriba</li>
                        <li>Acepta la conexión DIDComm</li>
                        <li>Tu credencial será transferida automáticamente</li>
                    </ol>
                    
                    <div class="wallet-list">
                        <span class="wallet">Lissi</span>
                        <span class="wallet">Trinsic</span>
                        <span class="wallet">Esatus</span>
                    </div>
                </div>
                
                <div class="url-link">
                    <strong>URL de Invitación:</strong><br>
                    {qr_data['invitation_url'][:50]}...
                </div>
                
                <div class="timestamp">
                    ⏰ Generado: {qr_data['timestamp']}<br>
                    🔑 ID: {connection_id}
                </div>
            </div>
        </body>
        </html>
        """
        
        logger.info(f"📱 Página QR solicitada para conexión: {connection_id}")
        return HTMLResponse(content=html_content)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error mostrando QR: {e}")
        raise HTTPException(status_code=500, detail="Error interno del servidor")
