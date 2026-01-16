"""
QRIS Generator Module
Modul untuk menghasilkan dan membaca QRIS yang berisi digital signature
"""

import qrcode
from qrcode.constants import ERROR_CORRECT_H
from PIL import Image
import json
import base64
from io import BytesIO
from typing import Dict, Any, Optional


def f20221310104_generate_qris(data: str, box_size: int = 10, border: int = 4) -> Image.Image:
    """
    Generate QRIS image dari data string
    
    Args:
        data: Data yang akan dienkode ke dalam QR code
        box_size: Ukuran setiap box dalam QR code
        border: Ukuran border QR code
    
    Returns:
        PIL Image object dari QR code
    """
    qr = qrcode.QRCode(
        version=None,  # Auto-size
        error_correction=ERROR_CORRECT_H,  # High error correction
        box_size=box_size,
        border=border,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    # Buat QR code dengan warna custom
    img = qr.make_image(fill_color="#1a1a2e", back_color="white")
    return img.convert('RGB')


def f20221310104_create_signature_qris(
    message: str, 
    signature: str, 
    public_key_pem: str
) -> Image.Image:
    """
    Buat QRIS yang berisi pesan, signature, dan public key
    
    Args:
        message: Pesan asli
        signature: Digital signature dalam format base64
        public_key_pem: Public key dalam format PEM
    
    Returns:
        PIL Image object dari QRIS
    """
    # Buat payload JSON
    payload = {
        "type": "digital_signature",
        "version": "1.0",
        "message": message,
        "signature": signature,
        "public_key": public_key_pem
    }
    
    # Convert ke JSON string
    json_data = json.dumps(payload, ensure_ascii=False)
    
    # Encode ke base64 untuk mengurangi ukuran
    encoded_data = base64.b64encode(json_data.encode('utf-8')).decode('utf-8')
    
    return f20221310104_generate_qris(encoded_data)


def f20221310104_decode_qris_data(encoded_data: str) -> Optional[Dict[str, Any]]:
    """
    Decode data QRIS dan extract payload
    
    Args:
        encoded_data: Data yang di-encode dari QRIS
    
    Returns:
        Dictionary berisi payload atau None jika gagal
    """
    try:
        # Decode dari base64
        json_data = base64.b64decode(encoded_data.encode('utf-8')).decode('utf-8')
        
        # Parse JSON
        payload = json.loads(json_data)
        
        # Validasi struktur
        required_fields = ['type', 'message', 'signature', 'public_key']
        if all(field in payload for field in required_fields):
            return payload
        
        return None
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return None


def f20221310104_qris_to_bytes(qr_image: Image.Image, format: str = 'PNG') -> bytes:
    """
    Convert QRIS image ke bytes
    
    Args:
        qr_image: PIL Image object
        format: Format gambar (PNG, JPEG, etc.)
    
    Returns:
        Image bytes
    """
    buffer = BytesIO()
    qr_image.save(buffer, format=format)
    buffer.seek(0)
    return buffer.getvalue()
