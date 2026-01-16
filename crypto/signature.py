"""
Digital Signature Module
Modul untuk membuat dan memverifikasi tanda tangan digital menggunakan RSA dan SHA-256
"""

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64


def f20221310104_hash_message(message: str) -> SHA256.SHA256Hash:
    """
    Hash pesan menggunakan algoritma SHA-256
    
    Args:
        message: Pesan yang akan di-hash
    
    Returns:
        SHA256 hash object
    """
    return SHA256.new(message.encode('utf-8'))


def f20221310104_sign_message(message: str, private_key: RSA.RsaKey) -> str:
    """
    Buat digital signature dari pesan menggunakan private key
    
    Proses:
    1. Hash pesan dengan SHA-256
    2. Enkripsi hash dengan private key RSA
    3. Encode hasil ke base64
    
    Args:
        message: Pesan yang akan ditandatangani
        private_key: RSA private key untuk signing
    
    Returns:
        Digital signature dalam format base64 string
    """
    # Hash pesan dengan SHA-256
    message_hash = f20221310104_hash_message(message)
    
    # Tanda tangani hash dengan private key
    signature = pkcs1_15.new(private_key).sign(message_hash)
    
    # Encode ke base64 untuk kemudahan penyimpanan/transfer
    return base64.b64encode(signature).decode('utf-8')


def f20221310104_verify_signature(message: str, signature: str, public_key: RSA.RsaKey) -> bool:
    """
    Verifikasi digital signature menggunakan public key
    
    Proses:
    1. Decode signature dari base64
    2. Hash pesan asli dengan SHA-256
    3. Verifikasi signature dengan public key
    4. Bandingkan hasil dekripsi dengan hash pesan
    
    Args:
        message: Pesan asli yang perlu diverifikasi
        signature: Digital signature dalam format base64
        public_key: RSA public key untuk verifikasi
    
    Returns:
        True jika signature valid, False jika tidak
    """
    try:
        # Clean signature string - remove whitespace and newlines
        signature_clean = signature.strip().replace('\n', '').replace('\r', '').replace(' ', '')
        
        # Fix base64 padding if needed
        padding_needed = len(signature_clean) % 4
        if padding_needed:
            signature_clean += '=' * (4 - padding_needed)
        
        # Decode signature dari base64
        signature_bytes = base64.b64decode(signature_clean)
        
        # Hash pesan yang diterima
        message_hash = f20221310104_hash_message(message)
        
        # Verifikasi signature
        pkcs1_15.new(public_key).verify(message_hash, signature_bytes)
        
        return True
    except (ValueError, TypeError) as e:
        print(f"Verification error: {e}")
        return False


def f20221310104_get_hash_hex(message: str) -> str:
    """
    Dapatkan hash pesan dalam format hexadecimal
    
    Args:
        message: Pesan yang akan di-hash
    
    Returns:
        Hash dalam format hex string
    """
    return f20221310104_hash_message(message).hexdigest()
