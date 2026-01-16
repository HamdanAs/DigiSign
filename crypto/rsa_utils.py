"""
RSA Key Generation and Management Utilities
Modul untuk menghasilkan dan mengelola kunci RSA
"""

from Crypto.PublicKey import RSA
from typing import Tuple


def f20221310104_generate_key_pair(key_size: int = 2048) -> Tuple[RSA.RsaKey, RSA.RsaKey]:
    """
    Generate RSA key pair (public key dan private key)
    
    Args:
        key_size: Ukuran kunci dalam bit (default: 2048)
    
    Returns:
        Tuple berisi (private_key, public_key)
    """
    private_key = RSA.generate(key_size)
    public_key = private_key.publickey()
    return private_key, public_key


def f20221310104_export_public_key(key: RSA.RsaKey) -> str:
    """
    Export public key ke format PEM
    
    Args:
        key: RSA public key object
    
    Returns:
        Public key dalam format PEM string
    """
    return key.export_key(format='PEM').decode('utf-8')


def f20221310104_export_private_key(key: RSA.RsaKey) -> str:
    """
    Export private key ke format PEM
    
    Args:
        key: RSA private key object
    
    Returns:
        Private key dalam format PEM string
    """
    return key.export_key(format='PEM').decode('utf-8')


def f20221310104_import_public_key(pem: str) -> RSA.RsaKey:
    """
    Import public key dari format PEM
    
    Args:
        pem: Public key dalam format PEM string
    
    Returns:
        RSA public key object
    """
    return RSA.import_key(pem.encode('utf-8'))


def f20221310104_import_private_key(pem: str) -> RSA.RsaKey:
    """
    Import private key dari format PEM
    
    Args:
        pem: Private key dalam format PEM string
    
    Returns:
        RSA private key object
    """
    return RSA.import_key(pem.encode('utf-8'))
