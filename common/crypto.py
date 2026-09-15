"""
Cryptography Module: AES-256-GCM Implementation
Provides authenticated encryption for covert channel payloads
"""

import os
import hashlib
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# Constants
PBKDF2_ITERATIONS = 100000
AES_KEY_SIZE = 32  # 256 bits
GCM_NONCE_SIZE = 12  # 96 bits recommended for GCM
SALT_SIZE = 16  # 128 bits


def derive_key(passphrase: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """
    Derive a 256-bit AES key from a passphrase using PBKDF2-HMAC-SHA256.
    
    Args:
        passphrase: User's pre-shared key (password)
        salt: Optional salt; if None, a random salt is generated
    
    Returns:
        Tuple of (derived_key, salt)
    """
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    
    key = kdf.derive(passphrase.encode('utf-8'))
    return key, salt


def encrypt_message(plaintext: str, passphrase: str) -> bytes:
    """
    Encrypt a message using AES-256-GCM.
    
    Format: salt (16) || nonce (12) || ciphertext || tag (16)
    
    Args:
        plaintext: Message to encrypt
        passphrase: Pre-shared key
    
    Returns:
        Encrypted payload with salt, nonce, ciphertext, and tag
    """
    # Derive key from passphrase
    key, salt = derive_key(passphrase)
    
    # Create AES-GCM cipher
    aesgcm = AESGCM(key)
    
    # Generate random nonce
    nonce = os.urandom(GCM_NONCE_SIZE)
    
    # Encrypt and authenticate
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    
    # Combine: salt || nonce || ciphertext (includes tag)
    encrypted_payload = salt + nonce + ciphertext
    
    return encrypted_payload


def decrypt_message(encrypted_payload: bytes, passphrase: str) -> str:
    """
    Decrypt a message using AES-256-GCM.
    
    Args:
        encrypted_payload: salt || nonce || ciphertext || tag
        passphrase: Pre-shared key
    
    Returns:
        Decrypted plaintext
    
    Raises:
        ValueError: If authentication fails or decryption fails
        Exception: If payload format is invalid
    """
    # Validate minimum size
    min_size = SALT_SIZE + GCM_NONCE_SIZE + 16  # salt + nonce + tag
    if len(encrypted_payload) < min_size:
        raise ValueError("Encrypted payload too short")
    
    # Extract components
    salt = encrypted_payload[:SALT_SIZE]
    nonce = encrypted_payload[SALT_SIZE:SALT_SIZE + GCM_NONCE_SIZE]
    ciphertext = encrypted_payload[SALT_SIZE + GCM_NONCE_SIZE:]
    
    # Derive key from passphrase and salt
    key, _ = derive_key(passphrase, salt)
    
    # Create AES-GCM cipher
    aesgcm = AESGCM(key)
    
    # Decrypt and verify
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")


def test_crypto():
    """Quick self-test of crypto functions"""
    passphrase = "test_password_123"
    message = "Hello, NetGhost!"
    
    # Encrypt
    encrypted = encrypt_message(message, passphrase)
    print(f"Encrypted length: {len(encrypted)} bytes")
    
    # Decrypt
    decrypted = decrypt_message(encrypted, passphrase)
    print(f"Decrypted: {decrypted}")
    
    assert decrypted == message, "Round-trip failed!"
    
    # Test wrong password
    try:
        decrypt_message(encrypted, "wrong_password")
        assert False, "Should have failed with wrong password"
    except ValueError:
        print("Wrong password correctly rejected")
    
    # Test tampering
    try:
        tampered = encrypted[:-1] + bytes([encrypted[-1] ^ 0xFF])
        decrypt_message(tampered, passphrase)
        assert False, "Should have detected tampering"
    except ValueError:
        print("Tampering correctly detected")
    
    print("Crypto self-test passed!")


if __name__ == "__main__":
    test_crypto()
