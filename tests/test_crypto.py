"""
Unit Tests for Cryptography Module
Tests AES-256-GCM encryption and decryption
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.crypto import derive_key, encrypt_message, decrypt_message


class TestCrypto:
    """Test suite for cryptography module"""
    
    def test_key_derivation(self):
        """Test PBKDF2 key derivation"""
        passphrase = "test_password"
        key1, salt1 = derive_key(passphrase)
        
        # Check key length
        assert len(key1) == 32, "Key should be 32 bytes (256 bits)"
        
        # Check salt length
        assert len(salt1) == 16, "Salt should be 16 bytes"
        
        # Different salt should give different key
        key2, salt2 = derive_key(passphrase)
        assert key1 != key2, "Different salts should produce different keys"
        
        # Same salt should give same key
        key3, _ = derive_key(passphrase, salt1)
        assert key1 == key3, "Same salt should produce same key"
    
    def test_encryption_decryption_round_trip(self):
        """Test encrypt and decrypt round trip"""
        passphrase = "my_secret_password"
        plaintext = "Hello, NetGhost!"
        
        # Encrypt
        encrypted = encrypt_message(plaintext, passphrase)
        
        # Verify encrypted is different from plaintext
        assert encrypted != plaintext.encode(), "Ciphertext should differ from plaintext"
        
        # Decrypt
        decrypted = decrypt_message(encrypted, passphrase)
        
        # Verify round trip
        assert decrypted == plaintext, "Decrypted text should match original"
    
    def test_wrong_password_fails(self):
        """Test that wrong password fails decryption"""
        passphrase = "correct_password"
        plaintext = "Secret message"
        
        encrypted = encrypt_message(plaintext, passphrase)
        
        # Try to decrypt with wrong password
        with pytest.raises(ValueError):
            decrypt_message(encrypted, "wrong_password")
    
    def test_tampering_detected(self):
        """Test that tampering is detected"""
        passphrase = "password123"
        plaintext = "Important message"
        
        encrypted = encrypt_message(plaintext, passphrase)
        
        # Tamper with last byte
        tampered = encrypted[:-1] + bytes([encrypted[-1] ^ 0xFF])
        
        # Should fail authentication
        with pytest.raises(ValueError):
            decrypt_message(tampered, passphrase)
    
    def test_short_message(self):
        """Test encryption of short message"""
        passphrase = "pass"
        plaintext = "Hi"
        
        encrypted = encrypt_message(plaintext, passphrase)
        decrypted = decrypt_message(encrypted, passphrase)
        
        assert decrypted == plaintext
    
    def test_long_message(self):
        """Test encryption of long message"""
        passphrase = "long_password"
        plaintext = "A" * 1000
        
        encrypted = encrypt_message(plaintext, passphrase)
        decrypted = decrypt_message(encrypted, passphrase)
        
        assert decrypted == plaintext
    
    def test_empty_message(self):
        """Test encryption of empty message"""
        passphrase = "password"
        plaintext = ""
        
        encrypted = encrypt_message(plaintext, passphrase)
        decrypted = decrypt_message(encrypted, passphrase)
        
        assert decrypted == plaintext
    
    def test_special_characters(self):
        """Test encryption with special characters"""
        passphrase = "password!@#$%"
        plaintext = "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?"
        
        encrypted = encrypt_message(plaintext, passphrase)
        decrypted = decrypt_message(encrypted, passphrase)
        
        assert decrypted == plaintext
    
    def test_unicode_message(self):
        """Test encryption of unicode message"""
        passphrase = "password"
        plaintext = "Hello 世界 🌍"
        
        encrypted = encrypt_message(plaintext, passphrase)
        decrypted = decrypt_message(encrypted, passphrase)
        
        assert decrypted == plaintext
    
    def test_nonce_uniqueness(self):
        """Test that nonces are unique across encryptions"""
        passphrase = "password"
        plaintext = "Same message"
        
        encrypted1 = encrypt_message(plaintext, passphrase)
        encrypted2 = encrypt_message(plaintext, passphrase)
        
        # Nonces should be different, so ciphertexts should differ
        assert encrypted1 != encrypted2, "Same plaintext should produce different ciphertext"
    
    def test_invalid_payload_format(self):
        """Test handling of invalid encrypted payload"""
        passphrase = "password"
        
        # Too short payload
        with pytest.raises(ValueError):
            decrypt_message(b"short", passphrase)
        
        # Random bytes
        with pytest.raises(ValueError):
            decrypt_message(b"X" * 100, passphrase)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
