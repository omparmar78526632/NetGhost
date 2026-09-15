"""
Unit Tests for Header Channel
Tests IP.id encoding and decoding
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.utils import bytes_to_uint16_list, uint16_list_to_bytes
from common.framing import create_frame, parse_frame
from common.crypto import encrypt_message, decrypt_message


class TestHeaderChannel:
    """Test suite for header channel encoding/decoding"""
    
    def test_bytes_to_uint16(self):
        """Test conversion of bytes to uint16 list"""
        data = b'\xDE\xAD\xBE\xEF'
        uint16_list = bytes_to_uint16_list(data)
        
        assert uint16_list == [0xDEAD, 0xBEEF], "Conversion incorrect"
    
    def test_uint16_to_bytes(self):
        """Test conversion of uint16 list to bytes"""
        uint16_list = [0xDEAD, 0xBEEF]
        data = uint16_list_to_bytes(uint16_list)
        
        assert data == b'\xDE\xAD\xBE\xEF', "Conversion incorrect"
    
    def test_round_trip_conversion(self):
        """Test round trip uint16 conversion"""
        original = b'\x12\x34\x56\x78\x9A\xBC'
        uint16_list = bytes_to_uint16_list(original)
        recovered = uint16_list_to_bytes(uint16_list)
        
        assert recovered == original, "Round trip failed"
    
    def test_odd_length_padding(self):
        """Test that odd-length bytes are padded correctly"""
        data = b'\xAB\xCD\xEF'
        uint16_list = bytes_to_uint16_list(data)
        
        # Should pad with 0x00
        assert uint16_list == [0xABCD, 0xEF00], "Odd length padding incorrect"
    
    def test_header_channel_simulation(self):
        """Test simulated header channel encode/decode"""
        passphrase = "test_password"
        plaintext = "Test message"
        
        # Sender side
        encrypted = encrypt_message(plaintext, passphrase)
        frame = create_frame(encrypted)
        chunks = bytes_to_uint16_list(frame)
        
        assert len(chunks) > 0, "Should produce chunks"
        assert all(0 <= c <= 0xFFFF for c in chunks), "All chunks should be 16-bit"
        
        # Simulate transmission (chunks would be sent in IP.id fields)
        # Receiver side
        reconstructed = uint16_list_to_bytes(chunks)
        payload, consumed = parse_frame(reconstructed)
        
        assert payload is not None, "Should parse frame"
        
        decrypted = decrypt_message(payload, passphrase)
        
        assert decrypted == plaintext, "End-to-end test failed"
    
    def test_short_message(self):
        """Test header channel with short message"""
        passphrase = "pass"
        plaintext = "Hi"
        
        encrypted = encrypt_message(plaintext, passphrase)
        frame = create_frame(encrypted)
        chunks = bytes_to_uint16_list(frame)
        
        # Reconstruct
        reconstructed = uint16_list_to_bytes(chunks)
        payload, _ = parse_frame(reconstructed)
        decrypted = decrypt_message(payload, passphrase)
        
        assert decrypted == plaintext
    
    def test_long_message(self):
        """Test header channel with long message"""
        passphrase = "password123"
        plaintext = "A" * 500
        
        encrypted = encrypt_message(plaintext, passphrase)
        frame = create_frame(encrypted)
        chunks = bytes_to_uint16_list(frame)
        
        print(f"Long message requires {len(chunks)} packets")
        
        # Reconstruct
        reconstructed = uint16_list_to_bytes(chunks)
        payload, _ = parse_frame(reconstructed)
        decrypted = decrypt_message(payload, passphrase)
        
        assert decrypted == plaintext
    
    def test_binary_data(self):
        """Test header channel with binary data"""
        data = bytes(range(256))  # All byte values
        
        uint16_list = bytes_to_uint16_list(data)
        recovered = uint16_list_to_bytes(uint16_list)
        
        assert recovered == data, "Binary data round trip failed"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
