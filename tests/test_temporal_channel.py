"""
Unit Tests for Temporal Channel
Tests bit encoding and timing-based decoding
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.utils import bytes_to_bits, bits_to_bytes
from common.framing import create_frame, parse_frame
from common.crypto import encrypt_message, decrypt_message


class TestTemporalChannel:
    """Test suite for temporal channel encoding/decoding"""
    
    def test_bytes_to_bits(self):
        """Test conversion of bytes to bits"""
        data = b'\xAB'  # 10101011
        bits = bytes_to_bits(data)
        
        expected = [1, 0, 1, 0, 1, 0, 1, 1]
        assert bits == expected, "Bit conversion incorrect"
    
    def test_bits_to_bytes(self):
        """Test conversion of bits to bytes"""
        bits = [1, 0, 1, 0, 1, 0, 1, 1]
        data = bits_to_bytes(bits)
        
        assert data == b'\xAB', "Byte conversion incorrect"
    
    def test_round_trip_bits(self):
        """Test round trip bit conversion"""
        original = b'\x12\x34\x56'
        bits = bytes_to_bits(original)
        recovered = bits_to_bytes(bits)
        
        assert recovered == original, "Round trip failed"
    
    def test_bit_padding(self):
        """Test that incomplete bit sequences are padded"""
        bits = [1, 0, 1]  # Only 3 bits
        data = bits_to_bytes(bits)
        
        # Should pad to 8 bits: 10100000
        assert data == b'\xA0', "Padding incorrect"
    
    def test_temporal_channel_simulation(self):
        """Test simulated temporal channel encode/decode"""
        passphrase = "test_password"
        plaintext = "Test"
        
        # Sender side
        encrypted = encrypt_message(plaintext, passphrase)
        frame = create_frame(encrypted)
        bits = bytes_to_bits(frame)
        
        assert len(bits) > 0, "Should produce bits"
        assert all(b in [0, 1] for b in bits), "All values should be 0 or 1"
        
        print(f"Temporal channel requires {len(bits)} packets")
        
        # Simulate transmission with timing
        # (In real implementation, each bit would be sent as a timed packet)
        
        # Receiver side
        reconstructed = bits_to_bytes(bits)
        payload, consumed = parse_frame(reconstructed)
        
        assert payload is not None, "Should parse frame"
        
        decrypted = decrypt_message(payload, passphrase)
        
        assert decrypted == plaintext, "End-to-end test failed"
    
    def test_threshold_classifier(self):
        """Test threshold-based bit classification"""
        # Simulated inter-packet delays (ms)
        delays = [45, 52, 95, 103, 48, 105, 50, 98]
        threshold = 75
        
        # Classify bits
        bits = [0 if d < threshold else 1 for d in delays]
        
        expected = [0, 0, 1, 1, 0, 1, 0, 1]
        assert bits == expected, "Threshold classification incorrect"
    
    def test_jitter_tolerance(self):
        """Test tolerance to timing jitter"""
        # Delays with jitter
        # Target: bit 0 = 50ms, bit 1 = 100ms
        # With +/- 10ms jitter
        delays_0 = [45, 48, 52, 55, 58]  # bit 0 with jitter
        delays_1 = [92, 95, 98, 105, 108]  # bit 1 with jitter
        
        threshold = 75
        
        bits_0 = [0 if d < threshold else 1 for d in delays_0]
        bits_1 = [0 if d < threshold else 1 for d in delays_1]
        
        # All should classify correctly
        assert all(b == 0 for b in bits_0), "Bit 0 classification with jitter failed"
        assert all(b == 1 for b in bits_1), "Bit 1 classification with jitter failed"
    
    def test_timing_sequence(self):
        """Test encoding and decoding of bit sequence"""
        # Original message
        message_bits = [1, 0, 1, 1, 0, 1, 0, 0]
        
        # Simulate timing encoding
        bit_0_delay = 50
        bit_1_delay = 100
        delays = [bit_1_delay if bit else bit_0_delay for bit in message_bits]
        
        # Simulate timing decoding
        threshold = 75
        decoded_bits = [0 if d < threshold else 1 for d in delays]
        
        assert decoded_bits == message_bits, "Timing sequence failed"
    
    def test_all_zeros(self):
        """Test sequence of all zeros"""
        data = b'\x00'
        bits = bytes_to_bits(data)
        
        assert bits == [0] * 8, "All zeros failed"
        
        recovered = bits_to_bytes(bits)
        assert recovered == data
    
    def test_all_ones(self):
        """Test sequence of all ones"""
        data = b'\xFF'
        bits = bytes_to_bits(data)
        
        assert bits == [1] * 8, "All ones failed"
        
        recovered = bits_to_bytes(bits)
        assert recovered == data
    
    def test_bit_count(self):
        """Test that bit count is correct for messages of various lengths"""
        test_cases = [
            (b"A", 8),
            (b"AB", 16),
            (b"ABC", 24),
            (b"\x00\xFF", 16),
        ]
        
        for data, expected_bits in test_cases:
            bits = bytes_to_bits(data)
            assert len(bits) == expected_bits, f"Bit count incorrect for {data}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
