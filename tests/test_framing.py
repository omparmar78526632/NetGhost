"""
Unit Tests for Framing Module
Tests frame creation and parsing
"""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.framing import create_frame, parse_frame, find_sync_marker, SYNC_MARKER


class TestFraming:
    """Test suite for framing module"""
    
    def test_create_frame_normal(self):
        """Test frame creation with normal payload"""
        payload = b"Hello, World!"
        frame = create_frame(payload)
        
        # Check frame structure
        assert len(frame) == 4 + len(payload), "Frame size incorrect"
        
        # Check sync marker (first 2 bytes)
        sync = int.from_bytes(frame[0:2], 'big')
        assert sync == SYNC_MARKER, "Sync marker incorrect"
        
        # Check length field (next 2 bytes)
        length = int.from_bytes(frame[2:4], 'big')
        assert length == len(payload), "Length field incorrect"
        
        # Check payload
        assert frame[4:] == payload, "Payload incorrect"
    
    def test_create_frame_empty(self):
        """Test frame creation with empty payload"""
        payload = b""
        frame = create_frame(payload)
        
        assert len(frame) == 4, "Empty frame should be 4 bytes (header only)"
        
        sync = int.from_bytes(frame[0:2], 'big')
        assert sync == SYNC_MARKER
        
        length = int.from_bytes(frame[2:4], 'big')
        assert length == 0
    
    def test_create_frame_large(self):
        """Test frame creation with large payload"""
        payload = b"X" * 10000
        frame = create_frame(payload)
        
        assert len(frame) == 4 + len(payload)
        
        sync = int.from_bytes(frame[0:2], 'big')
        assert sync == SYNC_MARKER
        
        length = int.from_bytes(frame[2:4], 'big')
        assert length == len(payload)
    
    def test_create_frame_too_large(self):
        """Test that oversized payload raises error"""
        payload = b"X" * 70000  # > 65535
        
        with pytest.raises(ValueError):
            create_frame(payload)
    
    def test_parse_frame_normal(self):
        """Test parsing of normal frame"""
        payload = b"Test message"
        frame = create_frame(payload)
        
        extracted, consumed = parse_frame(frame)
        
        assert extracted == payload, "Extracted payload should match original"
        assert consumed == len(frame), "Should consume entire frame"
    
    def test_parse_frame_with_prefix(self):
        """Test parsing frame with garbage prefix"""
        payload = b"Message"
        frame = create_frame(payload)
        
        # Add garbage before frame
        garbage = b"\x00\x11\x22\x33\x44\x55"
        data = garbage + frame
        
        extracted, consumed = parse_frame(data)
        
        assert extracted == payload, "Should extract payload despite garbage"
        assert consumed > len(garbage), "Should consume garbage + frame"
    
    def test_parse_frame_incomplete(self):
        """Test parsing of incomplete frame"""
        payload = b"Complete message"
        frame = create_frame(payload)
        
        # Truncate frame
        incomplete = frame[:10]
        
        extracted, consumed = parse_frame(incomplete)
        
        assert extracted is None, "Should return None for incomplete frame"
    
    def test_parse_frame_no_sync(self):
        """Test parsing data without sync marker"""
        data = b"\x00\x11\x22\x33\x44"
        
        extracted, consumed = parse_frame(data)
        
        assert extracted is None, "Should return None when no sync marker"
    
    def test_parse_frame_odd_length(self):
        """Test parsing frame with odd-length payload"""
        payload = b"Odd!"  # 4 bytes, but tests general odd handling
        frame = create_frame(payload)
        
        extracted, consumed = parse_frame(frame)
        
        assert extracted == payload
    
    def test_round_trip(self):
        """Test complete frame creation and parsing round trip"""
        test_cases = [
            b"",
            b"Short",
            b"Normal length message for testing",
            b"X" * 1000,
            b"\x00\x01\x02\x03\x04",  # Binary data
        ]
        
        for payload in test_cases:
            frame = create_frame(payload)
            extracted, _ = parse_frame(frame)
            assert extracted == payload, f"Round trip failed for payload length {len(payload)}"
    
    def test_find_sync_marker(self):
        """Test sync marker detection"""
        # Sync marker at start
        data1 = b"\xDE\xAD\x00\x00"
        pos1 = find_sync_marker(data1)
        assert pos1 == 0
        
        # Sync marker in middle
        data2 = b"\x00\x11\xDE\xAD\x00"
        pos2 = find_sync_marker(data2)
        assert pos2 == 2
        
        # No sync marker
        data3 = b"\x00\x11\x22\x33"
        pos3 = find_sync_marker(data3)
        assert pos3 == -1
    
    def test_multiple_frames(self):
        """Test parsing multiple consecutive frames"""
        payload1 = b"First"
        payload2 = b"Second"
        
        frame1 = create_frame(payload1)
        frame2 = create_frame(payload2)
        
        data = frame1 + frame2
        
        # Parse first frame
        extracted1, consumed1 = parse_frame(data)
        assert extracted1 == payload1
        
        # Parse second frame
        extracted2, consumed2 = parse_frame(data[consumed1:])
        assert extracted2 == payload2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
