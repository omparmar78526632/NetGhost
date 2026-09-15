"""
Framing Protocol Module
Implements frame structure: SYNC_MARKER || LENGTH || PAYLOAD
"""

import struct
from typing import Tuple, Optional


# Frame constants
SYNC_MARKER = 0xDEAD
SYNC_SIZE = 2  # bytes
LENGTH_SIZE = 2  # bytes
HEADER_SIZE = SYNC_SIZE + LENGTH_SIZE  # 4 bytes total
MAX_PAYLOAD_SIZE = 65535  # 2^16 - 1


def create_frame(payload: bytes) -> bytes:
    """
    Create a frame with sync marker and length prefix.
    
    Frame structure:
    +----------------+----------------+----------------------+
    | Sync Marker    | Payload Length | Payload              |
    | 0xDEAD (2B)    | uint16 (2B)    | N bytes              |
    +----------------+----------------+----------------------+
    
    Args:
        payload: Encrypted data to frame
    
    Returns:
        Complete frame as bytes
    
    Raises:
        ValueError: If payload is too large
    """
    if len(payload) > MAX_PAYLOAD_SIZE:
        raise ValueError(f"Payload too large: {len(payload)} > {MAX_PAYLOAD_SIZE}")
    
    # Pack: sync marker (big-endian uint16) + length (big-endian uint16) + payload
    frame = struct.pack('>H', SYNC_MARKER)  # Big-endian unsigned short
    frame += struct.pack('>H', len(payload))  # Big-endian unsigned short
    frame += payload
    
    return frame


def parse_frame(data: bytes) -> Tuple[Optional[bytes], int]:
    """
    Parse a frame and extract the payload.
    
    Args:
        data: Raw bytes potentially containing a frame
    
    Returns:
        Tuple of (payload, bytes_consumed)
        - payload: Extracted payload or None if frame is invalid
        - bytes_consumed: Number of bytes processed
    
    Process:
        1. Search for sync marker (0xDEAD)
        2. Read payload length
        3. Extract payload
        4. Validate frame completeness
    """
    # Need at least header
    if len(data) < HEADER_SIZE:
        return None, 0
    
    # Search for sync marker
    sync_pos = -1
    for i in range(len(data) - 1):
        marker = struct.unpack('>H', data[i:i+2])[0]
        if marker == SYNC_MARKER:
            sync_pos = i
            break
    
    if sync_pos == -1:
        # No sync marker found
        return None, 0
    
    # Check if we have enough data for header after sync
    if len(data) < sync_pos + HEADER_SIZE:
        return None, sync_pos
    
    # Extract length
    length_bytes = data[sync_pos + SYNC_SIZE:sync_pos + HEADER_SIZE]
    payload_length = struct.unpack('>H', length_bytes)[0]
    
    # Validate length
    if payload_length > MAX_PAYLOAD_SIZE:
        # Invalid length, skip this marker
        return None, sync_pos + SYNC_SIZE
    
    # Check if we have complete payload
    frame_end = sync_pos + HEADER_SIZE + payload_length
    if len(data) < frame_end:
        # Incomplete frame
        return None, sync_pos
    
    # Extract payload
    payload = data[sync_pos + HEADER_SIZE:frame_end]
    
    return payload, frame_end


def find_sync_marker(data: bytes, start_pos: int = 0) -> int:
    """
    Find the position of the sync marker in data.
    
    Args:
        data: Bytes to search
        start_pos: Position to start searching from
    
    Returns:
        Position of sync marker, or -1 if not found
    """
    for i in range(start_pos, len(data) - 1):
        marker = struct.unpack('>H', data[i:i+2])[0]
        if marker == SYNC_MARKER:
            return i
    return -1


def test_framing():
    """Self-test for framing functions"""
    print("Testing framing module...")
    
    # Test 1: Normal message
    payload1 = b"Hello, World!"
    frame1 = create_frame(payload1)
    extracted1, consumed1 = parse_frame(frame1)
    assert extracted1 == payload1, "Test 1 failed"
    assert consumed1 == len(frame1), "Test 1 consumption failed"
    print("✓ Test 1: Normal message")
    
    # Test 2: Empty payload
    payload2 = b""
    frame2 = create_frame(payload2)
    extracted2, consumed2 = parse_frame(frame2)
    assert extracted2 == payload2, "Test 2 failed"
    print("✓ Test 2: Empty payload")
    
    # Test 3: Long message
    payload3 = b"X" * 1000
    frame3 = create_frame(payload3)
    extracted3, consumed3 = parse_frame(frame3)
    assert extracted3 == payload3, "Test 3 failed"
    print("✓ Test 3: Long message")
    
    # Test 4: Frame with prefix garbage
    garbage = b"\x00\x11\x22\x33\x44"
    frame4 = garbage + create_frame(payload1)
    extracted4, consumed4 = parse_frame(frame4)
    assert extracted4 == payload1, "Test 4 failed"
    print("✓ Test 4: Frame with garbage prefix")
    
    # Test 5: Incomplete frame
    frame5 = create_frame(payload1)[:5]  # Truncated
    extracted5, consumed5 = parse_frame(frame5)
    assert extracted5 is None, "Test 5 should return None"
    print("✓ Test 5: Incomplete frame")
    
    # Test 6: No sync marker
    no_sync = b"\x00\x11\x22\x33"
    extracted6, consumed6 = parse_frame(no_sync)
    assert extracted6 is None, "Test 6 should return None"
    print("✓ Test 6: No sync marker")
    
    # Test 7: Odd length payload
    payload7 = b"Odd!"
    frame7 = create_frame(payload7)
    extracted7, consumed7 = parse_frame(frame7)
    assert extracted7 == payload7, "Test 7 failed"
    print("✓ Test 7: Odd length payload")
    
    print("All framing tests passed!")


if __name__ == "__main__":
    test_framing()
