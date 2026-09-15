"""
Utility Functions for NetGhost
"""

from typing import List


def bytes_to_bits(data: bytes) -> List[int]:
    """
    Convert bytes to list of bits (MSB first).
    
    Args:
        data: Bytes to convert
    
    Returns:
        List of bits (0 or 1)
    
    Example:
        bytes_to_bits(b'\xAB') -> [1,0,1,0,1,0,1,1]
    """
    bits = []
    for byte in data:
        for i in range(7, -1, -1):  # MSB first
            bit = (byte >> i) & 1
            bits.append(bit)
    return bits


def bits_to_bytes(bits: List[int]) -> bytes:
    """
    Convert list of bits to bytes (MSB first).
    
    Args:
        bits: List of bits (0 or 1)
    
    Returns:
        Bytes representation
    
    Note:
        Pads with zeros if bit count is not multiple of 8
    """
    # Pad to multiple of 8
    while len(bits) % 8 != 0:
        bits.append(0)
    
    byte_array = []
    for i in range(0, len(bits), 8):
        byte_val = 0
        for j in range(8):
            if i + j < len(bits):
                byte_val = (byte_val << 1) | bits[i + j]
        byte_array.append(byte_val)
    
    return bytes(byte_array)


def bytes_to_uint16_list(data: bytes) -> List[int]:
    """
    Convert bytes to list of 16-bit unsigned integers (big-endian).
    Pads with zero if odd length.
    
    Args:
        data: Bytes to convert
    
    Returns:
        List of 16-bit integers
    
    Example:
        bytes_to_uint16_list(b'\xDE\xAD\xBE\xEF') -> [0xDEAD, 0xBEEF]
    """
    # Pad if odd length
    if len(data) % 2 != 0:
        data = data + b'\x00'
    
    uint16_list = []
    for i in range(0, len(data), 2):
        value = (data[i] << 8) | data[i + 1]
        uint16_list.append(value)
    
    return uint16_list


def uint16_list_to_bytes(uint16_list: List[int]) -> bytes:
    """
    Convert list of 16-bit unsigned integers to bytes (big-endian).
    
    Args:
        uint16_list: List of 16-bit integers
    
    Returns:
        Bytes representation
    """
    byte_array = []
    for value in uint16_list:
        byte_array.append((value >> 8) & 0xFF)  # High byte
        byte_array.append(value & 0xFF)  # Low byte
    
    return bytes(byte_array)


def format_bytes_hex(data: bytes, bytes_per_line: int = 16) -> str:
    """
    Format bytes as hex dump for display.
    
    Args:
        data: Bytes to format
        bytes_per_line: Number of bytes per line
    
    Returns:
        Formatted hex string
    """
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i+bytes_per_line]
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{i:04X}  {hex_part:<{bytes_per_line*3}}  {ascii_part}')
    return '\n'.join(lines)


def test_utils():
    """Self-test for utility functions"""
    print("Testing utility functions...")
    
    # Test bytes_to_bits and bits_to_bytes
    data = b'\xAB\xCD'
    bits = bytes_to_bits(data)
    assert bits == [1,0,1,0,1,0,1,1, 1,1,0,0,1,1,0,1], "bits conversion failed"
    recovered = bits_to_bytes(bits)
    assert recovered == data, "bits round-trip failed"
    print("✓ Bits conversion")
    
    # Test uint16 conversion
    data2 = b'\xDE\xAD\xBE\xEF'
    uint16s = bytes_to_uint16_list(data2)
    assert uint16s == [0xDEAD, 0xBEEF], "uint16 conversion failed"
    recovered2 = uint16_list_to_bytes(uint16s)
    assert recovered2 == data2, "uint16 round-trip failed"
    print("✓ Uint16 conversion")
    
    # Test odd length
    data3 = b'\xAB\xCD\xEF'
    uint16s3 = bytes_to_uint16_list(data3)
    assert uint16s3 == [0xABCD, 0xEF00], "odd length padding failed"
    print("✓ Odd length handling")
    
    print("All utility tests passed!")


if __name__ == "__main__":
    test_utils()
