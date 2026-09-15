"""
Common modules for NetGhost covert channel implementation
"""

from .crypto import derive_key, encrypt_message, decrypt_message
from .framing import create_frame, parse_frame
from .utils import bytes_to_bits, bits_to_bytes

__all__ = [
    'derive_key',
    'encrypt_message',
    'decrypt_message',
    'create_frame',
    'parse_frame',
    'bytes_to_bits',
    'bits_to_bytes',
]
