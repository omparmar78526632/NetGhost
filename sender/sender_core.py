"""
Sender Core Logic
Implements both Header Field and Temporal IPD covert channels
"""

import time
import hashlib
import logging
import sys
from typing import List, Dict, Any
from scapy.all import IP, ICMP, send
import numpy as np

# Enable 1ms high-precision timer on Windows
if sys.platform == 'win32':
    try:
        import ctypes
        ctypes.windll.winmm.timeBeginPeriod(1)
    except Exception:
        pass

from common.crypto import encrypt_message
from common.framing import create_frame
from common.utils import bytes_to_uint16_list, bytes_to_bits
from common.timing import create_timing_profile


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class HeaderChannelSender:
    """
    Covert channel sender using IPv4 Identification field.
    Embeds 16 bits per packet in IP.id field.
    """
    
    def __init__(self, target_ip: str):
        """
        Initialize header channel sender.
        
        Args:
            target_ip: Destination IP address
        """
        self.target_ip = target_ip
        self.packets_sent = 0
        self.transmission_log = []
    
    def send_message(
        self,
        plaintext: str,
        passphrase: str,
        packet_callback: Any = None,
        timing_profile: str = 'normal',
        gmm_model=None,
        delay_ms: float = 50.0,
    ) -> Dict[str, Any]:
        """
        Send a message using header field steganography with configurable timing profile.
        
        Process:
            1. Validate & initialize timing profile
            2. Encrypt message (AES-256-GCM)
            3. Create frame (0xDEAD || length || payload)
            4. Split into 16-bit chunks
            5. Ask timing profile for next inter-packet delay and send each chunk in IP.id
        
        Args:
            plaintext: Message to send
            passphrase: Pre-shared key for encryption
            packet_callback: Optional callable(event_dict) for real-time visualization events
            timing_profile: 'normal', 'constant', 'gamma', or 'gmm'
            gmm_model: Trained TrafficProfiler instance (required when timing_profile=='gmm')
            delay_ms: Base constant delay in milliseconds (used by 'constant' profile)
        
        Returns:
            Dictionary with transmission statistics
        """
        # Validate timing profile first (fails fast if invalid or GMM not trained)
        profile = create_timing_profile(
            timing_profile,
            gmm_model=gmm_model,
            delay_ms=delay_ms,
        )

        logger.info(f"Starting header channel transmission to {self.target_ip}")
        logger.info(f"Message: '{plaintext}' ({len(plaintext)} bytes) | Timing Profile: {profile.label}")
        
        # Reset counters
        self.packets_sent = 0
        self.transmission_log = []
        start_time = time.time()
        
        # Step 1: Encrypt
        encrypted = encrypt_message(plaintext, passphrase)
        logger.info(f"Encrypted length: {len(encrypted)} bytes")
        
        # Step 2: Frame
        frame = create_frame(encrypted)
        logger.info(f"Frame size: {len(frame)} bytes")
        
        # Step 3: Convert to 16-bit chunks
        chunks = bytes_to_uint16_list(frame)
        total_chunks = len(chunks)
        frame_hash = hashlib.sha256(frame).hexdigest()[:16]
        nonce_hex = encrypted[16:28].hex() if len(encrypted) >= 28 else ""
        logger.info(
            f"Split into {total_chunks} chunks (16-bit each) | "
            f"frame_len={len(frame)}B | frame_hash={frame_hash} | nonce={nonce_hex}"
        )

        if packet_callback:
            try:
                packet_callback({
                    'type': 'tx_started',
                    'channel': 'IP-ID Header Embedding',
                    'mode': 'header',
                    'total_packets': total_chunks,
                    'plaintext_len': len(plaintext),
                    'encrypted_len': len(encrypted),
                    'frame_size': len(frame),
                    'timing_profile': profile.label,
                    'timestamp': start_time
                })
                packet_callback({
                    'type': 'tx_encrypt_complete',
                    'encrypted_length': len(encrypted),
                    'frame_size': len(frame)
                })
                packet_callback({
                    'type': 'tx_fragment_complete',
                    'fragment_count': total_chunks
                })
            except Exception:
                pass
        
        # Step 4: Send packets paced by the selected TimingProfile
        prev_ts = None
        for i, chunk in enumerate(chunks):
            intended_delay_s = 0.0
            if i > 0:
                intended_delay_s = profile.next_delay_s()
                time.sleep(intended_delay_s)

            # Create ICMP Echo Request with embedded data in IP.id
            packet = IP(dst=self.target_ip, id=chunk) / ICMP(seq=i)
            
            # Send packet
            send(packet, verbose=False)
            now_ts = time.time()
            actual_delay_ms = ((now_ts - prev_ts) * 1000.0) if prev_ts is not None else 0.0
            prev_ts = now_ts
            
            self.packets_sent += 1
            entry = {
                'packet_num': i + 1,
                'ip_id': chunk,
                'ip_id_hex': f'0x{chunk:04X}',
                'intended_delay_ms': round(intended_delay_s * 1000.0, 2),
                'actual_delay_ms': round(actual_delay_ms, 2),
                'timestamp': now_ts,
                'is_sync': chunk == 0xDEAD
            }
            self.transmission_log.append(entry)

            if packet_callback:
                try:
                    packet_callback({
                        'type': 'tx_packet',
                        'index': i + 1,
                        'total': total_chunks,
                        'ip_id': chunk,
                        'ip_id_hex': f'0x{chunk:04X}',
                        'intended_delay_ms': round(intended_delay_s * 1000.0, 2),
                        'actual_delay_ms': round(actual_delay_ms, 2),
                        'timing_profile': profile.label,
                        'channel': 'IP-ID Header Embedding',
                        'is_sync': chunk == 0xDEAD,
                        'timestamp': now_ts
                    })
                except Exception:
                    pass
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Calculate statistics
        stats = {
            'mode': 'header',
            'channel_label': 'IP-ID Header Embedding',
            'timing_profile': profile.name,
            'timing_profile_label': profile.label,
            'gmm_used': profile.name == 'gmm',
            'plaintext_length': len(plaintext),
            'encrypted_length': len(encrypted),
            'frame_size': len(frame),
            'packets_sent': self.packets_sent,
            'duration_seconds': duration,
            'throughput_bps': (len(frame) * 8) / duration if duration > 0 else 0,
            'transmission_log': self.transmission_log
        }
        
        first_delays = [e['intended_delay_ms'] for e in self.transmission_log[1:11]]
        logger.info(f"First {len(first_delays)} intended delays (ms): {first_delays}")
        logger.info(f"Transmission complete: {self.packets_sent} packets in {duration:.2f}s ({profile.label})")
        logger.info(f"Throughput: {stats['throughput_bps']:.2f} bps")

        if packet_callback:
            try:
                packet_callback({
                    'type': 'tx_completed',
                    'stats': stats,
                    'timestamp': end_time
                })
            except Exception:
                pass
        
        return stats


class TemporalChannelSender:
    """
    Covert channel sender using Inter-Packet Delay (IPD).
    Encodes 1 bit per packet using timing.
    """
    
    def __init__(self, target_ip: str):
        """
        Initialize temporal channel sender.
        
        Args:
            target_ip: Destination IP address
        """
        self.target_ip = target_ip
        self.packets_sent = 0
        self.transmission_log = []
    
    def send_message(
        self,
        plaintext: str,
        passphrase: str,
        bit_0_delay: float = 0.050,
        bit_1_delay: float = 0.100,
        timing_profile: str = 'constant',
        gmm_model=None,
        packet_callback: Any = None
    ) -> Dict[str, Any]:
        """
        Send a message using temporal IPD steganography.
        
        Process:
            1. Encrypt message
            2. Create frame
            3. Convert to bits
            4. Send ICMP packets with timing delays
        
        Args:
            plaintext: Message to send
            passphrase: Pre-shared key
            bit_0_delay: Delay for bit 0 in seconds
            bit_1_delay: Delay for bit 1 in seconds
            timing_profile: 'constant', 'normal', 'gamma', or 'gmm'
            gmm_model: Trained GMM model (if timing_profile=='gmm')
            packet_callback: Optional callable(event_dict) for real-time visualization events
        
        Returns:
            Dictionary with transmission statistics
        """
        # Validate and initialize timing profile (fails fast if invalid or GMM not trained)
        profile = create_timing_profile(
            timing_profile,
            gmm_model=gmm_model,
            bit_0_ms=bit_0_delay * 1000.0,
            bit_1_ms=bit_1_delay * 1000.0,
        )
        timing_profile_label = profile.label

        logger.info(f"Starting temporal channel transmission to {self.target_ip}")
        logger.info(f"Message: '{plaintext}' ({len(plaintext)} bytes)")
        logger.info(f"Timing profile: {profile.label} ({profile.name})")
        logger.info(f"Bit 0 delay: {bit_0_delay*1000:.1f}ms, Bit 1 delay: {bit_1_delay*1000:.1f}ms")
        
        # Reset counters
        self.packets_sent = 0
        self.transmission_log = []
        start_time = time.time()
        
        # Step 1: Encrypt
        encrypted = encrypt_message(plaintext, passphrase)
        logger.info(f"Encrypted length: {len(encrypted)} bytes")
        
        # Step 2: Frame
        frame = create_frame(encrypted)
        logger.info(f"Frame size: {len(frame)} bytes")
        
        # Step 3: Convert to bits
        bits = bytes_to_bits(frame)
        total_packets = len(bits) + 1
        logger.info(f"Bit stream length: {len(bits)} bits")

        if packet_callback:
            try:
                packet_callback({
                    'type': 'tx_started',
                    'channel': 'Temporal IPD',
                    'mode': 'temporal',
                    'total_packets': total_packets,
                    'bit_count': len(bits),
                    'plaintext_len': len(plaintext),
                    'encrypted_len': len(encrypted),
                    'frame_size': len(frame),
                    'timing_profile': timing_profile_label,
                    'timestamp': start_time
                })
                packet_callback({
                    'type': 'tx_encrypt_complete',
                    'encrypted_length': len(encrypted),
                    'frame_size': len(frame)
                })
                packet_callback({
                    'type': 'tx_fragment_complete',
                    'fragment_count': total_packets
                })
            except Exception:
                pass
        
        # Step 4: Send initial synchronization lead packet
        packet = IP(dst=self.target_ip) / ICMP(seq=0)
        send(packet, verbose=False)
        self.packets_sent += 1
        timestamp = time.time()
        self.transmission_log.append({
            'packet_num': 1,
            'bit': None,
            'intended_delay_ms': 0,
            'timestamp': timestamp
        })

        if packet_callback:
            try:
                packet_callback({
                    'type': 'tx_packet',
                    'index': 1,
                    'total': total_packets,
                    'channel': 'Temporal IPD',
                    'bit': None,
                    'intended_delay_ms': 0.0,
                    'actual_delay_ms': 0.0,
                    'timing_profile': timing_profile_label,
                    'is_sync': True,
                    'timestamp': timestamp
                })
            except Exception:
                pass

        # Step 5: Send timed packets for each bit in the stream
        for i, bit in enumerate(bits):
            # Ask the selected TimingProfile for the next inter-packet delay
            delay = profile.next_delay_s(bit=bit)
            
            # Sleep intended inter-packet delay
            time.sleep(delay)
            
            # Send timed ICMP Echo Request
            packet = IP(dst=self.target_ip) / ICMP(seq=i+1)
            send(packet, verbose=False)
            
            timestamp = time.time()
            self.packets_sent += 1
            self.transmission_log.append({
                'packet_num': i + 2,
                'bit': bit,
                'intended_delay_ms': delay * 1000,
                'timestamp': timestamp
            })

            if packet_callback:
                try:
                    packet_callback({
                        'type': 'tx_packet',
                        'index': i + 2,
                        'total': total_packets,
                        'channel': 'Temporal IPD',
                        'bit': bit,
                        'intended_delay_ms': round(delay * 1000, 1),
                        'actual_delay_ms': round(delay * 1000, 1),
                        'timing_profile': timing_profile_label,
                        'is_sync': False,
                        'timestamp': timestamp
                    })
                except Exception:
                    pass
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Calculate actual inter-packet delays
        for i in range(1, len(self.transmission_log)):
            actual_delay = (self.transmission_log[i]['timestamp'] - 
                          self.transmission_log[i-1]['timestamp']) * 1000
            self.transmission_log[i]['actual_delay_ms'] = actual_delay
        
        # Calculate statistics
        stats = {
            'mode': 'temporal',
            'channel_label': 'Temporal IPD',
            'timing_profile': profile.name,
            'timing_profile_label': timing_profile_label,
            'gmm_used': profile.name == 'gmm',
            'plaintext_length': len(plaintext),
            'encrypted_length': len(encrypted),
            'frame_size': len(frame),
            'bit_count': len(bits),
            'packets_sent': self.packets_sent,
            'duration_seconds': duration,
            'throughput_bps': len(bits) / duration if duration > 0 else 0,
            'transmission_log': self.transmission_log
        }
        
        logger.info(f"Transmission complete: {self.packets_sent} packets in {duration:.2f}s")
        logger.info(f"Throughput: {stats['throughput_bps']:.2f} bps")

        if packet_callback:
            try:
                packet_callback({
                    'type': 'tx_completed',
                    'stats': stats,
                    'timestamp': end_time
                })
            except Exception:
                pass
        
        return stats


def test_header_sender():
    """Test header channel sender (requires root)"""
    print("Testing Header Channel Sender...")
    sender = HeaderChannelSender("127.0.0.1")
    stats = sender.send_message("Test", "password123")
    print(f"Sent {stats['packets_sent']} packets")
    print("Header sender test complete!")


def test_temporal_sender():
    """Test temporal channel sender (requires root)"""
    print("Testing Temporal Channel Sender...")
    sender = TemporalChannelSender("127.0.0.1")
    stats = sender.send_message(
        "Hi",
        "password123",
        bit_0_delay=0.05,
        bit_1_delay=0.10,
        timing_profile='constant'
    )
    print(f"Sent {stats['bit_count']} bits in {stats['packets_sent']} packets")
    print("Temporal sender test complete!")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        if sys.argv[1] == "header":
            test_header_sender()
        elif sys.argv[1] == "temporal":
            test_temporal_sender()
    else:
        print("Usage: python sender_core.py [header|temporal]")
