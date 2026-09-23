"""
Sender Core Logic
Implements both Header Field and Temporal IPD covert channels
"""

import time
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
    
    def send_message(self, plaintext: str, passphrase: str, packet_callback: Any = None) -> Dict[str, Any]:
        """
        Send a message using header field steganography.
        
        Process:
            1. Encrypt message
            2. Create frame
            3. Split into 16-bit chunks
            4. Send each chunk in IP.id field
        
        Args:
            plaintext: Message to send
            passphrase: Pre-shared key for encryption
            packet_callback: Optional callable(event_dict) for real-time visualization events
        
        Returns:
            Dictionary with transmission statistics
        """
        logger.info(f"Starting header channel transmission to {self.target_ip}")
        logger.info(f"Message: '{plaintext}' ({len(plaintext)} bytes)")
        
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
        logger.info(f"Split into {total_chunks} chunks (16-bit each)")

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
                    'timing_profile': 'Direct',
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
        
        # Step 4: Send packets
        for i, chunk in enumerate(chunks):
            # Create ICMP Echo Request with embedded data in IP.id
            packet = IP(dst=self.target_ip, id=chunk) / ICMP(seq=i)
            
            # Send packet
            send(packet, verbose=False)
            
            self.packets_sent += 1
            entry = {
                'packet_num': i + 1,
                'ip_id': chunk,
                'ip_id_hex': f'0x{chunk:04X}',
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
                        'channel': 'IP-ID Header Embedding',
                        'is_sync': chunk == 0xDEAD,
                        'timestamp': time.time()
                    })
                except Exception:
                    pass
            
            # Small delay between packets to avoid overwhelming receiver
            time.sleep(0.01)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Calculate statistics
        stats = {
            'mode': 'header',
            'channel_label': 'IP-ID Header Embedding',
            'plaintext_length': len(plaintext),
            'encrypted_length': len(encrypted),
            'frame_size': len(frame),
            'packets_sent': self.packets_sent,
            'duration_seconds': duration,
            'throughput_bps': (len(frame) * 8) / duration if duration > 0 else 0,
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
        logger.info(f"Starting temporal channel transmission to {self.target_ip}")
        logger.info(f"Message: '{plaintext}' ({len(plaintext)} bytes)")
        logger.info(f"Timing profile: {timing_profile}")
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

        timing_profile_label = {
            'constant': 'Constant Delay',
            'normal': 'Normal / Variable Load',
            'gamma': 'Gamma Distribution',
            'gmm': 'GMM Fitted Distribution'
        }.get(timing_profile, timing_profile.upper())

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
            # Determine delay based on bit value and profile
            if timing_profile == 'constant':
                delay = 0.025 if bit == 0 else 0.125
            elif timing_profile == 'normal':
                target = 0.025 if bit == 0 else 0.125
                jitter = float(np.random.normal(0, 0.002))
                delay = max(0.018, min(0.040, target + jitter)) if bit == 0 else max(0.105, min(0.150, target + jitter))
            elif timing_profile == 'gamma':
                target = 0.025 if bit == 0 else 0.125
                shape = 2.0
                scale = target / shape
                val = float(np.random.gamma(shape, scale))
                delay = max(0.018, min(0.040, val)) if bit == 0 else max(0.105, min(0.150, val))
            elif timing_profile == 'gmm':
                # Modulate delay from GMM distribution conditioned on bit value (threshold = 75ms)
                if gmm_model is not None:
                    try:
                        if hasattr(gmm_model, 'sample_bit_delay'):
                            delay = gmm_model.sample_bit_delay(bit, threshold_ms=75.0)
                        else:
                            target = 0.025 if bit == 0 else 0.125
                            delay = target
                    except Exception as e:
                        logger.warning(f"GMM sampling fallback: {e}")
                        delay = 0.025 if bit == 0 else 0.125
                else:
                    delay = 0.025 if bit == 0 else 0.125
            else:
                delay = 0.025 if bit == 0 else 0.125
            
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
            'timing_profile': timing_profile,
            'timing_profile_label': timing_profile_label,
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
