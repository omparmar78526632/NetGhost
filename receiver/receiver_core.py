"""
Receiver Core Logic
Implements packet sniffing and decoding for both covert channels
"""

import time
import logging
import threading
import sys
from typing import List, Dict, Any, Optional, Callable
from scapy.all import sniff, IP, ICMP

# Enable 1ms high-precision timer on Windows
if sys.platform == 'win32':
    try:
        import ctypes
        ctypes.windll.winmm.timeBeginPeriod(1)
    except Exception:
        pass

from common.crypto import decrypt_message
from common.framing import parse_frame
from common.utils import uint16_list_to_bytes, bits_to_bytes


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def resolve_sniff_interfaces(interface: str = None):
    """
    Resolve network interface for Scapy sniffing.
    On Windows with Npcap, if no interface is specified, sniffs on both the active adapter and loopback.
    """
    if interface and interface != 'all':
        return interface
    try:
        from scapy.all import conf
        loopback = getattr(conf, 'loopback_name', None)
        if loopback and loopback in conf.ifaces:
            if conf.iface and conf.iface != loopback:
                return [conf.iface, loopback]
            return loopback
    except Exception:
        pass
    return None


class HeaderChannelReceiver:
    """
    Covert channel receiver supporting both IPv4 Header Embedding and Temporal IPD.
    Extracts 16 bits per packet from IP.id field and simultaneously analyzes inter-packet delays.
    """
    
    def __init__(self, passphrase: str, threshold_ms: float = 75.0):
        """
        Initialize header channel receiver.
        
        Args:
            passphrase: Pre-shared key for decryption
            threshold_ms: Threshold for temporal bit classification (milliseconds)
        """
        self.passphrase = passphrase
        self.threshold_ms = threshold_ms
        self.running = False
        self.packets_received = 0
        self.icmp_packets = 0
        self.uint16_values = []
        self.timestamps = []
        self.bits = []
        self.captured_packets_log = []
        self.status_history = []
        self.sync_detected = False
        self.frame_extracted = False
        self.decryption_success = False
        self.last_message = None
        self.last_error = None
        self.status_callback = None
        self.event_callback = None
        self.message_callback = None
        self.sniff_thread = None
    
    def get_state(self) -> Dict[str, Any]:
        """Return structured state snapshot"""
        return {
            'running': self.running,
            'channel': 'IP-ID Header Embedding (Auto-Detect)',
            'packets_received': self.packets_received,
            'icmp_packets': self.icmp_packets,
            'sync_detected': self.sync_detected,
            'frame_extracted': self.frame_extracted,
            'decryption_success': self.decryption_success,
            'last_message': self.last_message,
            'last_error': self.last_error,
            'recent_packets': self.captured_packets_log[-50:],
            'status_history': self.status_history[-20:]
        }
    
    def set_status_callback(self, callback: Callable):
        """Set callback for status updates"""
        self.status_callback = callback

    def set_event_callback(self, callback: Callable):
        """Set callback for structured visualization events"""
        self.event_callback = callback
    
    def set_message_callback(self, callback: Callable):
        """Set callback for decoded messages"""
        self.message_callback = callback

    def _emit_event(self, event_data: dict):
        """Broadcast structured event to event callback"""
        if self.event_callback:
            try:
                self.event_callback(event_data)
            except Exception:
                pass
    
    def _update_status(self, status: str):
        """Send status update"""
        self.status_history.append({'time': time.time(), 'message': status})
        if len(self.status_history) > 50:
            self.status_history = self.status_history[-50:]
        if self.status_callback:
            try:
                self.status_callback(status)
            except Exception:
                pass
        self._emit_event({'type': 'rx_status', 'message': status, 'timestamp': time.time()})
        try:
            logger.info(status)
        except Exception:
            try:
                safe_status = status.encode('ascii', errors='replace').decode('ascii')
                logger.info(safe_status)
            except Exception:
                pass
    
    def _packet_handler(self, packet):
        """Handle captured packets with simultaneous Header and Temporal decoding"""
        self.packets_received += 1
        
        # Filter for ICMP Echo Request
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            if packet[ICMP].type == 8:  # Echo Request
                curr_time = float(getattr(packet, 'time', None) or time.time())
                # Deduplicate Npcap multi-adapter / loopback double capture (<3ms)
                if self.timestamps and (curr_time - self.timestamps[-1]) < 0.003:
                    return
                
                self.icmp_packets += 1
                self.timestamps.append(curr_time)
                ip_id = packet[IP].id
                self.uint16_values.append(ip_id)
                
                is_sync = ip_id == 0xDEAD
                if is_sync:
                    self.sync_detected = True
                    self._emit_event({
                        'type': 'rx_sync_detected',
                        'marker': '0xDEAD',
                        'channel': 'IP-ID Header Embedding',
                        'timestamp': curr_time
                    })

                # Compute inter-packet delay for temporal analysis
                if len(self.timestamps) > 1:
                    delay_ms = (curr_time - self.timestamps[-2]) * 1000.0
                    bit = 0 if delay_ms < self.threshold_ms else 1
                    self.bits.append(bit)
                    pkt_entry = {
                        'packet_num': self.icmp_packets,
                        'ip_id': ip_id,
                        'ip_id_hex': f"0x{ip_id:04X}",
                        'delay_ms': round(delay_ms, 1),
                        'bit': bit,
                        'is_sync': is_sync,
                        'timestamp': curr_time
                    }
                    self.captured_packets_log.append(pkt_entry)
                    self._emit_event({
                        'type': 'rx_packet',
                        'index': self.icmp_packets,
                        'ip_id': ip_id,
                        'ip_id_hex': f"0x{ip_id:04X}",
                        'delay_ms': round(delay_ms, 1),
                        'bit': bit,
                        'is_sync': is_sync,
                        'channel': 'IP-ID Header Embedding',
                        'timestamp': curr_time
                    })
                    self._update_status(
                        f"Packet {self.icmp_packets}: IP.id=0x{ip_id:04X} ({ip_id}) | Δt={delay_ms:.1f}ms → bit {bit}"
                    )
                    # Attempt temporal decode first if temporal bit stream is active
                    if self._try_decode_temporal():
                        return
                else:
                    pkt_entry = {
                        'packet_num': self.icmp_packets,
                        'ip_id': ip_id,
                        'ip_id_hex': f"0x{ip_id:04X}",
                        'delay_ms': 0.0,
                        'bit': None,
                        'is_sync': is_sync,
                        'timestamp': curr_time
                    }
                    self.captured_packets_log.append(pkt_entry)
                    self._emit_event({
                        'type': 'rx_packet',
                        'index': self.icmp_packets,
                        'ip_id': ip_id,
                        'ip_id_hex': f"0x{ip_id:04X}",
                        'delay_ms': 0.0,
                        'bit': None,
                        'is_sync': is_sync,
                        'channel': 'IP-ID Header Embedding',
                        'timestamp': curr_time
                    })
                    self._update_status(
                        f"Packet {self.icmp_packets}: IP.id=0x{ip_id:04X} ({ip_id})"
                    )
                
                # Attempt header decode
                self._try_decode_header()
    
    def _try_decode_header(self) -> bool:
        """Attempt to decode frame from collected IP.id values with exact sync alignment"""
        if len(self.uint16_values) < 2:
            return False
        
        # Find all occurrences of SYNC marker 0xDEAD
        sync_indices = [i for i, val in enumerate(self.uint16_values) if val == 0xDEAD]
        if not sync_indices:
            if len(self.uint16_values) > 100:
                self.uint16_values = self.uint16_values[-50:]
            return False
        
        for sync_idx in sync_indices:
            # Need at least sync + length
            if len(self.uint16_values) < sync_idx + 2:
                continue
            
            payload_len = self.uint16_values[sync_idx + 1]
            if payload_len == 0 or payload_len > 65535:
                continue
            
            needed_chunks = (payload_len + 1) // 2
            total_needed = sync_idx + 2 + needed_chunks
            
            current_chunks_arrived = len(self.uint16_values) - (sync_idx + 2)
            progress_pct = min(100, max(0, int((current_chunks_arrived / needed_chunks) * 100))) if needed_chunks > 0 else 0

            self._emit_event({
                'type': 'rx_fragment',
                'index': current_chunks_arrived,
                'total': needed_chunks,
                'progress_pct': progress_pct,
                'channel': 'IP-ID Header Embedding'
            })
            
            if len(self.uint16_values) < total_needed:
                # Frame is still arriving, wait for more packets
                self.sync_detected = True
                continue
            
            # Extract complete frame
            self.sync_detected = True
            payload_chunks = self.uint16_values[sync_idx + 2 : total_needed]
            payload_bytes = uint16_list_to_bytes(payload_chunks)[:payload_len]
            
            self.frame_extracted = True
            self._emit_event({
                'type': 'rx_reassembly',
                'status': 'success',
                'frame_size': len(payload_bytes),
                'total_fragments': needed_chunks,
                'progress_pct': 100
            })
            self._update_status("✓ Sync marker detected (Header Channel)!")
            self._update_status(f"✓ Frame extracted: {len(payload_bytes)} bytes")
            
            try:
                plaintext = decrypt_message(payload_bytes, self.passphrase)
                self.decryption_success = True
                self.last_message = plaintext
                self.last_error = None
                self._emit_event({
                    'type': 'rx_auth_status',
                    'auth': 'SUCCESS',
                    'decrypt': 'SUCCESS'
                })
                self._emit_event({
                    'type': 'rx_message_recovered',
                    'message': plaintext
                })
                self._update_status("✓ Decryption successful!")
                self._update_status(f"✓ Message: {plaintext}")
                
                if self.message_callback:
                    self.message_callback(plaintext)
                
                # Reset buffers
                self.uint16_values = []
                self.bits = []
                self.timestamps = []
                return True
            except ValueError as e:
                self.decryption_success = False
                self.last_error = str(e)
                self._emit_event({
                    'type': 'rx_auth_status',
                    'auth': 'FAILED',
                    'decrypt': 'FAILED',
                    'error': str(e)
                })
                self._update_status(f"✗ Decryption failed: Check if passphrase matches sender! ({str(e)})")
                self.uint16_values = self.uint16_values[sync_idx + 1:]
                return False
        
        return False
    
    def _try_decode_temporal(self) -> bool:
        """Attempt to decode frame from collected bits with bit-level sync alignment"""
        if len(self.bits) < 32:  # Need at least header (16 bits sync + 16 bits length)
            return False
        
        # 0xDEAD sync marker in binary: 11011110 10101101
        sync_bits = [1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1]
        
        sync_idx = -1
        for i in range(len(self.bits) - len(sync_bits) + 1):
            if self.bits[i:i+len(sync_bits)] == sync_bits:
                sync_idx = i
                break
        
        if sync_idx == -1:
            return False
        
        self.sync_detected = True
        self._emit_event({
            'type': 'rx_sync_detected',
            'marker': '0xDEAD',
            'channel': 'Temporal IPD'
        })
        
        # Check if we have 16 bits for length after sync
        if len(self.bits) < sync_idx + 32:
            return False
        
        len_bits = self.bits[sync_idx + 16 : sync_idx + 32]
        len_bytes = bits_to_bytes(len_bits)
        import struct
        payload_len = struct.unpack('>H', len_bytes)[0]
        
        if payload_len == 0 or payload_len > 65535:
            self.bits = self.bits[sync_idx + 1:]
            return False
        
        total_bits_needed = sync_idx + 32 + (payload_len * 8)
        current_bits = len(self.bits) - (sync_idx + 32)
        total_payload_bits = payload_len * 8
        progress_pct = min(100, max(0, int((current_bits / total_payload_bits) * 100))) if total_payload_bits > 0 else 0

        self._emit_event({
            'type': 'rx_fragment',
            'index': current_bits,
            'total': total_payload_bits,
            'progress_pct': progress_pct,
            'channel': 'Temporal IPD'
        })

        if len(self.bits) < total_bits_needed:
            return False
        
        payload_bits = self.bits[sync_idx + 32 : total_bits_needed]
        payload_bytes = bits_to_bytes(payload_bits)
        
        self.frame_extracted = True
        self._emit_event({
            'type': 'rx_reassembly',
            'status': 'success',
            'frame_size': len(payload_bytes),
            'total_fragments': total_payload_bits,
            'progress_pct': 100
        })
        self._update_status("✓ Sync marker detected (Temporal Channel)!")
        self._update_status(f"✓ Frame extracted: {len(payload_bytes)} bytes")
        
        try:
            plaintext = decrypt_message(payload_bytes, self.passphrase)
            self.decryption_success = True
            self.last_message = plaintext
            self.last_error = None
            self._emit_event({
                'type': 'rx_auth_status',
                'auth': 'SUCCESS',
                'decrypt': 'SUCCESS'
            })
            self._emit_event({
                'type': 'rx_message_recovered',
                'message': plaintext
            })
            self._update_status("✓ Decryption successful!")
            self._update_status(f"✓ Message: {plaintext}")
            
            if self.message_callback:
                self.message_callback(plaintext)
            
            # Reset buffers
            self.bits = []
            self.timestamps = []
            self.uint16_values = []
            return True
        except ValueError as e:
            self.decryption_success = False
            self.last_error = str(e)
            self._emit_event({
                'type': 'rx_auth_status',
                'auth': 'FAILED',
                'decrypt': 'FAILED',
                'error': str(e)
            })
            self._update_status(f"✗ Decryption failed: Check if passphrase matches sender! ({str(e)})")
            self.bits = self.bits[sync_idx + 1:]
            return False
    
    def start_listening(self, interface: str = None, timeout: int = 600):
        """
        Start listening for packets.
        
        Args:
            interface: Network interface to sniff (None for all)
            timeout: Sniffing timeout in seconds
        """
        self.running = True
        self.packets_received = 0
        self.icmp_packets = 0
        self.uint16_values = []
        self.timestamps = []
        self.bits = []
        self.captured_packets_log = []
        self.sync_detected = False
        self.frame_extracted = False
        self.decryption_success = False
        self.last_message = None
        self.last_error = None
        
        target_iface = resolve_sniff_interfaces(interface)
        self._update_status(f"Starting receiver (Auto-Detect Header & Temporal)...")
        self._update_status(f"Interface: {interface if interface else 'all (including loopback)'}")

        self._emit_event({
            'type': 'rx_started',
            'channel': 'IP-ID Header Embedding & Temporal IPD',
            'interface': interface if interface else 'all (including loopback)',
            'timestamp': time.time()
        })
        
        # Start sniffing in background thread
        def sniff_worker():
            try:
                sniff(
                    iface=target_iface,
                    prn=self._packet_handler,
                    filter="icmp",
                    stop_filter=lambda p: not self.running,
                    timeout=timeout,
                    store=False
                )
            except Exception as e:
                self._update_status(f"Error: {str(e)}")
            finally:
                self.running = False
                self._emit_event({'type': 'rx_stopped', 'timestamp': time.time()})
        
        self.sniff_thread = threading.Thread(target=sniff_worker, daemon=True)
        self.sniff_thread.start()
    
    def stop_listening(self):
        """Stop listening for packets"""
        self.running = False
        self._emit_event({'type': 'rx_stopped', 'timestamp': time.time()})
        self._update_status("Stopping receiver...")


class TemporalChannelReceiver:
    """
    Covert channel receiver using Inter-Packet Delay (IPD).
    Decodes 1 bit per packet based on timing.
    """
    
    def __init__(self, passphrase: str, threshold_ms: float = 75.0):
        """
        Initialize temporal channel receiver.
        
        Args:
            passphrase: Pre-shared key for decryption
            threshold_ms: Threshold for bit classification (milliseconds)
        """
        self.passphrase = passphrase
        self.threshold_ms = threshold_ms
        self.threshold_s = threshold_ms / 1000.0
        self.running = False
        self.packets_received = 0
        self.icmp_packets = 0
        self.timestamps = []
        self.bits = []
        self.captured_packets_log = []
        self.status_history = []
        self.sync_detected = False
        self.frame_extracted = False
        self.decryption_success = False
        self.last_message = None
        self.last_error = None
        self.status_callback = None
        self.event_callback = None
        self.message_callback = None
        self.sniff_thread = None
    
    def get_state(self) -> Dict[str, Any]:
        """Return structured state snapshot"""
        return {
            'running': self.running,
            'channel': 'Temporal IPD',
            'packets_received': self.packets_received,
            'icmp_packets': self.icmp_packets,
            'sync_detected': self.sync_detected,
            'frame_extracted': self.frame_extracted,
            'decryption_success': self.decryption_success,
            'last_message': self.last_message,
            'last_error': self.last_error,
            'recent_packets': self.captured_packets_log[-50:],
            'status_history': self.status_history[-20:]
        }
    
    def set_status_callback(self, callback: Callable):
        """Set callback for status updates"""
        self.status_callback = callback

    def set_event_callback(self, callback: Callable):
        """Set callback for structured visualization events"""
        self.event_callback = callback
    
    def set_message_callback(self, callback: Callable):
        """Set callback for decoded messages"""
        self.message_callback = callback

    def _emit_event(self, event_data: dict):
        """Broadcast structured event to event callback"""
        if self.event_callback:
            try:
                self.event_callback(event_data)
            except Exception:
                pass
    
    def _update_status(self, status: str):
        """Send status update"""
        self.status_history.append({'time': time.time(), 'message': status})
        if len(self.status_history) > 50:
            self.status_history = self.status_history[-50:]
        if self.status_callback:
            try:
                self.status_callback(status)
            except Exception:
                pass
        self._emit_event({'type': 'rx_status', 'message': status, 'timestamp': time.time()})
        try:
            logger.info(status)
        except Exception:
            try:
                safe_status = status.encode('ascii', errors='replace').decode('ascii')
                logger.info(safe_status)
            except Exception:
                pass
    
    def _packet_handler(self, packet):
        """Handle captured packets"""
        self.packets_received += 1
        
        # Filter for ICMP Echo Request
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            if packet[ICMP].type == 8:  # Echo Request
                timestamp = float(getattr(packet, 'time', None) or time.time())
                # Deduplicate Npcap multi-adapter / loopback double capture (<3ms)
                if self.timestamps and (timestamp - self.timestamps[-1]) < 0.003:
                    return
                
                self.icmp_packets += 1
                
                # Store timestamp
                self.timestamps.append(timestamp)
                
                # Compute inter-packet delay
                if len(self.timestamps) > 1:
                    delay_s = timestamp - self.timestamps[-2]
                    delay_ms = delay_s * 1000
                    
                    # Classify bit based on threshold
                    bit = 0 if delay_ms < self.threshold_ms else 1
                    self.bits.append(bit)
                    
                    pkt_entry = {
                        'packet_num': self.icmp_packets,
                        'ip_id': packet[IP].id,
                        'ip_id_hex': f"0x{packet[IP].id:04X}",
                        'delay_ms': round(delay_ms, 1),
                        'bit': bit,
                        'is_sync': False,
                        'timestamp': timestamp
                    }
                    self.captured_packets_log.append(pkt_entry)
                    self._emit_event({
                        'type': 'rx_packet',
                        'index': self.icmp_packets,
                        'ip_id': packet[IP].id,
                        'ip_id_hex': f"0x{packet[IP].id:04X}",
                        'delay_ms': round(delay_ms, 1),
                        'bit': bit,
                        'is_sync': False,
                        'channel': 'Temporal IPD',
                        'timestamp': timestamp
                    })
                    
                    self._update_status(
                        f"Packet {self.icmp_packets}: Δt={delay_ms:.1f}ms → bit {bit}"
                    )
                    
                    # Try to decode after collecting bits
                    self._try_decode()
                else:
                    pkt_entry = {
                        'packet_num': self.icmp_packets,
                        'ip_id': packet[IP].id,
                        'ip_id_hex': f"0x{packet[IP].id:04X}",
                        'delay_ms': 0.0,
                        'bit': None,
                        'is_sync': True,
                        'timestamp': timestamp
                    }
                    self.captured_packets_log.append(pkt_entry)
                    self._emit_event({
                        'type': 'rx_packet',
                        'index': self.icmp_packets,
                        'ip_id': packet[IP].id,
                        'ip_id_hex': f"0x{packet[IP].id:04X}",
                        'delay_ms': 0.0,
                        'bit': None,
                        'is_sync': True,
                        'channel': 'Temporal IPD',
                        'timestamp': timestamp
                    })
                    self._update_status(f"Packet {self.icmp_packets}: First packet (lead sync)")
    
    def _try_decode(self):
        """Attempt to decode frame from collected bits with bit-level sync alignment"""
        if len(self.bits) < 32:  # Need at least header (16 bits sync + 16 bits length)
            return
        
        # 0xDEAD sync marker in binary: 11011110 10101101
        sync_bits = [1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1]
        
        # Search for sync pattern across all bit offsets
        sync_idx = -1
        for i in range(len(self.bits) - len(sync_bits) + 1):
            if self.bits[i:i+len(sync_bits)] == sync_bits:
                sync_idx = i
                break
        
        if sync_idx == -1:
            return
        
        self.sync_detected = True
        self._emit_event({
            'type': 'rx_sync_detected',
            'marker': '0xDEAD',
            'channel': 'Temporal IPD'
        })
        
        # Check if we have 16 bits for length after sync
        if len(self.bits) < sync_idx + 32:
            return
        
        len_bits = self.bits[sync_idx + 16 : sync_idx + 32]
        len_bytes = bits_to_bytes(len_bits)
        import struct
        payload_len = struct.unpack('>H', len_bytes)[0]
        
        if payload_len == 0 or payload_len > 65535:
            self.bits = self.bits[sync_idx + 1:]
            return
        
        total_bits_needed = sync_idx + 32 + (payload_len * 8)
        current_bits = len(self.bits) - (sync_idx + 32)
        total_payload_bits = payload_len * 8
        progress_pct = min(100, max(0, int((current_bits / total_payload_bits) * 100))) if total_payload_bits > 0 else 0

        self._emit_event({
            'type': 'rx_fragment',
            'index': current_bits,
            'total': total_payload_bits,
            'progress_pct': progress_pct,
            'channel': 'Temporal IPD'
        })

        if len(self.bits) < total_bits_needed:
            return
        
        payload_bits = self.bits[sync_idx + 32 : total_bits_needed]
        payload_bytes = bits_to_bytes(payload_bits)
        
        self.frame_extracted = True
        self._emit_event({
            'type': 'rx_reassembly',
            'status': 'success',
            'frame_size': len(payload_bytes),
            'total_fragments': total_payload_bits,
            'progress_pct': 100
        })
        self._update_status("✓ Sync marker detected (Temporal Channel)!")
        self._update_status(f"✓ Frame extracted: {len(payload_bytes)} bytes")
        
        try:
            plaintext = decrypt_message(payload_bytes, self.passphrase)
            self.decryption_success = True
            self.last_message = plaintext
            self.last_error = None
            self._emit_event({
                'type': 'rx_auth_status',
                'auth': 'SUCCESS',
                'decrypt': 'SUCCESS'
            })
            self._emit_event({
                'type': 'rx_message_recovered',
                'message': plaintext
            })
            self._update_status("✓ Decryption successful!")
            self._update_status(f"✓ Message: {plaintext}")
            
            if self.message_callback:
                self.message_callback(plaintext)
            
            # Reset buffers
            self.bits = []
            self.timestamps = []
            
        except ValueError as e:
            self.decryption_success = False
            self.last_error = str(e)
            self._emit_event({
                'type': 'rx_auth_status',
                'auth': 'FAILED',
                'decrypt': 'FAILED',
                'error': str(e)
            })
            self._update_status(f"✗ Decryption failed: Check if passphrase matches sender! ({str(e)})")
            self.bits = self.bits[sync_idx + 1:]
    
    def start_listening(self, interface: str = None, timeout: int = 600):
        """
        Start listening for packets.
        
        Args:
            interface: Network interface to sniff (None for all)
            timeout: Sniffing timeout in seconds
        """
        self.running = True
        self.packets_received = 0
        self.icmp_packets = 0
        self.timestamps = []
        self.bits = []
        self.captured_packets_log = []
        self.sync_detected = False
        self.frame_extracted = False
        self.decryption_success = False
        self.last_message = None
        self.last_error = None
        
        target_iface = resolve_sniff_interfaces(interface)
        self._update_status(f"Starting temporal channel receiver...")
        self._update_status(f"Interface: {interface if interface else 'all (including loopback)'}")
        self._update_status(f"Threshold: {self.threshold_ms}ms")

        self._emit_event({
            'type': 'rx_started',
            'channel': 'Temporal IPD',
            'interface': interface if interface else 'all (including loopback)',
            'timestamp': time.time()
        })
        
        # Start sniffing in background thread
        def sniff_worker():
            try:
                sniff(
                    iface=target_iface,
                    prn=self._packet_handler,
                    filter="icmp",
                    stop_filter=lambda p: not self.running,
                    timeout=timeout,
                    store=False
                )
            except Exception as e:
                self._update_status(f"Error: {str(e)}")
            finally:
                self.running = False
                self._emit_event({'type': 'rx_stopped', 'timestamp': time.time()})
        
        self.sniff_thread = threading.Thread(target=sniff_worker, daemon=True)
        self.sniff_thread.start()
    
    def stop_listening(self):
        """Stop listening for packets"""
        self.running = False
        self._emit_event({'type': 'rx_stopped', 'timestamp': time.time()})
        self._update_status("Stopping receiver...")


if __name__ == "__main__":
    print("Receiver core module")
    print("Run receiver_app.py to start the web interface")
