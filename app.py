"""
NETGHOST - Unified Cybernetic Network Steganography Laboratory Console
Backend Server: Hosts all 9 screens, Sender, Receiver, GMM Profiler, Packet Monitor, Experiments, Results, and Settings.
"""

import os
import sys
import queue
import time
import json
import csv
import uuid
import threading
import datetime
import numpy as np
from flask import Flask, render_template, request, jsonify, Response, send_file
import io

# Add project root to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

# Enable 1ms high-precision multimedia timer on Windows for microsecond IPD stability
if sys.platform == 'win32':
    try:
        import ctypes
        ctypes.windll.winmm.timeBeginPeriod(1)
    except Exception:
        pass

from common.crypto import encrypt_message, decrypt_message, derive_key, SALT_SIZE, GCM_NONCE_SIZE
from common.framing import create_frame, parse_frame, SYNC_MARKER, HEADER_SIZE
from common.utils import uint16_list_to_bytes, bytes_to_uint16_list, bytes_to_bits, bits_to_bytes
from common.timing import VALID_TIMING_PROFILES
from sender.sender_core import HeaderChannelSender, TemporalChannelSender
from receiver.receiver_core import HeaderChannelReceiver, TemporalChannelReceiver, resolve_sniff_interfaces
from ml.ml_profiler import TrafficProfiler

from scapy.all import sniff, IP, ICMP, TCP, UDP, Ether, wrpcap, Packet

app = Flask(
    __name__,
    static_folder=os.path.join(BASE_DIR, 'static'),
    template_folder=os.path.join(BASE_DIR, 'templates'),
    static_url_path='/static'
)
app.secret_key = os.urandom(24)

# Data storage paths
DATA_DIR = os.path.join(BASE_DIR, 'data')
os.makedirs(DATA_DIR, exist_ok=True)
EXPERIMENTS_FILE = os.path.join(DATA_DIR, 'experiments.json')
SETTINGS_FILE = os.path.join(DATA_DIR, 'settings.json')
SAMPLE_EXPERIMENT_IDS = {'exp-001', 'exp-002'}

# Global instances & queues
current_receiver = None
status_queue = queue.Queue()
message_queue = queue.Queue()
gmm_model = None
gmm_status_state = 'Not Trained'  # Not Trained, Training, Trained, Failed
gmm_last_error = None
GMM_MODEL_REL_PATH = os.path.join('ml', 'models', 'gmm_timing.pkl')

sse_subscribers = []
sse_lock = threading.Lock()

# System State Tracker
system_state = {
    'status': 'READY',  # READY, TRANSMITTING, RECEIVING, COMPLETED, ERROR
    'active_channel': 'None',
    'total_packets_sent': 0,
    'total_packets_received': 0,
    'total_bytes_sent': 0,
    'total_bytes_received': 0,
    'last_tx_time': None,
    'last_rx_message': None,
    'stealth_score': 94.2,
    'pipeline': {
        'sender': 'READY',
        'encryption': 'READY',
        'framing': 'READY',
        'channel': 'READY',
        'icmp': 'READY',
        'receiver': 'READY',
        'reassembly': 'READY',
        'decryption': 'READY'
    },
    'audit_log': [],
    'recent_status_events': []
}


def log_audit_event(event_type: str, details: str, status: str = 'INFO'):
    """Append event to security audit log"""
    entry = {
        'id': str(uuid.uuid4())[:8],
        'timestamp': datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3],
        'type': event_type,
        'details': details,
        'status': status
    }
    system_state['audit_log'].insert(0, entry)
    if len(system_state['audit_log']) > 50:
        system_state['audit_log'] = system_state['audit_log'][:50]


def broadcast_sse_event(event_data: dict):
    """Broadcast event dictionary to all active SSE subscribers"""
    with sse_lock:
        for q in list(sse_subscribers):
            try:
                q.put_nowait(event_data)
            except Exception:
                pass


# Initialize GMM Model
def load_gmm_model():
    """Load pre-trained GMM model if available"""
    global gmm_model, gmm_status_state, gmm_last_error
    model_path = os.path.join(BASE_DIR, GMM_MODEL_REL_PATH)
    if os.path.exists(model_path):
        try:
            profiler = TrafficProfiler()
            profiler.load_model(model_path)
            gmm_model = profiler
            gmm_status_state = 'Trained'
            gmm_last_error = None
            log_audit_event('GMM_INIT', f'GMM Timing Model loaded from {model_path}', 'SUCCESS')
            return True
        except Exception as e:
            gmm_model = None
            gmm_status_state = 'Failed'
            gmm_last_error = str(e)
            log_audit_event('GMM_INIT', f'Failed to load GMM model: {e}', 'WARNING')
            return False
    gmm_status_state = 'Not Trained'
    return False


# ==============================================================================
# PACKET MONITOR SNIFFER ENGINE
# ==============================================================================
class PacketMonitorEngine:
    def __init__(self):
        self.running = False
        self.packets = []
        self.raw_scapy_packets = []
        self.lock = threading.Lock()
        self.sniff_thread = None
        self.max_packets = 500

    def _packet_callback(self, pkt):
        if not self.running:
            return
        try:
            now_ts = time.time()
            now_str = datetime.datetime.fromtimestamp(now_ts).strftime('%H:%M:%S.%f')[:-3]
            
            proto = 'OTHER'
            src = '0.0.0.0'
            dst = '0.0.0.0'
            ip_id = '0x0000'
            ip_id_dec = 0
            ttl = 64
            ihl = 5
            version = 4
            flags = '0x00'
            frag = 0
            
            if pkt.haslayer(IP):
                ip_layer = pkt[IP]
                src = ip_layer.src
                dst = ip_layer.dst
                ip_id_dec = ip_layer.id
                ip_id = f"0x{ip_layer.id:04X}"
                ttl = ip_layer.ttl
                ihl = getattr(ip_layer, 'ihl', 5)
                version = ip_layer.version
                flags = str(ip_layer.flags)
                frag = ip_layer.frag

            icmp_type = None
            icmp_code = None
            icmp_seq = None
            if pkt.haslayer(ICMP):
                proto = 'ICMP'
                icmp_layer = pkt[ICMP]
                icmp_type = icmp_layer.type
                icmp_code = icmp_layer.code
                icmp_seq = getattr(icmp_layer, 'seq', 0)
            elif pkt.haslayer(TCP):
                proto = 'TCP'
            elif pkt.haslayer(UDP):
                proto = 'UDP'

            raw_bytes = bytes(pkt)
            length = len(raw_bytes)
            
            # Format hex dump
            hex_lines = []
            for i in range(0, min(length, 128), 16):
                chunk = raw_bytes[i:i+16]
                hex_str = ' '.join(f'{b:02x}' for b in chunk)
                ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                hex_lines.append(f"{i:04x}   {hex_str:<48}  {ascii_str}")
            hex_dump = '\n'.join(hex_lines)

            # Compute delta-t from previous packet
            with self.lock:
                delta_t = '—'
                if self.packets:
                    diff_ms = (now_ts - self.packets[-1]['timestamp_raw']) * 1000.0
                    delta_t = f"{diff_ms:.1f} ms"
                
                seq_num = len(self.packets) + 1
                channel_tag = 'STANDARD'
                if ip_id == '0xDEAD' or (proto == 'ICMP' and ip_id_dec > 1 and ip_id_dec != 0):
                    channel_tag = 'COVERT_IPID'
                elif proto == 'ICMP':
                    channel_tag = 'ICMP_TEMPORAL'

                entry = {
                    'num': seq_num,
                    'time': now_str,
                    'timestamp_raw': now_ts,
                    'src': src,
                    'dst': dst,
                    'proto': proto,
                    'length': length,
                    'ip_id': ip_id,
                    'ip_id_dec': ip_id_dec,
                    'delta_t': delta_t,
                    'channel': channel_tag,
                    'version': version,
                    'ihl': ihl,
                    'ttl': ttl,
                    'flags': flags,
                    'frag': frag,
                    'icmp_type': icmp_type,
                    'icmp_code': icmp_code,
                    'icmp_seq': icmp_seq,
                    'hex_dump': hex_dump
                }
                self.packets.append(entry)
                self.raw_scapy_packets.append(pkt)
                if len(self.packets) > self.max_packets:
                    self.packets = self.packets[-self.max_packets:]
                    self.raw_scapy_packets = self.raw_scapy_packets[-self.max_packets:]
        except Exception:
            pass

    def start(self, interface: str = None):
        if self.running:
            return
        self.running = True
        target_iface = resolve_sniff_interfaces(interface)
        
        def worker():
            try:
                sniff(
                    iface=target_iface,
                    prn=self._packet_callback,
                    filter="ip",
                    stop_filter=lambda p: not self.running,
                    store=False
                )
            except Exception as e:
                log_audit_event('MONITOR_ERROR', f'Packet monitor sniffer exception: {e}', 'ERROR')
            finally:
                self.running = False

        self.sniff_thread = threading.Thread(target=worker, daemon=True)
        self.sniff_thread.start()
        log_audit_event('MONITOR_START', f'Packet monitor capture started on {interface or "all"}', 'SUCCESS')

    def stop(self):
        self.running = False
        log_audit_event('MONITOR_STOP', 'Packet monitor capture stopped', 'INFO')

    def clear(self):
        with self.lock:
            self.packets.clear()
            self.raw_scapy_packets.clear()

    def export_pcap_bytes(self) -> bytes:
        with self.lock:
            if not self.raw_scapy_packets:
                return b''
            scratch_pcap = os.path.join(DATA_DIR, f"temp_export_{uuid.uuid4().hex[:8]}.pcap")
            try:
                wrpcap(scratch_pcap, self.raw_scapy_packets)
                with open(scratch_pcap, 'rb') as f:
                    data = f.read()
                return data
            except Exception as e:
                print(f"Error exporting pcap: {e}")
                return b''
            finally:
                if os.path.exists(scratch_pcap):
                    try:
                        os.remove(scratch_pcap)
                    except Exception:
                        pass


monitor_engine = PacketMonitorEngine()


# ==============================================================================
# EXPERIMENTS & SETTINGS PERSISTENCE
# ==============================================================================
def load_experiments() -> list:
    if os.path.exists(EXPERIMENTS_FILE):
        try:
            with open(EXPERIMENTS_FILE, 'r', encoding='utf-8') as f:
                experiments = json.load(f)
            actual_experiments = [
                experiment for experiment in experiments
                if experiment.get('id') not in SAMPLE_EXPERIMENT_IDS
            ]
            if len(actual_experiments) != len(experiments):
                save_experiments(actual_experiments)
            return actual_experiments
        except Exception:
            pass
    return []


def save_experiments(exps: list):
    try:
        with open(EXPERIMENTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(exps, f, indent=2)
    except Exception as e:
        print(f"Error saving experiments: {e}")


def load_settings() -> dict:
    default_settings = {
        'theme': 'dark',
        'reduce_motion': False,
        'accent_color': 'cyan',
        'default_target': '127.0.0.1',
        'capture_interface': 'all',
        'session_timeout': 30,
        'secret_visibility': False,
        'default_channel': 'header',
        'default_timing_profile': 'normal'
    }
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                default_settings.update(data)
        except Exception:
            pass
    return default_settings


def save_settings(st: dict):
    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(st, f, indent=2)
    except Exception as e:
        print(f"Error saving settings: {e}")


# ==============================================================================
# RECEIVER CALLBACKS
# ==============================================================================
def status_callback(status: str):
    """Callback for receiver status updates"""
    system_state['total_packets_received'] += 1
    system_state['pipeline']['receiver'] = 'ACTIVE'
    
    if 'Sync marker detected' in status:
        system_state['pipeline']['framing'] = 'ACTIVE'
    if 'Frame extracted' in status:
        system_state['pipeline']['reassembly'] = 'ACTIVE'
    if 'Decryption successful' in status:
        system_state['pipeline']['decryption'] = 'ACTIVE'
        system_state['status'] = 'COMPLETED'
        log_audit_event('DECRYPT_SUCCESS', 'Payload decrypted & authenticated via AES-256-GCM', 'SUCCESS')
    if 'Decryption failed' in status:
        system_state['pipeline']['decryption'] = 'ERROR'
        system_state['status'] = 'ERROR'
        log_audit_event('AUTH_FAILURE', 'Decryption failed: Authentication tag mismatch', 'ERROR')

    event_data = {
        'type': 'status',
        'message': status,
        'timestamp': time.time()
    }
    system_state['recent_status_events'].append(event_data)
    if len(system_state['recent_status_events']) > 50:
        system_state['recent_status_events'] = system_state['recent_status_events'][-50:]
    
    status_queue.put(event_data)
    broadcast_sse_event(event_data)


def message_callback(message: str):
    """Callback for decoded messages"""
    system_state['last_rx_message'] = message
    system_state['status'] = 'COMPLETED'
    system_state['pipeline']['decryption'] = 'ACTIVE'
    event_data = {
        'type': 'message',
        'message': message,
        'timestamp': time.time()
    }
    message_queue.put(event_data)
    broadcast_sse_event(event_data)


# ==============================================================================
# CORE ROUTING & OVERVIEW API
# ==============================================================================
@app.route('/')
def index():
    """Render NetGhost console, defaulting to node role if running standalone"""
    gmm_available = gmm_model is not None
    node_role = os.environ.get('NETGHOST_MODE', 'unified')
    host_port = request.host.split(':')[-1] if ':' in request.host else ('5001' if node_role == 'receiver' else '5000')
    node_port = os.environ.get('NETGHOST_PORT', host_port)
    default_view = 'sender' if node_role == 'sender' else ('receiver' if node_role == 'receiver' else 'overview')
    peer_url = "http://127.0.0.1:5001/receiver" if node_role == 'sender' else ("http://127.0.0.1:5000/sender" if node_role == 'receiver' else None)
    return render_template(
        'index.html',
        gmm_available=gmm_available,
        default_view=default_view,
        node_role=node_role,
        node_port=node_port,
        peer_url=peer_url
    )


@app.route('/sender')
def sender_page():
    """Dedicated Sender View on http://<host>:<port>/sender"""
    gmm_available = gmm_model is not None
    host_port = request.host.split(':')[-1] if ':' in request.host else '5000'
    node_role = 'sender'
    peer_url = "http://127.0.0.1:5001/receiver"
    return render_template(
        'index.html',
        gmm_available=gmm_available,
        default_view='sender',
        node_role=node_role,
        node_port=host_port,
        peer_url=peer_url
    )


@app.route('/receiver')
def receiver_page():
    """Dedicated Receiver View on http://<host>:<port>/receiver"""
    gmm_available = gmm_model is not None
    host_port = request.host.split(':')[-1] if ':' in request.host else '5001'
    node_role = 'receiver'
    peer_url = "http://127.0.0.1:5000/sender"
    return render_template(
        'index.html',
        gmm_available=gmm_available,
        default_view='receiver',
        node_role=node_role,
        node_port=host_port,
        peer_url=peer_url
    )


@app.route('/api/overview')
def get_overview_state():
    """Return live system telemetry, active channel, packet counts, and pipeline state"""
    exps = load_experiments()
    gmm_avail = gmm_model is not None
    rx_active = current_receiver.running if current_receiver else False
    return jsonify({
        'status': system_state['status'],
        'active_channel': system_state['active_channel'],
        'receiver_active': rx_active,
        'last_rx_message': system_state.get('last_rx_message'),
        'total_packets_sent': system_state['total_packets_sent'],
        'total_packets_received': system_state['total_packets_received'],
        'total_bytes_sent': system_state['total_bytes_sent'],
        'total_bytes_received': system_state['total_bytes_received'],
        'stealth_score': system_state['stealth_score'],
        'gmm_available': gmm_avail,
        'experiments_count': len(exps),
        'pipeline': system_state['pipeline'],
        'audit_log': system_state['audit_log'][:8]
    })


@app.route('/api/receiver/state')
def get_receiver_state():
    """Return real-time receiver state, sync detection, and last recovered plaintext"""
    global current_receiver
    if current_receiver and hasattr(current_receiver, 'get_state'):
        rx_state = current_receiver.get_state()
    else:
        rx_state = {
            'running': False,
            'channel': 'None',
            'packets_received': 0,
            'icmp_packets': 0,
            'sync_detected': False,
            'frame_extracted': False,
            'decryption_success': False,
            'last_message': system_state.get('last_rx_message'),
            'last_error': None,
            'recent_packets': [],
            'status_history': []
        }
    
    # Only fallback to system_state['last_rx_message'] if decryption did not explicitly fail
    if not rx_state.get('last_message') and system_state.get('last_rx_message') and not rx_state.get('last_error') and not rx_state.get('sync_detected'):
        rx_state['last_message'] = system_state['last_rx_message']
        rx_state['decryption_success'] = True

    rx_state['system_status'] = system_state['status']
    rx_state['pipeline'] = system_state['pipeline']
    return jsonify({'success': True, 'data': rx_state})


# ==============================================================================
# SENDER ENDPOINTS
# ==============================================================================
@app.route('/api/sender/prepare', methods=['POST'])
def prepare_payload():
    """
    Real Cryptographic Preparation Endpoint.
    Performs PBKDF2 key derivation, AES-256-GCM encryption, framing, and fragment calculation.
    """
    try:
        data = request.get_json(silent=True) or {}
        message = data.get('message', '')
        passphrase = data.get('passphrase', '')
        mode = data.get('mode', 'header')

        if not passphrase:
            return jsonify({'error': 'Shared secret passphrase is required for key derivation.'}), 400
        if not message:
            return jsonify({'error': 'Plaintext payload cannot be empty.'}), 400
        if len(message) > 10000:
            return jsonify({'error': 'Payload exceeds maximum limit (10,000 characters).'}), 400

        # Step 1: Encrypt with AES-256-GCM
        encrypted = encrypt_message(message, passphrase)
        salt = encrypted[:SALT_SIZE]
        nonce = encrypted[SALT_SIZE:SALT_SIZE + GCM_NONCE_SIZE]
        tag = encrypted[-16:]
        ciphertext = encrypted[SALT_SIZE + GCM_NONCE_SIZE:-16]

        # Step 2: Create Frame
        frame = create_frame(encrypted)

        # Step 3: Compute Fragments & Preview
        if mode == 'header':
            uint16_vals = bytes_to_uint16_list(frame)
            fragment_count = len(uint16_vals)
            preview_items = [
                {'idx': 1, 'hex': f"0x{uint16_vals[0]:04X}", 'desc': 'SYNC_MARKER (0xDEAD)'},
                {'idx': 2, 'hex': f"0x{uint16_vals[1]:04X}", 'desc': f'LENGTH ({len(encrypted)}B)'}
            ]
            for i, val in enumerate(uint16_vals[2:6], start=3):
                preview_items.append({'idx': i, 'hex': f"0x{val:04X}", 'desc': f'CIPHERTEXT_CHUNK_{i-2}'})
        else:
            bits = bytes_to_bits(frame)
            fragment_count = len(bits) + 1  # includes lead sync packet
            preview_items = [
                {'idx': 1, 'hex': '0xDEAD', 'desc': 'SYNC_LEAD_PACKET'},
                {'idx': 2, 'hex': f"BIT_STREAM_{len(bits)}b", 'desc': f'IPD_MODULATED ({len(bits)} bits)'}
            ]

        system_state['pipeline']['encryption'] = 'READY'
        system_state['pipeline']['framing'] = 'READY'

        return jsonify({
            'success': True,
            'plaintext_length': len(message),
            'salt_size_bytes': SALT_SIZE,
            'salt_hex': salt.hex().upper(),
            'nonce_size_bytes': GCM_NONCE_SIZE,
            'nonce_hex': nonce.hex().upper(),
            'tag_size_bytes': 16,
            'tag_hex': tag.hex().upper(),
            'encrypted_size_bytes': len(encrypted),
            'frame_size_bytes': len(frame),
            'frame_hex': frame.hex().upper(),
            'fragment_count': fragment_count,
            'mode': mode,
            'preview_fragments': preview_items
        })
    except Exception as e:
        return jsonify({'error': f"Preparation failed: {str(e)}"}), 500


@app.route('/send', methods=['POST'])
def send_message():
    """Handle covert message transmission"""
    try:
        data = request.get_json(silent=True) or {}
        raw_target = data.get('target_ip', '127.0.0.1').strip()
        # Sanitize target IP: ICMP operates at Layer 3 (IP), so strip any Layer 4 ports (e.g. :5001) or URL schemes
        clean_target = raw_target.replace('http://', '').replace('https://', '').strip()
        if ':' in clean_target:
            clean_target = clean_target.split(':')[0].strip()
        target_ip = clean_target or '127.0.0.1'
        
        passphrase = data.get('passphrase', '').strip()
        message = data.get('message', '')
        mode = data.get('mode', 'header')
        timing_profile = (data.get('timing_profile') or 'normal').strip().lower()
        delay_ms = float(data.get('delay_ms', 50.0))
        
        if not target_ip:
            return jsonify({'error': 'Destination Target IP address is required'}), 400
        if not passphrase:
            return jsonify({'error': 'Shared Secret Passphrase is required'}), 400
        if not message:
            return jsonify({'error': 'Plaintext Message payload cannot be empty'}), 400
        if timing_profile not in VALID_TIMING_PROFILES:
            return jsonify({'error': f"Invalid timing profile '{timing_profile}'. Must be one of: {', '.join(VALID_TIMING_PROFILES)}"}), 400

        if timing_profile == 'gmm':
            if not gmm_model or not gmm_model.is_trained():
                load_gmm_model()
            if not gmm_model or not gmm_model.is_trained():
                return jsonify({
                    'error': 'GMM model is not trained or loaded. Please train or load a GMM model in Traffic Profiler first.'
                }), 400
        
        system_state['status'] = 'TRANSMITTING'
        system_state['active_channel'] = 'IP-ID Header Embedding' if mode == 'header' else 'Temporal IPD'
        system_state['pipeline']['sender'] = 'ACTIVE'
        system_state['pipeline']['channel'] = 'ACTIVE'
        system_state['pipeline']['icmp'] = 'ACTIVE'
        
        if mode == 'header':
            sender = HeaderChannelSender(target_ip)
            stats = sender.send_message(
                message,
                passphrase,
                packet_callback=broadcast_sse_event,
                timing_profile=timing_profile,
                gmm_model=gmm_model if timing_profile == 'gmm' else None,
                delay_ms=delay_ms,
            )
            system_state['total_packets_sent'] += stats['packets_sent']
            system_state['total_bytes_sent'] += stats['frame_size']
            system_state['last_tx_time'] = time.time()
            system_state['status'] = 'COMPLETED'
            log_audit_event('TX_HEADER', f"Sent {stats['packets_sent']} packets ({stats['frame_size']}B, {stats['timing_profile_label']}) to {target_ip}", 'SUCCESS')
            return jsonify({'success': True, 'stats': stats})
        
        elif mode == 'temporal':
            bit_0_delay = float(data.get('bit_0_delay', 25)) / 1000.0
            bit_1_delay = float(data.get('bit_1_delay', 125)) / 1000.0
            model = gmm_model if timing_profile == 'gmm' else None
            
            sender = TemporalChannelSender(target_ip)
            stats = sender.send_message(
                message,
                passphrase,
                bit_0_delay=bit_0_delay,
                bit_1_delay=bit_1_delay,
                timing_profile=timing_profile,
                gmm_model=model,
                packet_callback=broadcast_sse_event
            )
            system_state['total_packets_sent'] += stats['packets_sent']
            system_state['total_bytes_sent'] += stats['frame_size']
            system_state['last_tx_time'] = time.time()
            system_state['status'] = 'COMPLETED'
            log_audit_event('TX_TEMPORAL', f"Sent {stats['packets_sent']} packets ({stats.get('timing_profile_label', stats['timing_profile'])} IPD) to {target_ip}", 'SUCCESS')
            return jsonify({'success': True, 'stats': stats})
        
        else:
            return jsonify({'error': f"Invalid channel mode: {mode}"}), 400
    
    except Exception as e:
        system_state['status'] = 'ERROR'
        system_state['pipeline']['sender'] = 'ERROR'
        broadcast_sse_event({'type': 'tx_failed', 'error': str(e), 'timestamp': time.time()})
        log_audit_event('TX_ERROR', f"Transmission failed: {str(e)}", 'ERROR')
        return jsonify({'error': str(e)}), 500


# ==============================================================================
# RECEIVER ENDPOINTS
# ==============================================================================
@app.route('/start', methods=['POST'])
def start_receiver():
    """Start listening for incoming covert packets"""
    global current_receiver
    
    try:
        data = request.get_json(silent=True) or {}
        passphrase = data.get('passphrase', '').strip()
        mode = data.get('mode', 'header')
        interface = data.get('interface', None)
        
        if not passphrase:
            return jsonify({'error': 'Shared Secret Passphrase is required to start sniffer.'}), 400
        
        # Clear queues
        while not status_queue.empty():
            try:
                status_queue.get_nowait()
            except queue.Empty:
                break
        while not message_queue.empty():
            try:
                message_queue.get_nowait()
            except queue.Empty:
                break
        
        if current_receiver:
            current_receiver.stop_listening()
            current_receiver = None
        
        system_state['last_rx_message'] = None
        
        if mode == 'header':
            current_receiver = HeaderChannelReceiver(passphrase)
        elif mode == 'temporal':
            threshold = float(data.get('threshold', 65.0))
            current_receiver = TemporalChannelReceiver(passphrase, threshold)
        else:
            return jsonify({'error': f"Invalid receiver mode: {mode}"}), 400
        
        current_receiver.set_status_callback(status_callback)
        current_receiver.set_event_callback(broadcast_sse_event)
        current_receiver.set_message_callback(message_callback)
        current_receiver.start_listening(interface=interface, timeout=600)
        
        system_state['status'] = 'RECEIVING'
        system_state['pipeline']['receiver'] = 'ACTIVE'
        log_audit_event('RX_START', f"Receiver sniffer started in {mode.upper()} mode on {interface or 'all'}", 'SUCCESS')
        
        return jsonify({'success': True})
    
    except Exception as e:
        system_state['status'] = 'ERROR'
        system_state['pipeline']['receiver'] = 'ERROR'
        log_audit_event('RX_ERROR', f"Failed to start receiver: {str(e)}", 'ERROR')
        return jsonify({'error': str(e)}), 500


@app.route('/stop', methods=['POST'])
def stop_receiver():
    """Stop receiving covert packets"""
    global current_receiver
    
    if current_receiver:
        current_receiver.stop_listening()
        current_receiver = None
    
    broadcast_sse_event({'type': 'rx_stopped', 'timestamp': time.time()})
    system_state['status'] = 'READY'
    system_state['pipeline']['receiver'] = 'READY'
    log_audit_event('RX_STOP', "Receiver sniffer stopped", 'INFO')
    return jsonify({'success': True})


@app.route('/stream')
def stream():
    """Server-Sent Events stream for real-time packet observation & message decoding"""
    def event_stream():
        client_q = queue.Queue(maxsize=5000)
        with sse_lock:
            sse_subscribers.append(client_q)
        try:
            # Yield initial connection event
            yield f"data: {json.dumps({'type': 'connection', 'status': 'connected', 'timestamp': time.time()})}\n\n"
            
            # Send initial replay of current state if receiver has captured packets or recovered message
            if system_state.get('last_rx_message'):
                yield f"data: {json.dumps({'type': 'message', 'message': system_state['last_rx_message'], 'timestamp': time.time()})}\n\n"
            
            while True:
                try:
                    event = client_q.get(timeout=0.5)
                    yield f"data: {json.dumps(event)}\n\n"
                except queue.Empty:
                    yield f": keepalive\n\n"
                time.sleep(0.02)
        finally:
            with sse_lock:
                if client_q in sse_subscribers:
                    sse_subscribers.remove(client_q)

    return Response(event_stream(), mimetype='text/event-stream')


# ==============================================================================
# PROFILER & ML ENDPOINTS
# ==============================================================================
@app.route('/gmm_status')
def gmm_status():
    """Check GMM model status and validation metrics"""
    is_loaded = bool(gmm_model and gmm_model.is_trained())
    model_path = os.path.join(BASE_DIR, GMM_MODEL_REL_PATH)
    if is_loaded:
        stats = gmm_model.get_statistics()
        return jsonify({
            'available': True,
            'loaded': True,
            'status': 'Trained',
            'model_file': GMM_MODEL_REL_PATH,
            'model_exists_on_disk': os.path.exists(model_path),
            'error': None,
            'statistics': stats
        })
    return jsonify({
        'available': False,
        'loaded': False,
        'status': gmm_status_state,
        'model_file': GMM_MODEL_REL_PATH,
        'model_exists_on_disk': os.path.exists(model_path),
        'error': gmm_last_error,
        'statistics': None
    })


@app.route('/api/profiler/load', methods=['POST'])
def api_load_gmm():
    """Explicitly load saved GMM model from disk"""
    global gmm_model, gmm_status_state, gmm_last_error
    model_path = os.path.join(BASE_DIR, GMM_MODEL_REL_PATH)
    if not os.path.exists(model_path):
        gmm_status_state = 'Not Trained'
        gmm_last_error = f"Model file not found: {GMM_MODEL_REL_PATH}"
        return jsonify({'success': False, 'status': 'Not Trained', 'loaded': False, 'error': gmm_last_error}), 404
    try:
        profiler = TrafficProfiler()
        profiler.load_model(model_path)
        gmm_model = profiler
        gmm_status_state = 'Trained'
        gmm_last_error = None
        stats = profiler.get_statistics()
        log_audit_event('GMM_LOAD', f"Loaded GMM model from {GMM_MODEL_REL_PATH}", 'SUCCESS')
        return jsonify({
            'success': True,
            'status': 'Trained',
            'loaded': True,
            'model_file': GMM_MODEL_REL_PATH,
            'statistics': stats
        })
    except Exception as e:
        gmm_model = None
        gmm_status_state = 'Failed'
        gmm_last_error = str(e)
        return jsonify({'success': False, 'status': 'Failed', 'loaded': False, 'error': str(e)}), 500


def _build_profiler_response(delays: list, filename: str, n_components: int = 3):
    """Helper to fit GMM, compute validation metrics, histogram, and save model"""
    global gmm_model, gmm_status_state, gmm_last_error
    gmm_status_state = 'Training'
    try:
        arr = np.array(delays, dtype=float)
        arr = arr[np.isfinite(arr) & (arr > 0)]
        if len(arr) < 10:
            raise ValueError("Need at least 10 valid packet delay samples to train GMM model.")

        profiler = TrafficProfiler(n_components=n_components)
        cleaned = profiler.clean_timing_data(arr)
        if len(cleaned) < 10:
            raise ValueError("Insufficient samples remaining after outlier cleaning (need at least 10).")

        profiler.train_gmm(cleaned, dataset_source=filename)

        model_path = os.path.join(BASE_DIR, GMM_MODEL_REL_PATH)
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        profiler.save_model(model_path)
        gmm_model = profiler
        gmm_status_state = 'Trained'
        gmm_last_error = None
    except Exception as e:
        gmm_status_state = 'Failed'
        gmm_last_error = str(e)
        log_audit_event('PROFILER_FAIL', f"GMM training failed on {filename}: {e}", 'ERROR')
        raise

    # Compute statistics
    total_duration_sec = np.sum(arr) / 1000.0
    hrs = int(total_duration_sec // 3600)
    mins = int((total_duration_sec % 3600) // 60)
    secs = int(total_duration_sec % 60)
    duration_str = f"{hrs:02d}:{mins:02d}:{secs:02d}"

    avg_ipd = float(np.mean(arr))
    median_ipd = float(np.median(arr))
    jitter = float(np.std(arr))

    # Compute histogram (20 bins)
    hist, bin_edges = np.histogram(cleaned, bins=20, density=True)
    hist_counts, _ = np.histogram(cleaned, bins=20)
    bin_centers = [(bin_edges[i] + bin_edges[i+1])/2 for i in range(len(hist))]

    stats = profiler.get_statistics()
    samples = [round(float(s), 2) for s in profiler.sample_delay(15)]

    # Compute exact PDF curve points for canvas rendering
    x_eval = np.linspace(float(np.min(cleaned)), float(np.max(cleaned)), 100)
    log_pdf = profiler.gmm.score_samples(x_eval.reshape(-1, 1))
    pdf_eval = np.exp(log_pdf)

    # Component details for table
    comp_details = []
    for i in range(n_components):
        comp_details.append({
            'component': f"C{i+1}",
            'weight': round(float(stats['weights'][i]), 3),
            'mean': round(float(stats['means'][i]), 2),
            'variance': round(float(stats['variances'][i]), 2)
        })

    log_audit_event(
        'PROFILER_TRAIN',
        f"GMM trained on {filename} ({stats.get('n_samples', len(cleaned))} samples, K={n_components}, LL={stats.get('log_likelihood')})",
        'SUCCESS'
    )

    return {
        'success': True,
        'status': 'Trained',
        'loaded': True,
        'model_file': GMM_MODEL_REL_PATH,
        'filename': filename,
        'packets': int(len(arr) + 1),
        'n_samples': int(stats.get('n_samples', len(cleaned))),
        'duration': duration_str,
        'avg_ipd': f"{avg_ipd:.1f} ms",
        'median_ipd': f"{median_ipd:.1f} ms",
        'jitter': f"{jitter:.1f} ms",
        'components': n_components,
        'log_likelihood': stats.get('log_likelihood'),
        'aic': stats.get('aic'),
        'bic': stats.get('bic'),
        'component_details': comp_details,
        'stats': stats,
        'raw_delays_sample': [round(float(x), 1) for x in cleaned[:100]],
        'pdf_curve': {
            'x': [round(float(x), 1) for x in x_eval],
            'y': [round(float(y), 5) for y in pdf_eval]
        },
        'histogram': {
            'bin_centers': [round(float(c), 1) for c in bin_centers],
            'frequencies': [round(float(f), 4) for f in hist],
            'counts': [int(c) for c in hist_counts]
        },
        'samples': samples
    }


@app.route('/api/profiler/upload_pcap', methods=['POST'])
def upload_pcap():
    """Handle PCAP / CSV file upload and train GMM timing model"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded in request'}), 400

    file = request.files['file']
    if not file or not file.filename:
        return jsonify({'error': 'Empty filename uploaded'}), 400

    filename = file.filename
    ext = os.path.splitext(filename)[1].lower()

    scratch_dir = os.path.join(BASE_DIR, 'scratch')
    os.makedirs(scratch_dir, exist_ok=True)
    temp_path = os.path.join(scratch_dir, f"upload_{int(time.time())}_{filename}")
    file.save(temp_path)

    try:
        delays = []
        if ext in ['.pcap', '.pcapng', '.cap']:
            profiler = TrafficProfiler()
            timing_data = profiler.extract_timing_from_pcap(temp_path)
            delays = timing_data.tolist()
        elif ext in ['.csv', '.txt']:
            with open(temp_path, 'r', encoding='utf-8') as f:
                content = f.read()
            import re
            numbers = re.findall(r'[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?', content)
            delays = [float(n) for n in numbers if float(n) > 0]
        else:
            return jsonify({'error': 'Unsupported file format. Please upload .pcap, .pcapng, or .csv'}), 400

        res = _build_profiler_response(delays, filename, n_components=3)
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': f"Processing failed: {str(e)}"}), 500
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


@app.route('/api/profiler/preset', methods=['POST'])
def load_preset_profile():
    """Generate realistic baseline traffic dataset for benchmark testing"""
    data = request.get_json(silent=True) or {}
    preset = data.get('preset', 'http')
    n_components = int(data.get('components', 3))

    np.random.seed(int(time.time()) % 100000)
    if preset == 'video':
        c1 = np.random.normal(15.0, 3.5, 4500)
        c2 = np.random.normal(50.0, 8.0, 3000)
        c3 = np.random.normal(120.0, 20.0, 800)
        delays = np.concatenate([c1, c2, c3])
        filename = "video_streaming_capture.pcap"
    elif preset == 'dns':
        c1 = np.random.normal(45.0, 6.0, 3500)
        c2 = np.random.normal(110.0, 15.0, 2500)
        c3 = np.random.normal(300.0, 45.0, 1000)
        delays = np.concatenate([c1, c2, c3])
        filename = "dns_telemetry_capture.pcap"
    else:
        c1 = np.random.normal(20.0, 5.0, 6200)
        c2 = np.random.normal(75.0, 15.0, 4100)
        c3 = np.random.normal(220.0, 40.0, 2180)
        delays = np.concatenate([c1, c2, c3])
        filename = "http_web_browsing.pcap"

    try:
        res = _build_profiler_response(delays.tolist(), filename, n_components=n_components)
        return jsonify(res)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/profiler/train', methods=['POST'])
def train_gmm():
    """Train or retrain GMM timing model from request parameters"""
    data = request.get_json(silent=True) or {}
    if 'delays' in data and data['delays']:
        n_components = int(data.get('components', 3))
        res = _build_profiler_response(data['delays'], "custom_distribution.pcap", n_components=n_components)
        return jsonify(res)
    return load_preset_profile()


# ==============================================================================
# PACKET MONITOR ENDPOINTS
# ==============================================================================
@app.route('/api/monitor/start', methods=['POST'])
def start_packet_monitor():
    data = request.get_json(silent=True) or {}
    interface = data.get('interface', None)
    monitor_engine.start(interface=interface)
    return jsonify({'success': True, 'running': True})


@app.route('/api/monitor/stop', methods=['POST'])
def stop_packet_monitor():
    monitor_engine.stop()
    return jsonify({'success': True, 'running': False})


@app.route('/api/monitor/packets')
def get_monitor_packets():
    proto_filter = request.args.get('filter', 'all').upper()
    limit = int(request.args.get('limit', 100))
    
    with monitor_engine.lock:
        pkts = monitor_engine.packets[:]
    
    if proto_filter != 'ALL':
        pkts = [p for p in pkts if p['proto'] == proto_filter]
    
    return jsonify({
        'running': monitor_engine.running,
        'total': len(pkts),
        'packets': pkts[-limit:]
    })


@app.route('/api/monitor/clear', methods=['POST'])
def clear_monitor_packets():
    monitor_engine.clear()
    return jsonify({'success': True})


@app.route('/api/monitor/export_pcap')
def export_monitor_pcap():
    pcap_data = monitor_engine.export_pcap_bytes()
    if not pcap_data:
        return jsonify({'error': 'No captured packets available to export.'}), 400
    
    return send_file(
        io.BytesIO(pcap_data),
        mimetype='application/vnd.tcpdump.pcap',
        as_attachment=True,
        download_name=f"netghost_capture_{int(time.time())}.pcap"
    )


# ==============================================================================
# EXPERIMENTS REGISTRY & EXECUTION ENDPOINTS
# ==============================================================================
@app.route('/api/experiments/list')
def list_experiments():
    exps = load_experiments()
    return jsonify({'success': True, 'experiments': exps})


@app.route('/api/experiments/create', methods=['POST'])
def create_experiment():
    data = request.get_json(silent=True) or {}
    name = data.get('name', '').strip()
    channel = data.get('channel', 'header')
    payload = data.get('payload', '').strip()
    timing_profile = data.get('timing_profile', 'Normal')
    target_ip = data.get('target_ip', '127.0.0.1')
    interface = data.get('interface', 'Loopback')

    if not name:
        return jsonify({'error': 'Experiment Name is required'}), 400
    if not payload:
        return jsonify({'error': 'Payload content is required'}), 400

    new_exp = {
        'id': f"exp-{uuid.uuid4().hex[:6]}",
        'name': name,
        'channel': 'IP-ID Header Embedding' if channel == 'header' else 'Temporal IPD',
        'payload': payload,
        'timing_profile': timing_profile,
        'target_ip': target_ip,
        'interface': interface,
        'status': 'Created',
        'created_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'started_at': None,
        'completed_at': None,
        'results': None
    }

    exps = load_experiments()
    exps.insert(0, new_exp)
    save_experiments(exps)
    log_audit_event('EXP_CREATE', f"Experiment '{name}' created ({new_exp['id']})", 'SUCCESS')

    return jsonify({'success': True, 'experiment': new_exp})


@app.route('/api/experiments/<exp_id>/run', methods=['POST'])
def run_experiment(exp_id):
    exps = load_experiments()
    exp = next((e for e in exps if e['id'] == exp_id), None)
    if not exp:
        return jsonify({'error': f'Experiment {exp_id} not found'}), 404

    exp['status'] = 'Running'
    exp['started_at'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    save_experiments(exps)

    try:
        target_ip = exp.get('target_ip', '127.0.0.1')
        payload = exp.get('payload', 'TEST')
        passphrase = 'demo123'
        is_header = 'Header' in exp.get('channel', '')

        if is_header:
            sender = HeaderChannelSender(target_ip)
            stats = sender.send_message(payload, passphrase)
        else:
            sender = TemporalChannelSender(target_ip)
            profile = exp.get('timing_profile', 'normal').lower()
            if 'gmm' in profile:
                profile = 'gmm'
            elif 'gamma' in profile:
                profile = 'gamma'
            elif 'constant' in profile:
                profile = 'constant'
            else:
                profile = 'normal'
            stats = sender.send_message(payload, passphrase, timing_profile=profile, gmm_model=gmm_model)

        measured_delays = [
            float(packet.get('actual_delay_ms', 0))
            for packet in stats.get('transmission_log', [])[1:]
            if float(packet.get('actual_delay_ms', 0)) > 0
        ]

        exp['status'] = 'Completed'
        exp['completed_at'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        exp['results'] = {
            'measurement_source': 'sender',
            'payload_bytes': len(payload.encode('utf-8')),
            'packets_sent': stats['packets_sent'],
            'duration_s': round(float(stats['duration_seconds']), 2),
            'throughput_bps': round(float(stats['throughput_bps']), 1),
            'avg_inter_packet_delay_ms': (
                round(float(np.mean(measured_delays)), 2) if measured_delays else None
            )
        }
        save_experiments(exps)
        log_audit_event('EXP_RUN', f"Experiment '{exp['name']}' completed successfully", 'SUCCESS')
        return jsonify({'success': True, 'experiment': exp})
    except Exception as e:
        exp['status'] = 'Failed'
        exp['completed_at'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        exp['results'] = {'error': str(e)}
        save_experiments(exps)
        log_audit_event('EXP_FAIL', f"Experiment '{exp['name']}' failed: {e}", 'ERROR')
        return jsonify({'error': str(e)}), 500


@app.route('/api/experiments/<exp_id>/view')
def view_experiment(exp_id):
    exps = load_experiments()
    exp = next((e for e in exps if e['id'] == exp_id), None)
    if not exp:
        return jsonify({'error': 'Experiment not found'}), 404
    return jsonify({'success': True, 'experiment': exp})


@app.route('/api/experiments/<exp_id>/delete', methods=['POST'])
def delete_experiment(exp_id):
    exps = load_experiments()
    exps = [e for e in exps if e['id'] != exp_id]
    save_experiments(exps)
    return jsonify({'success': True})


@app.route('/api/experiments/clear', methods=['POST'])
def clear_all_experiments():
    save_experiments([])
    return jsonify({'success': True})


# ==============================================================================
# RESULTS & ANALYTICS ENDPOINTS
# ==============================================================================
@app.route('/api/results/data')
def get_results_analytics():
    exps = load_experiments()
    completed = [
        e for e in exps
        if e.get('status') == 'Completed'
        and isinstance(e.get('results'), dict)
        and e['results'].get('measurement_source') == 'sender'
    ]
    
    if not completed:
        return jsonify({
            'available': False,
            'message': 'No measured sender-side experiment results available.',
            'experiments_count': 0,
            'total_packets_transmitted': 0,
            'avg_throughput_bps': None,
            'avg_duration_s': None,
            'avg_inter_packet_delay_ms': None,
            'series': []
        })
    
    throughputs = [e['results']['throughput_bps'] for e in completed]
    durations = [e['results']['duration_s'] for e in completed]
    total_packets = sum(e['results']['packets_sent'] for e in completed)
    measured_delays = [
        e['results']['avg_inter_packet_delay_ms']
        for e in completed
        if e['results'].get('avg_inter_packet_delay_ms') is not None
    ]
    
    series_data = []
    for e in completed:
        series_data.append({
            'name': e['name'],
            'channel': e['channel'],
            'throughput_bps': e['results']['throughput_bps'],
            'duration_s': e['results']['duration_s'],
            'packets': e['results']['packets_sent'],
            'payload_bytes': e['results']['payload_bytes'],
            'avg_inter_packet_delay_ms': e['results'].get('avg_inter_packet_delay_ms')
        })

    return jsonify({
        'available': True,
        'experiments_count': len(completed),
        'total_packets_transmitted': total_packets,
        'avg_throughput_bps': round(float(np.mean(throughputs)), 1),
        'avg_duration_s': round(float(np.mean(durations)), 2),
        'avg_inter_packet_delay_ms': (
            round(float(np.mean(measured_delays)), 2) if measured_delays else None
        ),
        'series': series_data
    })


@app.route('/api/results/export_report')
def export_results_report():
    exps = load_experiments()
    completed = [
        e for e in exps
        if e.get('status') == 'Completed'
        and isinstance(e.get('results'), dict)
        and e['results'].get('measurement_source') == 'sender'
    ]
    
    fmt = request.args.get('format', 'csv').lower()
    
    if fmt == 'json':
        return jsonify({'exported_at': datetime.datetime.now().isoformat(), 'results': completed})
    
    # CSV generation
    output = io.StringIO(newline='')
    writer = csv.writer(output)
    writer.writerow([
        'Experiment ID', 'Name', 'Channel', 'Payload Size (bytes)',
        'Packets Sent', 'Duration (s)', 'Throughput (bps)',
        'Average Inter-packet Delay (ms)', 'Status'
    ])
    for e in completed:
        r = e['results']
        writer.writerow([
            e['id'], e['name'], e['channel'], r.get('payload_bytes', ''),
            r.get('packets_sent', 0), r.get('duration_s', 0),
            r.get('throughput_bps', 0), r.get('avg_inter_packet_delay_ms', ''),
            e['status']
        ])

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f"attachment;filename=netghost_results_report_{int(time.time())}.csv"}
    )


# ==============================================================================
# SETTINGS ENDPOINTS
# ==============================================================================
@app.route('/api/settings', methods=['GET', 'POST'])
def handle_settings():
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        save_settings(data)
        log_audit_event('SETTINGS_UPDATE', 'Laboratory settings updated and persisted', 'SUCCESS')
        return jsonify({'success': True, 'settings': data})
    else:
        st = load_settings()
        return jsonify({'success': True, 'settings': st})


@app.route('/api/settings/reset', methods=['POST'])
def reset_settings():
    default_st = {
        'theme': 'dark',
        'reduce_motion': False,
        'accent_color': 'cyan',
        'default_target': '127.0.0.1',
        'capture_interface': 'all',
        'session_timeout': 30,
        'secret_visibility': False,
        'default_channel': 'header',
        'default_timing_profile': 'normal'
    }
    save_settings(default_st)
    log_audit_event('SETTINGS_RESET', 'Settings reset to factory defaults', 'INFO')
    return jsonify({'success': True, 'settings': default_st})


if __name__ == '__main__':
    print("=" * 65)
    print("👻  NETGHOST - UNIFIED NETWORK STEGANOGRAPHY LABORATORY CONSOLE")
    print("=" * 65)
    print()
    
    load_gmm_model()
    print()
    print("Starting Unified Laboratory Console on:")
    print("👉  URL: http://127.0.0.1:5000")
    print()
    print("Contains all 9 screens:")
    print("  1. Overview / Control Center   6. Experiments")
    print("  2. Sender                      7. Results")
    print("  3. Receiver                    8. Documentation")
    print("  4. Traffic Profiler            9. Settings")
    print("  5. Packet Monitor")
    print()
    print("Press Ctrl+C to stop")
    print("=" * 65)
    print()
    
    app.run(host='127.0.0.1', port=5000, debug=False, threaded=True)
