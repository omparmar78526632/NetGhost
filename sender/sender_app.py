"""
NETGHOST – DEDICATED SENDER NODE  (port 5000)
Self-contained Flask app: serves the Sender UI and all send/prepare APIs.
No dependency on app.py.

Run:
    python sender/sender_app.py          (normal)
    python sender/sender_app.py --port 5000
"""

import os
import sys
import json
import queue
import time
import threading

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.winmm.timeBeginPeriod(1)
    except Exception:
        pass

from flask import Flask, render_template, request, jsonify, Response

from common.crypto import encrypt_message, SALT_SIZE, GCM_NONCE_SIZE
from common.framing import create_frame
from common.utils import bytes_to_uint16_list, bytes_to_bits
from common.timing import VALID_TIMING_PROFILES
from sender.sender_core import HeaderChannelSender, TemporalChannelSender
from ml.ml_profiler import TrafficProfiler


# ── Flask setup ──────────────────────────────────────────────────────────────
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "sender", "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
    static_url_path="/static",
)
app.secret_key = os.urandom(24)

# ── GMM model ─────────────────────────────────────────────────────────────────
gmm_model = None
GMM_MODEL_PATH = os.path.join(BASE_DIR, "ml", "models", "gmm_timing.pkl")


def load_gmm_model():
    global gmm_model
    if os.path.exists(GMM_MODEL_PATH):
        try:
            profiler = TrafficProfiler()
            profiler.load_model(GMM_MODEL_PATH)
            gmm_model = profiler
            print(f"  [✓] GMM model loaded from {GMM_MODEL_PATH}")
            return True
        except Exception as e:
            print(f"  [!] Failed to load GMM model: {e}")
    else:
        print(f"  [!] GMM model not found — run: python ml/train_model.py")
    return False


# ── SSE broadcast ─────────────────────────────────────────────────────────────
sse_subscribers = []
sse_lock = threading.Lock()


def broadcast(event_data: dict):
    with sse_lock:
        for q in list(sse_subscribers):
            try:
                q.put_nowait(event_data)
            except Exception:
                pass


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
@app.route("/sender")
def index():
    return render_template(
        "sender.html",
        default_view="sender",
        node_role="sender",
        node_port="5000",
        peer_url="http://127.0.0.1:5001/receiver",
        gmm_available=gmm_model is not None,
    )


@app.route("/api/sender/prepare", methods=["POST"])
def prepare_payload():
    """Encrypt & frame the payload; return preview metrics — no packets sent."""
    try:
        data = request.get_json(silent=True) or {}
        message = data.get("message", "")
        passphrase = data.get("passphrase", "")
        mode = data.get("mode", "header")

        if not passphrase:
            return jsonify({"error": "Shared secret passphrase is required."}), 400
        if not message:
            return jsonify({"error": "Plaintext message cannot be empty."}), 400
        if len(message) > 10000:
            return jsonify({"error": "Message exceeds 10 000 character limit."}), 400

        encrypted = encrypt_message(message, passphrase)
        salt = encrypted[:SALT_SIZE]
        nonce = encrypted[SALT_SIZE: SALT_SIZE + GCM_NONCE_SIZE]
        tag = encrypted[-16:]
        frame = create_frame(encrypted)

        if mode == "header":
            uint16_vals = bytes_to_uint16_list(frame)
            fragment_count = len(uint16_vals)
            preview = [
                {"idx": 1, "hex": f"0x{uint16_vals[0]:04X}", "desc": "SYNC_MARKER (0xDEAD)"},
                {"idx": 2, "hex": f"0x{uint16_vals[1]:04X}", "desc": f"LENGTH ({len(encrypted)}B)"},
            ]
            for i, v in enumerate(uint16_vals[2:6], start=3):
                preview.append({"idx": i, "hex": f"0x{v:04X}", "desc": f"CIPHERTEXT_CHUNK_{i-2}"})
        else:
            bits = bytes_to_bits(frame)
            fragment_count = len(bits) + 1
            preview = [
                {"idx": 1, "hex": "0xDEAD", "desc": "SYNC_LEAD_PACKET"},
                {"idx": 2, "hex": f"BIT_STREAM_{len(bits)}b", "desc": f"IPD_MODULATED ({len(bits)} bits)"},
            ]

        return jsonify({
            "success": True,
            "plaintext_length": len(message),
            "salt_hex": salt.hex().upper(),
            "nonce_hex": nonce.hex().upper(),
            "tag_hex": tag.hex().upper(),
            "encrypted_size_bytes": len(encrypted),
            "frame_size_bytes": len(frame),
            "frame_hex": frame.hex().upper(),
            "fragment_count": fragment_count,
            "mode": mode,
            "preview_fragments": preview,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/send", methods=["POST"])
def send_message():
    """Actually send the covert message over the network."""
    try:
        data = request.get_json(silent=True) or {}

        # Sanitise target IP (strip port/scheme if user pastes a URL)
        raw = data.get("target_ip", "127.0.0.1").strip()
        clean = raw.replace("http://", "").replace("https://", "").strip()
        target_ip = clean.split(":")[0].strip() or "127.0.0.1"

        passphrase = data.get("passphrase", "").strip()
        message = data.get("message", "")
        mode = data.get("mode", "header")
        timing_profile = (data.get("timing_profile") or "normal").strip().lower()
        delay_ms = float(data.get("delay_ms", 50.0))

        if not passphrase:
            return jsonify({"error": "Shared secret passphrase is required."}), 400
        if not message:
            return jsonify({"error": "Message cannot be empty."}), 400
        if timing_profile not in VALID_TIMING_PROFILES:
            return jsonify({"error": f"Invalid timing profile '{timing_profile}'."}), 400
        if timing_profile == "gmm":
            if not gmm_model or not gmm_model.is_trained():
                load_gmm_model()
            if not gmm_model or not gmm_model.is_trained():
                return jsonify({"error": "GMM model not trained. Run: python ml/train_model.py"}), 400

        if mode == "header":
            sender = HeaderChannelSender(target_ip)
            stats = sender.send_message(
                message, passphrase,
                packet_callback=broadcast,
                timing_profile=timing_profile,
                gmm_model=gmm_model if timing_profile == "gmm" else None,
                delay_ms=delay_ms,
            )
            return jsonify({"success": True, "stats": stats})

        elif mode == "temporal":
            bit_0_delay = float(data.get("bit_0_delay", 25)) / 1000.0
            bit_1_delay = float(data.get("bit_1_delay", 125)) / 1000.0
            sender = TemporalChannelSender(target_ip)
            stats = sender.send_message(
                message, passphrase,
                bit_0_delay=bit_0_delay,
                bit_1_delay=bit_1_delay,
                timing_profile=timing_profile,
                gmm_model=gmm_model if timing_profile == "gmm" else None,
                packet_callback=broadcast,
            )
            return jsonify({"success": True, "stats": stats})

        else:
            return jsonify({"error": f"Unknown mode: {mode}"}), 400

    except Exception as e:
        broadcast({"type": "tx_failed", "error": str(e), "timestamp": time.time()})
        return jsonify({"error": str(e)}), 500


@app.route("/gmm_status")
def gmm_status():
    if gmm_model and gmm_model.is_trained():
        stats = gmm_model.get_statistics()
        return jsonify({"available": True, "status": "Trained", "loaded": True, "statistics": stats})
    return jsonify({"available": False, "status": "Not Trained", "loaded": False})


@app.route("/stream")
def stream():
    """Server-Sent Events stream for live transmission visualisation."""
    def event_stream():
        client_q: queue.Queue = queue.Queue(maxsize=2000)
        with sse_lock:
            sse_subscribers.append(client_q)
        try:
            yield f"data: {json.dumps({'type': 'connection', 'status': 'connected'})}\n\n"
            while True:
                try:
                    evt = client_q.get(timeout=20)
                    yield f"data: {json.dumps(evt)}\n\n"
                except queue.Empty:
                    yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
        finally:
            with sse_lock:
                try:
                    sse_subscribers.remove(client_q)
                except ValueError:
                    pass

    return Response(event_stream(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── Minimal stubs so the full template doesn't 404 ───────────────────────────

@app.route("/api/overview")
def overview():
    return jsonify({
        "status": "READY", "active_channel": "None",
        "receiver_active": False, "last_rx_message": None,
        "total_packets_sent": 0, "total_packets_received": 0,
        "total_bytes_sent": 0, "total_bytes_received": 0,
        "stealth_score": 94.2,
        "gmm_available": gmm_model is not None,
        "experiments_count": 0,
        "pipeline": {k: "READY" for k in
                     ["sender", "encryption", "framing", "channel",
                      "icmp", "receiver", "reassembly", "decryption"]},
        "audit_log": [],
    })


@app.route("/api/receiver/state")
def receiver_state():
    # Sender node has no receiver — return safe empty state
    return jsonify({"success": True, "data": {
        "running": False, "channel": "None",
        "packets_received": 0, "icmp_packets": 0,
        "sync_detected": False, "frame_extracted": False,
        "decryption_success": False, "last_message": None,
        "last_error": None, "recent_packets": [], "status_history": [],
    }})


@app.route("/api/monitor/packets")
def monitor_packets():
    return jsonify({"packets": [], "total": 0, "running": False})


@app.route("/api/monitor/start", methods=["POST"])
@app.route("/api/monitor/stop", methods=["POST"])
def monitor_control():
    return jsonify({"success": True})


@app.route("/api/profiler/upload_pcap", methods=["POST"])
def profiler_upload():
    return jsonify({"error": "Traffic Profiler is available on the Receiver node."}), 501


@app.route("/api/profiler/preset", methods=["POST"])
@app.route("/api/profiler/train", methods=["POST"])
@app.route("/api/profiler/load", methods=["POST"])
def profiler_actions():
    return jsonify({"error": "Traffic Profiler is available on the Receiver node."}), 501


@app.route("/api/experiments", methods=["GET"])
def experiments_list():
    return jsonify({"experiments": []})


@app.route("/api/experiments", methods=["POST"])
def experiments_save():
    return jsonify({"success": True})


@app.route("/api/settings", methods=["GET"])
def settings_get():
    return jsonify({
        "theme": "dark", "default_target": "127.0.0.1",
        "default_channel": "header", "default_timing_profile": "normal",
    })


@app.route("/api/settings", methods=["POST"])
def settings_save():
    return jsonify({"success": True})


@app.route("/stop", methods=["POST"])
def stop_receiver():
    return jsonify({"success": True})


@app.route("/start", methods=["POST"])
def start_receiver():
    return jsonify({"error": "Start the Receiver node at http://127.0.0.1:5001"}), 400


# ── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    print("=" * 65)
    print("  NETGHOST – DEDICATED SENDER NODE")
    print("=" * 65)
    print(f"  • Sender URL   : http://127.0.0.1:{args.port}/sender")
    print(f"  • Receiver URL : http://127.0.0.1:5001/receiver")
    print("=" * 65)
    load_gmm_model()
    print("  [✓] Sender node online.")
    print("  NOTE: Run as Administrator for raw ICMP packet sending.")
    print("=" * 65)
    app.run(host="127.0.0.1", port=args.port, debug=False, threaded=True)
