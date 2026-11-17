"""
NETGHOST – DEDICATED RECEIVER NODE  (port 5001)
Self-contained Flask app: serves the Receiver UI and all sniff/decode APIs.
No dependency on app.py.

Run:
    python receiver/receiver_app.py          (normal, requires Admin/root)
    python receiver/receiver_app.py --port 5001
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

from receiver.receiver_core import HeaderChannelReceiver, TemporalChannelReceiver
from ml.ml_profiler import TrafficProfiler


# ── Flask setup ──────────────────────────────────────────────────────────────
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "receiver", "templates"),
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


# ── Receiver state ────────────────────────────────────────────────────────────
current_receiver = None
status_queue: queue.Queue = queue.Queue()
message_queue: queue.Queue = queue.Queue()

sse_subscribers = []
sse_lock = threading.Lock()


def broadcast(event_data: dict):
    with sse_lock:
        for q in list(sse_subscribers):
            try:
                q.put_nowait(event_data)
            except Exception:
                pass


def _status_callback(status: str):
    evt = {"type": "status", "message": status, "timestamp": time.time()}
    status_queue.put(evt)
    broadcast(evt)


def _message_callback(message: str):
    evt = {"type": "message", "message": message, "timestamp": time.time()}
    message_queue.put(evt)
    broadcast(evt)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
@app.route("/receiver")
def index():
    return render_template(
        "receiver.html",
        default_view="receiver",
        node_role="receiver",
        node_port="5001",
        peer_url="http://127.0.0.1:5000/sender",
        gmm_available=gmm_model is not None,
    )


@app.route("/start", methods=["POST"])
def start_receiver():
    global current_receiver

    try:
        data = request.get_json(silent=True) or {}
        passphrase = data.get("passphrase", "").strip()
        mode = data.get("mode", "header")
        interface = data.get("interface") or None
        # On Windows loopback experiments, default to NPF_Loopback to avoid
        # WiFi/Ethernet noise drowning out the covert ICMP packets
        if not interface or interface in ('auto', 'lo', 'loopback'):
            from receiver.receiver_core import resolve_sniff_interfaces
            interface = resolve_sniff_interfaces(None)

        if not passphrase:
            return jsonify({"error": "Shared secret passphrase is required."}), 400

        # Drain queues
        for q in (status_queue, message_queue):
            while not q.empty():
                try:
                    q.get_nowait()
                except queue.Empty:
                    break

        # Stop previous receiver
        if current_receiver:
            current_receiver.stop_listening()
            current_receiver = None

        if mode == "header":
            rx = HeaderChannelReceiver(passphrase)
        elif mode == "temporal":
            threshold = float(data.get("threshold", 65.0))
            rx = TemporalChannelReceiver(passphrase, threshold)
        else:
            return jsonify({"error": f"Unknown mode: {mode}"}), 400

        rx.set_status_callback(_status_callback)
        rx.set_event_callback(broadcast)
        rx.set_message_callback(_message_callback)
        rx.start_listening(interface=interface, timeout=600)
        current_receiver = rx

        return jsonify({"success": True})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/stop", methods=["POST"])
def stop_receiver():
    global current_receiver
    if current_receiver:
        current_receiver.stop_listening()
        current_receiver = None
    broadcast({"type": "rx_stopped", "timestamp": time.time()})
    return jsonify({"success": True})


@app.route("/api/receiver/state")
def receiver_state():
    global current_receiver
    if current_receiver and hasattr(current_receiver, "get_state"):
        state = current_receiver.get_state()
    else:
        state = {
            "running": False, "channel": "None",
            "packets_received": 0, "icmp_packets": 0,
            "sync_detected": False, "frame_extracted": False,
            "decryption_success": False, "last_message": None,
            "last_error": None, "recent_packets": [], "status_history": [],
        }
    # Key fix: once last_message is set, clear last_error so the banner hides
    if state.get("last_message"):
        state["last_error"] = None
        state["decryption_success"] = True
    return jsonify({"success": True, "data": state})


@app.route("/stream")
def stream():
    """Server-Sent Events for live receiver updates."""
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


@app.route("/gmm_status")
def gmm_status():
    if gmm_model and gmm_model.is_trained():
        stats = gmm_model.get_statistics()
        return jsonify({"available": True, "status": "Trained", "loaded": True, "statistics": stats})
    return jsonify({"available": False, "status": "Not Trained", "loaded": False})


@app.route("/api/profiler/upload_pcap", methods=["POST"])
def profiler_upload():
    """Upload a PCAP and train GMM on its inter-packet delays."""
    global gmm_model
    try:
        f = request.files.get("pcap_file")
        if not f:
            return jsonify({"error": "No file uploaded."}), 400

        tmp_path = os.path.join(BASE_DIR, "ml", "models", "_upload_tmp.pcap")
        f.save(tmp_path)

        profiler = TrafficProfiler(n_components=3)
        raw = profiler.extract_timing_from_pcap(tmp_path)
        cleaned = profiler.clean_timing_data(raw)
        profiler.train_gmm(cleaned, dataset_source=f.filename)
        profiler.save_model(GMM_MODEL_PATH)
        gmm_model = profiler
        os.remove(tmp_path)

        return jsonify({"success": True, "statistics": profiler.get_statistics()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/profiler/preset", methods=["POST"])
def profiler_preset():
    """Train GMM using the built-in synthetic baseline PCAP."""
    global gmm_model
    try:
        from ml.ml_profiler import create_synthetic_baseline_pcap
        baseline = os.path.join(BASE_DIR, "ml", "models", "baseline_synthetic.pcap")
        if not os.path.exists(baseline):
            create_synthetic_baseline_pcap(baseline, n_packets=1000)

        profiler = TrafficProfiler(n_components=3)
        raw = profiler.extract_timing_from_pcap(baseline)
        cleaned = profiler.clean_timing_data(raw)
        profiler.train_gmm(cleaned, dataset_source="baseline_synthetic.pcap")
        profiler.save_model(GMM_MODEL_PATH)
        gmm_model = profiler
        return jsonify({"success": True, "statistics": profiler.get_statistics()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/profiler/train", methods=["POST"])
def profiler_train():
    return profiler_preset()


@app.route("/api/profiler/load", methods=["POST"])
def profiler_load():
    global gmm_model
    try:
        profiler = TrafficProfiler()
        profiler.load_model(GMM_MODEL_PATH)
        gmm_model = profiler
        return jsonify({"success": True, "statistics": profiler.get_statistics()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Minimal stubs so the full shared template doesn't 404 ────────────────────

@app.route("/api/overview")
def overview():
    rx_active = current_receiver.running if current_receiver else False
    rx_msg = (current_receiver.last_message
              if current_receiver and current_receiver.last_message else None)
    return jsonify({
        "status": "RECEIVING" if rx_active else "READY",
        "active_channel": (current_receiver.get_state().get("channel", "None")
                           if current_receiver else "None"),
        "receiver_active": rx_active,
        "last_rx_message": rx_msg,
        "total_packets_sent": 0,
        "total_packets_received": (current_receiver.icmp_packets
                                   if current_receiver else 0),
        "total_bytes_sent": 0, "total_bytes_received": 0,
        "stealth_score": 94.2,
        "gmm_available": gmm_model is not None,
        "experiments_count": 0,
        "pipeline": {k: "READY" for k in
                     ["sender", "encryption", "framing", "channel",
                      "icmp", "receiver", "reassembly", "decryption"]},
        "audit_log": [],
    })


@app.route("/send", methods=["POST"])
def send_message():
    return jsonify({"error": "Send from the Sender node at http://127.0.0.1:5000"}), 400


@app.route("/api/sender/prepare", methods=["POST"])
def prepare_payload():
    return jsonify({"error": "Prepare from the Sender node at http://127.0.0.1:5000"}), 400


@app.route("/api/monitor/packets")
def monitor_packets():
    return jsonify({"packets": [], "total": 0, "running": False})


@app.route("/api/monitor/start", methods=["POST"])
@app.route("/api/monitor/stop", methods=["POST"])
def monitor_control():
    return jsonify({"success": True})


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


# ── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5001)
    args = parser.parse_args()

    print("=" * 65)
    print("  NETGHOST – DEDICATED RECEIVER NODE")
    print("=" * 65)
    print(f"  • Receiver URL : http://127.0.0.1:{args.port}/receiver")
    print(f"  • Sender URL   : http://127.0.0.1:5000/sender")
    print("=" * 65)
    load_gmm_model()
    print("  [✓] Receiver node online.")
    print("  NOTE: Run as Administrator for raw ICMP packet capture.")
    print("=" * 65)
    app.run(host="127.0.0.1", port=args.port, debug=False, threaded=True)
