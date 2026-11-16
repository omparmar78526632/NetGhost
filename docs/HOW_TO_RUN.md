# How to Run NetGhost — Complete Execution & Verification Guide

This guide covers environment setup, launching NetGhost in unified or dual-node mode, training/loading the GMM timing model, running both covert channels, inspecting traffic in Wireshark, running automated tests, and troubleshooting common issues.

---

## 1. Prerequisites

- **Operating System:** Windows 10/11 (or Linux/macOS)
- **Python:** Python 3.8+ (project virtual environment `.venv` included/recommended)
- **Packet Capture Driver:**
  - **Windows:** [Npcap](https://npcap.com/) installed with **Loopback adapter support** enabled (`Adapter for loopback traffic capture` / `\Device\NPF_Loopback`)
  - **Linux/macOS:** `libpcap` (`sudo apt-get install libpcap-dev` on Debian/Ubuntu)
- **Privileges:** **Administrator** (Windows) or **`sudo`/root** (Linux/macOS) is required for live raw ICMP packet injection and loopback sniffing. *(Non-elevated verification is supported via `pytest` and `scratch/e2e_pipeline_verify.py`.)*
- **Optional (for packet inspection):** [Wireshark](https://www.wireshark.org/)

---

## 2. Project Setup & Dependency Installation

From the project root (`d:\cnt\cnt_cp1\NetGhost`):

```powershell
# 1. Create virtual environment (if not already present)
python -m venv .venv

# 2. Activate virtual environment (Windows PowerShell / CMD)
.venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

Installed packages from `requirements.txt`: `flask`, `scapy`, `cryptography`, `numpy`, `scikit-learn`, `joblib`, `pytest`, `pytest-cov`.

---

## 3. Starting the Application

You can run NetGhost in **Unified Mode** (single dashboard on port `5000`) or **Dual-Node Mode** (isolated Sender on `:5000` and Receiver on `:5001`).

> **Important:** Open your terminal (`Command Prompt` or `PowerShell`) **as Administrator** for live ICMP capture and transmission.

### Option A: Unified Dashboard (Recommended for Single-Machine Lab)
```cmd
cd d:\cnt\cnt_cp1\NetGhost
.venv\Scripts\python.exe app.py
```
- Open in browser: `http://127.0.0.1:5000`
- Direct views: `http://127.0.0.1:5000/sender` and `http://127.0.0.1:5000/receiver`

### Option B: Dual-Node Isolated Launchers
**Terminal 1 (Admin) — Receiver (`http://127.0.0.1:5001`):**
```cmd
cd d:\cnt\cnt_cp1\NetGhost
.venv\Scripts\python.exe receiver\receiver_app.py
```

**Terminal 2 (Admin) — Sender (`http://127.0.0.1:5000`):**
```cmd
cd d:\cnt\cnt_cp1\NetGhost
.venv\Scripts\python.exe sender\sender_app.py
```

### Option C: Windows Batch Launchers
From an Administrator Command Prompt in the project root, you may also run:
- `start_netghost.bat` (unified dashboard)
- `start_dual_nodes.bat` (launches both Sender and Receiver nodes)

---

## 4. Training / Loading the GMM Timing Model

A pre-trained 3-component GMM model is already saved at `ml/models/gmm_timing.pkl`.

### Load in the Web UI (Traffic Profiler)
1. Open the **Traffic Profiler** screen in the left sidebar.
2. Click **Load Saved Model** (triggers `POST /api/profiler/load`).
3. Verify status reports **`Trained`** and displays component `means`, `variances`, and `weights` (`GET /gmm_status`).

### Retrain via CLI (`ml/train_model.py`)
```cmd
# Train on a synthetic 1000-packet baseline PCAP
.venv\Scripts\python.exe ml\train_model.py --create-synthetic --synthetic-packets 1000 --components 3 --output ml\models\gmm_timing.pkl

# Or train from your own captured PCAP file
.venv\Scripts\python.exe ml\train_model.py --pcap path\to\capture.pcap --components 3 --output ml\models\gmm_timing.pkl
```

---

## 5. Running IP-ID Header Embedding Mode

**Best for:** Fast transmission of short to medium messages (`16 bits` per packet).

1. **Receiver View (`/receiver` or `http://127.0.0.1:5001`):**
   - **Pre-Shared Key (PSK):** Enter e.g. `netghost2026`
   - **Capture Duration:** `30` seconds (default)
   - Click **Start Listening** (`POST /start`).
2. **Sender View (`/sender` or `http://127.0.0.1:5000`):**
   - **Target IP:** `127.0.0.1`
   - **Pre-Shared Key (PSK):** `netghost2026` *(must match Receiver)*
   - **Transmission Mode:** Select **`IP-ID Header Embedding`** *(note: the Timing Profile selector is intentionally hidden in this mode)*
   - **Message:** e.g. `Hello from NetGhost`
   - Click **Send Message** (`POST /send`).
3. **Verify Result:**
   - Receiver captures packets, detects `IP.id = 0xDEAD` at `ICMP.seq = 0`, reassembles the frame, verifies the AES-256-GCM tag, and displays the decoded plaintext.

---

## 6. Running Temporal IPD Channel Mode

**Best for:** Maximum stealth demonstration (`1 bit` per packet via inter-packet delay).

1. **Receiver View:**
   - **Pre-Shared Key (PSK):** `netghost2026`
   - **Timing Threshold:** `75` ms (default: `< 75 ms` = bit `0`, `>= 75 ms` = bit `1`)
   - **Capture Duration:** Set to **`120`** or **`300`** seconds (a 5-byte message = ~425 packets takes ~40–60+ seconds).
   - Click **Start Listening**.
2. **Sender View:**
   - **Target IP:** `127.0.0.1`
   - **Pre-Shared Key (PSK):** `netghost2026`
   - **Transmission Mode:** Select **`Temporal IPD`** *(the Timing Profile dropdown now appears)*
   - **Timing Profile:** Choose one of:
     - `Constant Delay` (`25 ms` / `125 ms`)
     - `Normal / Variable Load` (Gaussian jitter)
     - `Gamma Distribution` (queue delay model)
     - `GMM Fitted Distribution` (requires loaded `gmm_timing.pkl`)
   - **Message:** Keep short for live demos (e.g. `Hi` or `OM`).
   - Click **Send Message**.

---

## 7. Using Traffic Profiler, Packet Monitor, Experiments & Results

- **Traffic Profiler:** Upload a `.pcap`/`.pcapng` (`POST /api/profiler/upload_pcap`), generate synthetic baseline traffic (`POST /api/profiler/preset`), train a 3-component GMM (`POST /api/profiler/train`), or load `ml/models/gmm_timing.pkl` (`POST /api/profiler/load`).
- **Packet Monitor:** Start/stop live ICMP inspection (`POST /api/monitor/start`, `POST /api/monitor/stop`), clear buffer, or export captured packets as PCAP (`GET /api/monitor/export_pcap`).
- **Experiments & Results:** Create experiment records (`POST /api/experiments/create`), run them (`POST /api/experiments/<id>/run`), and review/export measured sender-side packet count, duration, throughput, message size, and packet interval (`GET /api/results/export_report`). Receiver delivery, loss, and payload authentication are not measured by this report.

---

## 8. Wireshark Packet-Level Verification

1. Open **Wireshark** (as Administrator if needed).
2. Select interface: **`Adapter for loopback traffic capture`** (Windows) or **`lo`** (Linux).
3. Apply display filter:
   ```text
   icmp.type == 8
   ```
4. **For IP-ID Header Mode:**
   - Expand **Internet Protocol Version 4** in Packet #1 (`seq=0`).
   - Verify **Identification** shows **`0xdead`** (sync marker).
   - Packet #2 (`seq=1`) shows the 16-bit payload length in hex.
   - Subsequent packets carry encrypted chunks in `Identification`.
5. **For Temporal IPD Mode:**
   - Enable **View → Time Display Format → Seconds Since Previous Displayed Packet**.
   - Inspect the **Time** column between consecutive `icmp.type == 8` packets to observe short (`~0.025 s`, bit `0`) and long (`~0.125 s`, bit `1`) delays.

---

## 9. Running Automated Tests (`pytest`)

Run the full 65-test suite without needing Administrator privileges:

```cmd
cd d:\cnt\cnt_cp1\NetGhost
.venv\Scripts\python.exe -m pytest -v
```

Run with coverage:
```cmd
.venv\Scripts\python.exe -m pytest --cov=common --cov=sender --cov=receiver --cov=ml
```

Run a single test file (for example, timing & GMM integration):
```cmd
.venv\Scripts\python.exe -m pytest tests\test_timing_and_gmm.py -v
```

---

## 10. Running Non-Admin End-to-End Verification

If you are in a non-elevated shell where Npcap loopback sniffing is restricted, run the in-process E2E verification script:

```cmd
cd d:\cnt\cnt_cp1\NetGhost
.venv\Scripts\python.exe scratch\e2e_pipeline_verify.py
```

This verifies encryption, `0xDEAD` framing, channel encoding/decoding, GMM timing bounds, and AES-256-GCM decryption end-to-end.

---

## 11. Verifying Security Failure Cases

1. **Wrong PSK Test:** Set Sender PSK to `passA` and Receiver PSK to `passB`. Receiver will capture all packets and display **`AUTHENTICATION FAILED: Decryption failed`** with zero plaintext leakage.
2. **Early Stop / Incomplete Capture:** Stop the Receiver before all packets arrive. Reassembly pauses below `100%` and never outputs partial/corrupted plaintext.

---

## 12. Common Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| **`Error opening adapter` / No packets captured** | Terminal not running as Administrator, or Npcap loopback missing | Restart terminal **As Administrator**; ensure Npcap is installed with Loopback support |
| **`AUTHENTICATION FAILED: Decryption failed`** | Mismatched PSK, packet drop, or duplicate/out-of-order corruption | Verify identical PSK on Sender and Receiver; ensure Receiver started *before* Sender |
| **`Awaiting 0xDEAD sync marker`** | Sender not started, wrong Target IP, or Temporal Receiver used while Sender is in Header mode | Match Target IP (`127.0.0.1`) and verify both sides are using the intended channel mode |
| **Temporal mode stops before finishing** | Receiver `Capture Duration` expired mid-transmission | Increase Receiver Capture Duration to `120`–`300` seconds before clicking **Start Listening** |
| **`GMM model not loaded`** | `gmm_timing.pkl` not loaded into active session | Click **Load Saved Model** in Traffic Profiler or run `ml\train_model.py --create-synthetic` |

---

## 13. Clean Shutdown

1. Click **Stop Listening** in the Receiver UI if a capture is active.
2. Press **`Ctrl+C`** in the terminal(s) running `app.py`, `sender_app.py`, or `receiver_app.py`.
3. Stop any active Wireshark capture.
