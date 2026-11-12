# NetGhost — Master Technical Project Documentation

**Project Title:** NetGhost: Covert Data Communication Using Network Steganography and Traffic Modulation  
**Domain:** Network Security, Network Steganography, Applied Cryptography, Machine Learning  
**Protocol Stack:** IPv4, ICMP Echo Request (Type 8), AES-256-GCM, PBKDF2-HMAC-SHA256, Scapy, Flask  
**Team Members:** Om Parmar (OM), Kedar N., Kedar P., Atharva (Arthava)

---

## 1. Project Title & Overview

**NetGhost** is a laboratory-grade network steganography system that demonstrates covert, encrypted data transmission over standard IPv4/ICMP ("ping") traffic. Rather than relying solely on conventional encryption—which protects message content while leaving observable communication metadata—NetGhost embeds encrypted payloads inside legitimate network protocol behavior using two distinct covert channels:

1. **IP-ID Header Embedding (Storage Steganography):** Encodes 16-bit payload chunks directly into the IPv4 `Identification` (`IP.id`) header field of ICMP Echo Request packets.
2. **Temporal IPD Channel (Timing Steganography):** Encodes binary bits (`0` and `1`) in the **Inter-Packet Delay (IPD, $\Delta t$)** between consecutive ICMP Echo Request packets without altering packet headers or payloads.

Both channels share a unified cryptographic and framing pipeline (**PBKDF2-HMAC-SHA256** + **AES-256-GCM** + `0xDEAD` binary framing) and are operated through a unified Flask web dashboard (`app.py`) with real-time Server-Sent Events (SSE) visualization, an integrated Gaussian Mixture Model (GMM) traffic profiler, live packet monitoring, and automated experiment benchmarking.

---

## 2. Abstract

Conventional secure transport protocols (such as TLS/HTTPS and IPsec VPNs) ensure confidentiality and integrity, but their presence is immediately visible to Deep Packet Inspection (DPI) firewalls, Security Information and Event Management (SIEM) systems, and traffic-analysis monitors. NetGhost addresses this limitation by combining **authenticated encryption** with **network steganography**. Plaintext messages are first encrypted using **AES-256-GCM** with a 256-bit key derived from a Pre-Shared Key (PSK) via **PBKDF2-HMAC-SHA256** (100,000 iterations, 16-byte random salt) and a 12-byte random nonce. The resulting binary bundle (`salt || nonce || ciphertext || 16-byte tag`) is wrapped in a synchronization frame (`0xDEAD` sync marker + 2-byte big-endian length prefix) and transmitted over ICMP Echo Request packets via either 16-bit `IP.id` header embedding or 1-bit-per-packet Inter-Packet Delay modulation. To resist statistical timing analysis in temporal mode, NetGhost supports four timing profiles—**Constant Delay**, **Normal / Variable Load**, **Gamma Distribution**, and a **3-component Gaussian Mixture Model (GMM)** trained via Expectation-Maximization (EM) on baseline PCAP inter-packet delays.

---

## 3. Problem Statement

Modern perimeter defenses, DPI appliances, and network anomaly detectors inspect both packet payloads and communication metadata:
- **Encrypted payloads look anomalous:** Standard encrypted tunnels are easy to fingerprint, throttle, or block in restricted networks.
- **Naive covert channels lack confidentiality or integrity:** Raw steganographic schemes without authenticated encryption leak data if discovered and fail silently under packet loss, reordering, or tampering.
- **Naive timing channels are statistically detectable:** Fixed-delay timing channels (`bit 0 = 25 ms`, `bit 1 = 125 ms`) produce sharp bimodal spikes in inter-arrival histograms that statistical Intrusion Detection Systems (IDS) can flag.

NetGhost solves all three challenges in an educational and verifiable laboratory platform:
1. It uses **ICMP Echo Requests (Type 8)**—a ubiquitous diagnostic protocol—as the covert carrier.
2. It enforces **AES-256-GCM AEAD** so unauthorized observers cannot read payloads and any dropped, reordered, or tampered packet triggers an `InvalidTag` authentication failure rather than silent corruption.
3. It integrates **Gamma queue modeling** and **EM-trained GMM timing synthesis** to shape covert packet intervals after realistic network traffic.

---

## 4. Objectives

- Implement a modular, verifiable **end-to-end covert communication pipeline** in Python.
- Provide **confidentiality, integrity, and authenticity** via PBKDF2-HMAC-SHA256 and AES-256-GCM.
- Implement **two complementary covert channels** over IPv4/ICMP:
  - High-throughput **IP-ID Header Embedding** (16 bits/packet).
  - Stealth-oriented **Temporal IPD Modulation** (1 bit/packet).
- Integrate **four timing profiles** (`constant`, `normal`, `gamma`, `gmm`), including a scikit-learn **3-component GMM** trained on PCAP inter-packet delays.
- Provide an interactive **Flask + SSE web laboratory** (`app.py`) with separate Sender and Receiver views, Traffic Profiler, Packet Monitor, Experiments runner, and Results export.
- Verify correctness through **65 automated pytest unit/integration tests**, an end-to-end pipeline verification script, and **Wireshark** packet-level inspection.

---

## 5. System Architecture

NetGhost is organized into clean, decoupled layers across `common/`, `sender/`, `receiver/`, `ml/`, `templates/`, `static/`, and `tests/`.

```
+-----------------------------------------------------------------------------+
|                        WEB UI & REST / SSE LAYER                            |
|  app.py (Flask, Port 5000 unified | sender_app.py :5000 | receiver_app :5001)|
|  templates/index.html + static/js/netghost.js + static/css/netghost.css     |
+--------------------------------------+--------------------------------------+
                                       |
          +----------------------------+----------------------------+
          |                                                         |
          v                                                         v
+-----------------------------+                       +-----------------------------+
|       SENDER PIPELINE       |                       |      RECEIVER PIPELINE      |
|  sender/sender_core.py      |                       |  receiver/receiver_core.py  |
|  - HeaderChannelSender      |                       |  - HeaderChannelReceiver    |
|  - TemporalChannelSender    |                       |  - TemporalChannelReceiver  |
+--------------+--------------+                       +--------------+--------------+
               |                                                     ^
               v                                                     |
+-----------------------------+                       +-----------------------------+
|    COMMON CRYPTO & FRAME    |                       |   SCAPY / NPCAP / LIBPCAP   |
|  common/crypto.py (AES-GCM) |                       |   ICMP Type 8 Sniffing &    |
|  common/framing.py (0xDEAD) |                       |   Loopback Deduplication    |
|  common/timing.py (Profiles)|                       +-----------------------------+
|  common/utils.py (Bit/Word) |
+--------------+--------------+
               |
               v
+-----------------------------+
|   ML TRAFFIC PROFILER       |
|  ml/ml_profiler.py          |
|  ml/train_model.py          |
|  ml/models/gmm_timing.pkl   |
+-----------------------------+
```

### Runtime Modes
1. **Unified Mode (`python app.py`):** Runs a single Flask server on `http://127.0.0.1:5000` exposing all 9 workspace views (`Overview`, `Sender`, `Receiver`, `Traffic Profiler`, `Packet Monitor`, `Experiments`, `Results`, `Documentation`, `Settings`).
2. **Dual-Node Mode (`sender/sender_app.py` and `receiver/receiver_app.py`):** Launches two isolated Flask processes using `NETGHOST_MODE=sender` (port `5000`) and `NETGHOST_MODE=receiver` (port `5001`).

---

## 6. Repository Structure

```text
NetGhost/
├── app.py                          # Unified Flask server, REST APIs, SSE /stream, Experiments & Monitor
├── config.py                       # Global constants (IP, ports, GMM path, SYNC_MARKER = 0xDEAD)
├── requirements.txt                # Python dependencies
├── common/
│   ├── __init__.py
│   ├── crypto.py                   # PBKDF2-HMAC-SHA256 + AES-256-GCM encryption/decryption
│   ├── framing.py                  # Binary frame creation/parsing (0xDEAD + 2B length)
│   ├── timing.py                   # Timing profiles: Constant, Normal, Gamma, GMM + factory
│   └── utils.py                    # Byte/bit/uint16 conversions & hex formatting
├── sender/
│   ├── __init__.py
│   ├── sender_core.py              # HeaderChannelSender & TemporalChannelSender (Scapy raw ICMP)
│   └── sender_app.py               # Standalone Sender launcher (NETGHOST_MODE=sender, port 5000)
├── receiver/
│   ├── __init__.py
│   ├── receiver_core.py            # HeaderChannelReceiver & TemporalChannelReceiver + sniffer
│   └── receiver_app.py             # Standalone Receiver launcher (NETGHOST_MODE=receiver, port 5001)
├── ml/
│   ├── __init__.py
│   ├── ml_profiler.py              # TrafficProfiler (PCAP parser, EM GMM training, sampling, joblib)
│   ├── train_model.py              # CLI tool to train GMM on real or synthetic PCAPs
│   └── models/
│       └── gmm_timing.pkl          # Pre-trained 3-component GMM artifact
├── templates/
│   └── index.html                  # Single-page Cybernetic Lab UI (9 sidebar screens)
├── static/
│   ├── css/netghost.css            # Lab UI styling & theme
│   └── js/netghost.js              # Client-side controller, SSE listener, live flow visualizers
├── tests/
│   ├── test_crypto.py              # AES-GCM, PBKDF2, wrong PSK, tamper tests
│   ├── test_framing.py             # 0xDEAD framing, boundary, garbage tolerance tests
│   ├── test_header_channel.py      # uint16 chunking & header channel round-trip tests
│   ├── test_temporal_channel.py    # Bitstream conversion & temporal threshold tests
│   ├── test_ml.py                  # TrafficProfiler cleaning, GMM training, save/load tests
│   ├── test_live_flow_events.py    # SSE event callback & pipeline integration tests
│   └── test_timing_and_gmm.py      # Timing profile bounds, GMM integration & API tests
├── docs/
│   ├── PROJECT_DOCUMENTATION.md    # Master technical documentation (this file)
│   ├── WORK_DISTRIBUTION.md        # Team role & module contribution breakdown
│   └── HOW_TO_RUN.md               # Step-by-step setup, execution, Wireshark & troubleshooting guide
└── start_*.bat                     # Windows Admin batch launchers
```

---

## 7. End-to-End Data Flow

Every covert transmission follows a deterministic 10-step runtime pipeline:

```text
User Plaintext Message + PSK
  │
  ▼ (1) Key Derivation & Encryption — common/crypto.py
  │     16B random Salt + PSK ──► PBKDF2-HMAC-SHA256 (100,000 iters) ──► 32B AES Key
  │     Plaintext + 12B random Nonce + Key ──► AES-256-GCM ──► Ciphertext + 16B Tag
  │     Payload = Salt (16B) || Nonce (12B) || Ciphertext (N B) || Tag (16B)
  │
  ▼ (2) Framing — common/framing.py
  │     Frame = 0xDEAD (2B) || uint16_be(len(Payload)) (2B) || Payload
  │
  ▼ (3) Encoding & Timing — sender/sender_core.py + common/timing.py
  │     ├── Header Mode:   Pad odd byte with 0x00 ─► 16-bit chunks ─► IP(id=chunk)/ICMP(seq=i)
  │     └── Temporal Mode: Convert Frame to MSB-first bits ─► Lead ICMP(seq=0) + 1 pkt/bit after Δt
  │
  ▼ (4) Raw ICMP Transmission — Scapy send(pkt, verbose=0)
  │
  ▼ (5) Receiver Capture — receiver/receiver_core.py (Scapy AsyncSniffer, filter="icmp")
  │     Loopback deduplication (<3 ms identical (ip_id, seq) guard & (seq, ip_id) tracking)
  │
  ▼ (6) Extraction / Demodulation
  │     ├── Header Mode:   Extract IP.id per ICMP.seq, reset on (0xDEAD, seq=0), sort by seq
  │     └── Temporal Mode: Measure Δt between packets ─► < 75 ms = bit 0, >= 75 ms = bit 1
  │
  ▼ (7) Frame Reconstruction — common/framing.py (find 0xDEAD, validate length)
  │
  ▼ (8) Authenticated Decryption — common/crypto.py (verify 16B GCM Tag)
  │
  ▼ (9) Result Delivery — Plaintext displayed or AUTHENTICATION FAILED raised
```

---

## 8. Cryptographic Design (`common/crypto.py`)

NetGhost uses **AES-256-GCM** (Galois/Counter Mode), an Authenticated Encryption with Associated Data (AEAD) cipher, paired with **PBKDF2-HMAC-SHA256**.

### Parameters
| Parameter | Constant / Value | Purpose |
| :--- | :--- | :--- |
| **Cipher** | `AESGCM` (256-bit key) | Confidentiality + built-in 128-bit integrity tag |
| **Key Derivation** | `PBKDF2HMAC(SHA256)` | Derives 32-byte key from UTF-8 passphrase |
| **Iterations** | `PBKDF2_ITERATIONS = 100,000` | Slows offline brute-force / dictionary attacks |
| **Salt Size** | `SALT_SIZE = 16` bytes | Random per encryption; defeats rainbow tables |
| **Nonce Size** | `GCM_NONCE_SIZE = 12` bytes | Random 96-bit IV per encryption; ensures semantic security |
| **Auth Tag Size** | 16 bytes (appended by `AESGCM`) | Detects any bit flip, packet drop, or wrong PSK (`InvalidTag`) |
| **Total Overhead** | `16 + 12 + 16 = 44` bytes | Added to plaintext length |

### Wire Layout of Encrypted Payload
```text
+----------------+----------------+----------------------+----------------+
|  Salt (16 B)   |  Nonce (12 B)  |   Ciphertext (N B)   | Auth Tag (16 B)|
+----------------+----------------+----------------------+----------------+
Bytes 0..15        16..27           28..(28+N-1)           Last 16 bytes
```

### Why AES-256-GCM?
- **No block padding overhead:** Operates as a stream cipher (CTR + GHASH), so an $N$-byte plaintext yields an $N$-byte ciphertext.
- **Fail-closed integrity:** If a single packet is dropped, duplicated out of order, or altered in transit—or if the receiver enters a mismatched PSK—`decrypt_message()` raises an authentication error and never leaks corrupted plaintext.

---

## 9. Framing Protocol (`common/framing.py`)

Because raw network sniffers can capture background ICMP packets before or after a covert session, NetGhost wraps every encrypted payload in an explicit binary frame:

```text
+----------------------+----------------------+----------------------------------+
|  Sync Marker (2 B)   | Payload Length (2 B) |      Encrypted Payload (N B)     |
|       0xDEAD         |   Big-endian uint16  |   Salt + Nonce + Cipher + Tag    |
+----------------------+----------------------+----------------------------------+
```

- **`SYNC_MARKER = 0xDEAD`**: 2-byte big-endian magic header (`b'\xde\xad'`).
- **`HEADER_SIZE = 4`** bytes (`>HH` struct format).
- **`MAX_PAYLOAD_SIZE = 65535`** bytes.
- **`create_frame(payload)`**: Validates length $\le 65535$ and prepends `0xDEAD` + 2-byte length.
- **`parse_frame(data)`** & **`find_sync_marker(data)`**: Scans the reassembled byte stream for `0xDEAD`, reads the 2-byte length, and extracts the exact payload once `len(data) >= sync_idx + 4 + length`.

---

## 10. Utility Conversions (`common/utils.py`)

`common/utils.py` provides deterministic big-endian conversions used by both channels:
- **`bytes_to_uint16_list(data)`**: Pads odd-length byte strings with a trailing `0x00` byte and unpacks pairs into big-endian `uint16` integers for `IP.id`.
- **`uint16_list_to_bytes(values)`**: Packs a sequence of `uint16` integers back into raw bytes.
- **`bytes_to_bits(data)`**: Converts each byte to 8 bits in **MSB-first** order (`(byte >> (7 - i)) & 1`).
- **`bits_to_bytes(bits)`**: Pads trailing bits to a multiple of 8 and reconstructs bytes.
- **`format_bytes_hex(data)`**: Produces readable hex previews for logging and UI telemetry.

---

## 11. Covert Channel 1: IP-ID Header Embedding

**Classes:** `HeaderChannelSender` (`sender/sender_core.py`), `HeaderChannelReceiver` (`receiver/receiver_core.py`)

### Encoding & Transmission
1. Encrypts plaintext with AES-256-GCM and creates the `0xDEAD` frame.
2. Converts the frame into 16-bit `uint16` chunks via `bytes_to_uint16_list()` (trailing `0x00` pad if odd length; the 2-byte `LENGTH` header in the frame ensures the parser reads only the exact encrypted payload bytes and ignores the trailing pad).
3. For each chunk index `i` (`0, 1, ..., K-1`), crafts and sends:
   ```python
   IP(dst=self.target_ip, id=chunk) / ICMP(type=8, seq=i)
   ```
4. Uses an internal timing profile (default `normal`) via `create_timing_profile()` to pace consecutive packets naturally.
5. Logs diagnostic metadata before sending: `frame_len`, `frame_hash` (SHA-256), `nonce`, and chunk count (never logging secrets).

### Reception & Reassembly
- Sniffs ICMP packets (`filter="icmp"`) on resolved interfaces (`resolve_sniff_interfaces()`, automatically selecting `\Device\NPF_Loopback` on Windows when sniffing `127.0.0.1`).
- **Loopback Deduplication:** Suppresses kernel/Npcap loopback echoes only when `(ip_id, icmp_seq)` matches the previous packet within `< 3 ms`, and ignores duplicate `(icmp_seq, ip_id)` pairs.
- **Session Reset:** When `ip_id == 0xDEAD` and `icmp_seq == 0` arrives, resets the chunk buffer for the new transmission.
- **Ordered Reassembly:** Reconstructs the byte stream sorted by `ICMP.seq` (`0..max_seq`), parses the `0xDEAD` frame, and decrypts with AES-256-GCM.
- **Capacity:** **16 bits (2 bytes) per packet**, completing typical short messages in under 1 second.

---

## 12. Covert Channel 2: Temporal IPD Channel

**Classes:** `TemporalChannelSender` (`sender/sender_core.py`), `TemporalChannelReceiver` (`receiver/receiver_core.py`)

### Encoding & Transmission
1. Encrypts plaintext, builds the `0xDEAD` frame, and converts it to an MSB-first bit array (`N = len(frame) * 8` bits).
2. Sends a **lead synchronization packet** (`IP(dst=target_ip) / ICMP(type=8, seq=0)`) at $t = 0$.
3. For each bit $b_i \in \{0, 1\}$ (`seq = 1..N`), queries `profile.next_delay_s(bit=bit)`, sleeps for $\Delta t$, and sends `IP(dst=target_ip) / ICMP(type=8, seq=i+1)`.
4. On Windows, `timeBeginPeriod(1)` (`winmm.dll`) is enabled during transmission so `time.sleep()` achieves 1 ms timer resolution.

### Reception & Threshold Demodulation
- Records arrival timestamps of incoming ICMP Echo Requests.
- Computes inter-packet delay $\Delta t_{\text{ms}} = (t_k - t_{k-1}) \times 1000$.
- Classifies each interval against **`threshold_ms = 75.0 ms`**:
  - $\Delta t < 75.0\text{ ms} \implies \text{Bit } 0$
  - $\Delta t \ge 75.0\text{ ms} \implies \text{Bit } 1$
- Converts accumulated bits to bytes, searches for `0xDEAD` + length, and verifies/decrypts via AES-256-GCM.
- **Capacity:** **1 bit per packet** (payload headers remain completely unmodified).

---

## 13. Timing Profiles & Mathematical Models (`common/timing.py`)

`common/timing.py` defines four selectable timing profiles (`VALID_TIMING_PROFILES = ("normal", "constant", "gamma", "gmm")`) instantiated via `create_timing_profile(...)`:

| Profile Key | UI Label | Class | Default Parameters | Statistical Behavior |
| :--- | :--- | :--- | :--- | :--- |
| `constant` | **Constant Delay** | `ConstantTimingProfile` | `delay_ms=50.0`, `bit_0_ms=25.0`, `bit_1_ms=125.0` | Fixed deterministic interval. Zero jitter; easiest to decode, but produces two sharp spikes on IDS histograms. |
| `normal` | **Normal / Variable Load** | `NormalVariableTimingProfile` | `mean_ms=35.0`, `std_ms=12.0`, `min_ms=10.0`, `max_ms=150.0`, `bit_0_ms=25.0`, `bit_1_ms=125.0`, `bit_std_ms=4.0` | Adds Gaussian jitter $\mathcal{N}(\mu, \sigma^2)$ clamped to bounds. Simulates natural measurement noise. |
| `gamma` | **Gamma Distribution** | `GammaTimingProfile` | `mean_ms=35.0`, `shape=2.0`, `min_ms=10.0`, `max_ms=200.0`, `bit_0_ms=25.0`, `bit_1_ms=125.0` | Samples $\text{Gamma}(k=2.0, \theta=\mu/2.0)$ clamped to bounds. Models right-skewed router queue delays. |
| `gmm` | **GMM Fitted Distribution** | `GMMTimingProfile` | `min_ms=5.0`, `max_ms=500.0`, `threshold_ms=75.0` | Samples from a trained 3-component `TrafficProfiler` GMM (`weights_`, `means_`, `covariances_`). |

### UI Visibility Rule
In the Sender UI (`templates/index.html` + `static/js/netghost.js`), the `#timingProfileGroup` selector is **hidden (`display: none`)** when `IP-ID Header Embedding` is selected and **visible (`display: block`)** only when `Temporal IPD` is selected.

---

## 14. Gaussian Mixture Model (GMM) Traffic Profiler (`ml/ml_profiler.py`, `ml/train_model.py`)

NetGhost's Traffic Profiler learns multimodal inter-packet delay distributions from network captures so covert timing traffic statistically resembles ambient background traffic.

### Training Pipeline
1. **PCAP Extraction (`extract_timing_from_pcap`):** Reads packets via Scapy `rdpcap()`, computes consecutive timestamp differences in milliseconds ($\Delta t_{\text{ms}}$).
2. **Data Cleaning (`clean_timing_data`):** Removes NaN/Inf values and filters intervals outside `[0.1, 1000.0] ms`. Requires at least 10 valid samples.
3. **EM Fitting (`train_gmm`):** Fits `sklearn.mixture.GaussianMixture(n_components=3, covariance_type='full', max_iter=200, reg_covar=1e-4)` on the 1D millisecond array.
4. **Computed Statistics (`_compute_statistics`):** Stores `n_samples`, `n_components`, `means`, `variances`, `weights`, `converged`, `n_iter`, `log_likelihood`, `aic`, `bic`, `min_bound_ms` (`5.0`), `max_bound_ms` (`500.0`), `dataset_source`, and `trained_at`.
5. **Persistence (`save_model` / `load_model`):** Serializes the fitted profiler to `ml/models/gmm_timing.pkl` via `joblib`.
6. **Sampling (`sample_next_delay_s` / `sample_bit_delay`):** Draws independent samples from the fitted Gaussian components (respecting component weights) clamped to `[5.0, 500.0] ms`. For bit-conditioned temporal transmission, `GMMTimingProfile` samples from the fast (`< threshold_ms`) or slow (`>= threshold_ms`) regimes of the GMM.

### Pre-Trained Baseline Model
The repository ships with `ml/models/gmm_timing.pkl` (3 components), which can be loaded in the UI or via `POST /api/profiler/load` and inspected via `GET /gmm_status`.

---

## 15. Research Paper Alignment & Differences

NetGhost's timing and statistical evasion design is grounded in peer-reviewed covert channel literature (also cited in `README.md` and code docstrings):

1. **Gianvecchio, S., Wang, H., Wijesekera, D., & Jajodia, S. (2008).** *"Model-Based Covert Timing Channels: Automated Modeling and Evasion."* RAID 2008, LNCS 5230, pp. 211–230.
   - **Aligned:** Uses an EM-fitted multi-component GMM over empirical inter-packet delays, evaluates Log-Likelihood, AIC, and BIC, and generates bounded synthetic delays.
   - **Explicit Implementation Difference:** NetGhost uses a 1D GMM with independent bounded component sampling (`[5.0, 500.0] ms`) rather than a full inverse-CDF transform or Markov renewal chain.
2. **Cabuk, S., Brodley, C. E., & Shields, C. (2004).** *"IP Covert Timing Channels: Design and Detection."* ACM CCS 2004.
   - Motivates the baseline binary IPD threshold channel and the need to move beyond rigid constant delays.
3. **Additional Standards & References:** NIST SP 800-38D (AES-GCM), RFC 8018 / PKCS #5 (PBKDF2), Wendzel et al. (2014), Zander et al. (2007).

---

## 16. Web Application & API Endpoints (`app.py`)

`app.py` serves both the single-page Cybernetic Lab UI and the JSON/SSE API:

### UI & Page Routes
- `GET /` — Main dashboard (Overview in unified mode, or locked to Sender/Receiver in dual-node mode)
- `GET /sender` — Sender view
- `GET /receiver` — Receiver view

### Core Covert Channel APIs
- `GET /api/overview` — System status, active mode, GMM state, recent logs
- `POST /api/sender/prepare` — Pre-computes encryption/frame metadata preview
- `POST /send` — Starts covert transmission (`target_ip`, `psk`, `message`, `mode`, `timing_profile`, etc.)
- `POST /start` — Starts background Scapy receiver (`psk`, `mode`, `duration`, `threshold_ms`)
- `POST /stop` — Stops active receiver
- `GET /api/receiver/state` — Returns current receiver buffer, progress, and decoded plaintext
- `GET /stream` — Server-Sent Events (SSE) stream pushing live packet, timing, and status events

### Traffic Profiler (GMM) APIs
- `GET /gmm_status` — Returns GMM training/load state and component statistics (`means`, `variances`, `weights`, `aic`, `bic`)
- `POST /api/profiler/load` — Loads `ml/models/gmm_timing.pkl`
- `POST /api/profiler/upload_pcap` — Uploads a `.pcap`/`.pcapng` file for profiling
- `POST /api/profiler/preset` — Generates synthetic baseline traffic data
- `POST /api/profiler/train` — Trains a 3-component GMM on the loaded dataset

### Monitor, Experiments, Results & Settings APIs
- `POST /api/monitor/start`, `POST /api/monitor/stop`, `GET /api/monitor/packets`, `POST /api/monitor/clear`, `GET /api/monitor/export_pcap`
- `GET /api/experiments/list`, `POST /api/experiments/create`, `POST /api/experiments/<id>/run`, `GET /api/experiments/<id>/view`, `DELETE /api/experiments/<id>/delete`, `POST /api/experiments/clear`
- `GET /api/results/data`, `GET /api/results/export_report`
- `GET/POST /api/settings`, `POST /api/settings/reset`

---

## 17. UI Modules & Visualization

The frontend (`templates/index.html`, `static/js/netghost.js`, `static/css/netghost.css`) provides 9 sidebar screens:
1. **Overview:** System health, active channel summary, quick metrics.
2. **Sender:** Target IP, PSK, plaintext input, Transmission Mode (`IP-ID Header Embedding` / `Temporal IPD`), conditional Timing Profile selector (shown only in `Temporal IPD` mode), and **Live Transmission Flow** visualizer (5-stage pipeline + IP-ID packet card conveyor + live stopwatch).
3. **Receiver:** PSK, capture duration, threshold (`75 ms`), Start/Stop controls, **Live Reception Flow** visualizer (7-stage pipeline, temporal bit timeline, reassembly progress, and typewriter plaintext terminal).
4. **Traffic Profiler:** Load pre-trained GMM, upload PCAP, generate synthetic baseline, train GMM, and inspect component means/variances/weights.
5. **Packet Monitor:** Live ICMP packet table with capture start/stop/clear and PCAP export.
6. **Experiments:** Create, run, inspect, and compare repeatable covert channel test runs.
7. **Results:** Aggregated metrics and downloadable report export.
8. **Documentation:** Built-in reference panel.
9. **Settings:** Runtime configuration and reset controls.

---

## 18. Security & Threat Model

| Property | Mechanism | Protection Level |
| :--- | :--- | :--- |
| **Confidentiality** | AES-256-GCM + PBKDF2 (100k iters, 16B salt, 12B nonce) | Strong against passive eavesdropping |
| **Integrity & Tamper Detection** | 16-byte GCM Authentication Tag | Fails closed (`InvalidTag`) on any bit flip, drop, or wrong PSK |
| **DPI Resistance (Content)** | Standard ICMP Echo Request packets | No plaintext or TLS handshake signatures |
| **Statistical Evasion (Timing)** | Gamma & 3-component GMM timing profiles | Mimics ambient router/network IPD distributions |

**Out-of-Scope / Known Threat Vectors:**
- Active network normalizers that overwrite `IP.id` or buffer/pace ICMP traffic can disrupt `IP-ID` or `Temporal` decoding (detected safely via AES-GCM tag failure).
- High-volume ICMP traffic volume analysis or endpoint host monitoring can still observe unusual ICMP packet counts.

---

## 19. Error Handling & Integrity Guarantees

- **Simplex Design (No ACKs):** NetGhost transmits unidirectionally so no return channel leaks covert session existence.
- **Wrong Passphrase:** PBKDF2 derives a different key; AES-GCM tag verification fails and displays `AUTHENTICATION FAILED: Decryption failed` without revealing corrupt output.
- **Packet Loss / Early Stop:** Frame buffer remains below 100% or fails `InvalidTag` upon decryption.
- **Channel Mode Mismatch:** Header packets sent at millisecond speed appear as all-`0` bits to a Temporal receiver and never match `0xDEAD`.

---

## 20. Performance Characteristics

| Metric | IP-ID Header Embedding | Temporal IPD Channel |
| :--- | :--- | :--- |
| **Steganography Type** | Storage (IPv4 `IP.id`) | Timing (Inter-Packet Delay $\Delta t$) |
| **Capacity per Packet** | 16 bits (2 bytes) | 1 bit |
| **Typical Speed (short msg)** | < 1 second (~500–8,000 bps depending on pacing) | ~40–120 seconds (~3–13 bps) |
| **Packet Count for `"HELLO"` (5 B)** | 27 packets (53B frame padded to 54B = 27 words) | 425 packets (1 lead + 424 bits) |
| **Jitter Sensitivity** | Low (ordered by `ICMP.seq`) | Moderate–High (depends on 75 ms threshold margin) |

---

## 21. Testing & Verification Strategy

NetGhost uses a three-tier verification approach:
1. **Automated Pytest Suite (`tests/` — 65 tests):**
   - `test_crypto.py` — PBKDF2 + AES-GCM round trips, wrong PSK, tampering, Unicode, nonce uniqueness.
   - `test_framing.py` — `0xDEAD` sync detection, length validation, garbage prefix tolerance, oversized rejection.
   - `test_header_channel.py` — `uint16` chunking, odd-length padding, header channel round trips.
   - `test_temporal_channel.py` — MSB-first bit conversion, 75 ms threshold decoding, jitter tolerance.
   - `test_ml.py` — PCAP timing extraction, outlier cleaning, 3-component GMM training, joblib save/load.
   - `test_live_flow_events.py` — Live SSE callback and UI event emission.
   - `test_timing_and_gmm.py` — Timing profile factory, `[5.0, 500.0] ms` bounds, GMM integration, API endpoints.
2. **Non-Elevated End-to-End Verification (`scratch/e2e_pipeline_verify.py`):**
   - Verifies full encryption → framing → channel encoding → decoding → decryption without requiring Windows Administrator / Npcap privileges.
3. **Live Packet-Level Verification (Wireshark):**
   - Capturing on `Adapter for loopback traffic capture` with `icmp.type == 8` verifies `IP.id = 0xDEAD` in Packet #1 (Header mode) and $\Delta t$ intervals (Temporal mode).

---

## 22. Limitations & Challenges

- **Administrator Privileges Required for Live Sniffing/Injection:** Scapy raw sockets and Npcap loopback capture require elevated privileges on Windows (`sudo`/capabilities on Linux).
- **No Forward Error Correction (FEC):** Because NetGhost prioritizes minimal overhead and fail-closed security, lost packets cannot be repaired and trigger reassembly/authentication failure.
- **Temporal Throughput:** At 1 bit per packet (~25 ms / ~125 ms), Temporal IPD mode is suited for short covert messages rather than large file transfers.
- **OS Timer Granularity:** Windows default ~15.6 ms sleep granularity requires `timeBeginPeriod(1)` for accurate sub-10 ms timing control.

---

## 23. Future Enhancements

- **Forward Error Correction (FEC):** Reed-Solomon or Hamming coding before encryption to tolerate minor packet loss or timing jitter.
- **Additional Covert Carriers:** TCP sequence numbers, DNS query timing/subdomains, or HTTP header ordering.
- **Adaptive Threshold Estimation:** Receiver-side K-means or Otsu thresholding on incoming $\Delta t$ distributions instead of a static `75.0 ms` cutoff.
- **Asymmetric Key Exchange:** Ephemeral ECDH key agreement to remove manual PSK distribution.

---

## 24. Conclusion

NetGhost demonstrates that true communication stealth requires uniting **applied cryptography**, **low-level packet engineering**, and **statistical traffic modeling**. By combining PBKDF2-HMAC-SHA256 + AES-256-GCM authenticated encryption with both 16-bit `IP.id` header embedding and ML-shaped (Gamma / 3-component GMM) temporal modulation, the system provides a complete, verifiable laboratory platform for studying both covert channel construction and defensive detection.

---

## 25. References

1. Gianvecchio, S., Wang, H., Wijesekera, D., & Jajodia, S. (2008). *Model-Based Covert Timing Channels: Automated Modeling and Evasion.* RAID 2008, LNCS 5230, pp. 211–230.
2. Cabuk, S., Brodley, C. E., & Shields, C. (2004). *IP Covert Timing Channels: Design and Detection.* ACM CCS 2004.
3. Wendzel, S., Zander, S., Fechner, B., & Herdin, C. (2014). *Pattern-Based Survey and Categorization of Network Covert Channel Techniques.* ACM Computing Surveys.
4. Zander, S., Armitage, G., & Branch, P. (2007). *A Survey of Covert Channels and Countermeasures in Computer Network Protocols.* IEEE Communications Surveys & Tutorials.
5. Dworkin, M. (2007). *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC.* NIST Special Publication 800-38D.
6. Moriarty, K., Kaliski, B., & Rusch, A. (2017). *PKCS #5: Password-Based Cryptography Specification Version 2.1 (PBKDF2).* RFC 8018.

