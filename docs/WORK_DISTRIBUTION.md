# NetGhost — Team Work Distribution & Module Ownership

**Project Title:** NetGhost: Covert Data Communication Using Network Steganography and Traffic Modulation  
**Team Members (4):** **OM** (Om Parmar), **Kedar.N**, **Kedar.P**, **Arthava** (Atharva)

> **Attribution Note:** Role and module assignments below are derived from the repository's existing contribution record (`NETGHOST_TEAM_CONTRIBUTION.md`) and mapped to the current codebase structure. Where newer files (`common/timing.py`, `tests/test_timing_and_gmm.py`) extend an existing module area, ownership is aligned to the corresponding domain owner.

---

## 1. Team Overview Table

| Member | Primary Role | Owned / Assigned Modules & Files | Key Technical Responsibilities |
| :--- | :--- | :--- | :--- |
| **OM** (Om Parmar) | **Lead Architect & Transmission Specialist** | • `sender/sender_core.py`<br>• `sender/sender_app.py`<br>• `config.py`<br>• `start_netghost.bat`, `start_dual_nodes.bat`, `start_sender.bat` | • System architecture & dual-node execution design<br>• `HeaderChannelSender` (`IP.id` 16-bit embedding)<br>• `TemporalChannelSender` (IPD bit modulation)<br>• Raw Scapy IP/ICMP packet crafting & transmission<br>• Windows 1 ms multimedia timer (`timeBeginPeriod`) & launch scripts |
| **Kedar.N** | **Cryptography & Receiver Specialist** | • `common/crypto.py`<br>• `common/framing.py`<br>• `common/utils.py`<br>• `receiver/receiver_core.py`<br>• `receiver/receiver_app.py`<br>• `tests/test_crypto.py`, `tests/test_framing.py` | • AES-256-GCM AEAD encryption/decryption engine<br>• PBKDF2-HMAC-SHA256 (100,000 rounds) key derivation<br>• `0xDEAD` binary framing protocol & `uint16`/bit utilities<br>• Scapy sniffer, Npcap loopback resolution & `<3 ms` deduplication<br>• `75 ms` temporal bit demodulator & `ICMP.seq`-ordered reassembly |
| **Kedar.P** | **Machine Learning & Traffic Profiling Specialist** | • `ml/ml_profiler.py`<br>• `ml/train_model.py`<br>• `common/timing.py`<br>• `ml/models/gmm_timing.pkl`<br>• `tests/test_ml.py`, `tests/test_timing_and_gmm.py` | • PCAP inter-packet delay (IPD) extraction & outlier cleaning<br>• 3-component Gaussian Mixture Model (EM) training & `joblib` persistence<br>• Model evaluation (`log_likelihood`, `AIC`, `BIC`, means, variances, weights)<br>• Timing profile implementations (`Constant`, `Normal`, `Gamma`, `GMM`)<br>• Bounded timing synthesis (`[5.0, 500.0] ms`) |
| **Arthava** (Atharva) | **Full-Stack Dashboard, Live Visualizer & QA Specialist** | • `app.py`<br>• `templates/index.html`<br>• `static/css/netghost.css`<br>• `static/js/netghost.js`<br>• `tests/test_live_flow_events.py`, `tests/test_header_channel.py`, `tests/test_temporal_channel.py` | • Unified Flask REST API (`app.py`) & node isolation (`:5000` vs `:5001`)<br>• Server-Sent Events (`GET /stream`) real-time telemetry pipeline<br>• Cybernetic Lab UI (9 screens: Overview, Sender, Receiver, Profiler, Monitor, Experiments, Results, Docs, Settings)<br>• Live Transmission & Reception Flow visualizers + typewriter terminal<br>• Automated `pytest` integration & E2E verification |

---

## 2. Detailed Individual Contributions

### 2.1 OM (Om Parmar) — Lead Architect & Transmission Specialist
- **End-to-End Architecture & Configuration (`config.py`):**
  - Defined the layered covert communication stack mapping application-layer encrypted frames onto IPv4/ICMP Echo Request packets.
  - Established dual-node execution constants (`SENDER_PORT = 5000`, `RECEIVER_PORT = 5001`, `DEFAULT_TARGET_IP = "127.0.0.1"`, `SYNC_MARKER = 0xDEAD`).
- **Covert Sender Engine (`sender/sender_core.py`, `sender/sender_app.py`):**
  - **`HeaderChannelSender`:** Slices framed ciphertext into 16-bit chunks and injects each chunk into `IP(dst=target_ip, id=chunk) / ICMP(seq=i)` with diagnostic frame-hash/nonce logging.
  - **`TemporalChannelSender`:** Transmits a lead synchronization packet (`seq=0`) followed by 1 ICMP packet per bit, querying the active timing profile (`constant`, `normal`, `gamma`, or `gmm`) for each bit's inter-packet delay.
  - **Windows Timer Precision:** Interfaces with `winmm.dll` (`timeBeginPeriod(1)`) so Python sleep intervals maintain 1 ms precision on Windows hosts.
- **Deployment & Launch Automation:**
  - Created Windows batch launchers (`start_netghost.bat`, `start_dual_nodes.bat`, `start_sender.bat`) for virtual environment activation and elevated execution.

### 2.2 Kedar.N — Cryptography & Receiver Specialist
- **Authenticated Encryption (`common/crypto.py`):**
  - Implemented `PBKDF2HMAC` (SHA-256, 100,000 iterations, 16-byte random salt) to derive 256-bit keys from user passphrases.
  - Implemented `AESGCM` encryption/decryption with 12-byte random nonces and 16-byte authentication tags (`salt || nonce || ciphertext || tag`), ensuring fail-closed `InvalidTag` rejection on tampering or wrong PSK.
- **Framing & Serialization (`common/framing.py`, `common/utils.py`):**
  - Built `create_frame`, `parse_frame`, and `find_sync_marker` around the 4-byte header (`0xDEAD` + big-endian `uint16` length, max `65,535` bytes).
  - Implemented `bytes_to_uint16_list`, `uint16_list_to_bytes`, `bytes_to_bits` (MSB-first), `bits_to_bytes`, and `format_bytes_hex`.
- **Receiver Sniffing & Demodulation (`receiver/receiver_core.py`, `receiver/receiver_app.py`):**
  - Implemented `resolve_sniff_interfaces()` for cross-platform and Windows `\Device\NPF_Loopback` capture.
  - Engineered `HeaderChannelReceiver` with `< 3 ms` loopback duplicate suppression, `(icmp_seq, ip_id)` dedup tracking, `(0xDEAD, seq=0)` session reset, and `ICMP.seq`-ordered frame reassembly.
  - Engineered `TemporalChannelReceiver` using a `75.0 ms` midpoint threshold to classify inter-packet delays into bits and reassemble encrypted frames.

### 2.3 Kedar.P — Machine Learning & Traffic Profiling Specialist
- **PCAP Timing Extraction & Cleaning (`ml/ml_profiler.py`):**
  - Built `extract_timing_from_pcap()` using Scapy `rdpcap()` to compute consecutive millisecond inter-arrival times ($\Delta t_{\text{ms}}$).
  - Built `clean_timing_data()` to filter non-finite values and intervals outside `[0.1, 1000.0] ms`.
- **Gaussian Mixture Model Training & Persistence (`ml/ml_profiler.py`, `ml/train_model.py`):**
  - Implemented 3-component `GaussianMixture(covariance_type='full', max_iter=200, reg_covar=1e-4)` training via EM.
  - Computed model diagnostics (`means`, `variances`, `weights`, `log_likelihood`, `aic`, `bic`, `converged`, `n_iter`) and serialized `ml/models/gmm_timing.pkl` via `joblib`.
  - Built the CLI training utility (`ml/train_model.py`) supporting real PCAP files and synthetic baseline generation (`--create-synthetic`).
- **Timing Profile Engine (`common/timing.py`):**
  - Implemented the four unified timing profiles (`ConstantTimingProfile`, `NormalVariableTimingProfile`, `GammaTimingProfile`, `GMMTimingProfile`) and `create_timing_profile()` factory, clamping sampled GMM delays to `[5.0, 500.0] ms`.

### 2.4 Arthava (Atharva) — Full-Stack Dashboard, Live Visualizer & QA Specialist
- **Flask Backend & Real-Time Streaming (`app.py`):**
  - Developed the unified Flask server supporting both unified mode (`:5000`) and isolated dual-node mode (`NETGHOST_MODE=sender|receiver`).
  - Implemented REST endpoints for transmission (`/send`, `/api/sender/prepare`), reception (`/start`, `/stop`, `/api/receiver/state`), GMM management (`/gmm_status`, `/api/profiler/*`), live packet monitoring (`/api/monitor/*`), experiments (`/api/experiments/*`), results export (`/api/results/*`), and settings (`/api/settings`).
  - Built the Server-Sent Events stream (`GET /stream`) for zero-polling browser telemetry.
- **Cybernetic Lab Frontend (`templates/index.html`, `static/css/netghost.css`, `static/js/netghost.js`):**
  - Built the 9-screen navigation shell keeping Sender and Receiver cleanly separated.
  - Enforced mode-aware Sender controls (`#timingProfileGroup` hidden in `IP-ID Header Embedding` mode and visible only in `Temporal IPD` mode).
  - Implemented Live Transmission Flow (5-stage pipeline, packet conveyor) and Live Reception Flow (7-stage pipeline, 75 ms threshold timeline, typewriter plaintext reveal).
- **Automated Testing & QA (`tests/`):**
  - Maintained the 65-test `pytest` suite covering cryptography, framing, header/temporal channels, ML profiling, timing profiles, and SSE live flow events.

---

## 3. Shared Integration Responsibilities

All four members collaborated on cross-module integration milestones:
1. **End-to-End Frame Consistency:** Aligning odd-length `uint16` padding in `Sender` with `0xDEAD` + `LENGTH` parsing and `ICMP.seq`-ordered reassembly in `Receiver` so AES-256-GCM authentication succeeds deterministically.
2. **GMM-to-Sender Integration:** Connecting `ml/models/gmm_timing.pkl` loading (`POST /api/profiler/load`) directly to `TemporalChannelSender` via `GMMTimingProfile`.
3. **Loopback Capture Reliability:** Resolving Windows Npcap loopback duplication and timing jitter so both Wireshark inspection and UI telemetry match.

---

## 4. Testing, Documentation & Viva Preparation Breakdown

| Activity | Lead Owner(s) | Supporting Members |
| :--- | :--- | :--- |
| **Unit & Integration Test Suite (`pytest -v`, 65 tests)** | Arthava, Kedar.N | Kedar.P (ML & timing tests), OM (sender validation) |
| **Non-Admin E2E Pipeline Verification (`scratch/e2e_pipeline_verify.py`)** | Kedar.N, Arthava | OM, Kedar.P |
| **Wireshark Packet & IPD Verification** | OM, Kedar.N | Kedar.P, Arthava |
| **Technical Documentation (`PROJECT_DOCUMENTATION.md`)** | All Members | Coordinated by OM & Arthava |
| **Execution & Setup Guide (`HOW_TO_RUN.md`)** | OM, Arthava | Kedar.N, Kedar.P |
| **Viva & Demo Walkthrough** | Each member defends their owned subsystem | Full-team live demo (`IP-ID` + `Temporal GMM`) |

