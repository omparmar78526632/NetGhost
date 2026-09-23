# NETGHOST: Complete Project & Technical Guide

---

## Table of Contents
1. [Chapter 1: Project Overview & Motivation](#chapter-1-project-overview--motivation)
2. [Chapter 2: System Architecture & 4-Stage Pipeline](#chapter-2-system-architecture--4-stage-pipeline)
3. [Chapter 3: The Two Covert Channels](#chapter-3-the-two-covert-channels)
4. [Chapter 4: Timing Profiles & Delay Mechanisms](#chapter-4-timing-profiles--delay-mechanisms)
5. [Chapter 5: Understanding Duration & Timers](#chapter-5-understanding-duration--timers)
6. [Chapter 6: Complete Step-by-Step Example Walkthrough ("HELLO")](#chapter-6-complete-step-by-step-example-walkthrough-hello)
7. [Chapter 7: Failure Scenarios & Security Verification](#chapter-7-failure-scenarios--security-verification)
8. [Chapter 8: Complete Technical Glossary](#chapter-8-complete-technical-glossary)
9. [Chapter 9: Libraries and Technologies Used](#chapter-9-libraries-and-technologies-used)
10. [Chapter 10: Viva & Presentation Guide](#chapter-10-viva--presentation-guide)

---

# Chapter 1: Project Overview & Motivation

### 1.1 What is NETGHOST?
NETGHOST is an advanced network steganography system designed to transmit encrypted information invisibly across computer networks. It transforms standard network traffic (such as ICMP ping packets) into a hidden carrier for secret data.

### 1.2 The Core Problem: Cryptography vs. Steganography
* **Cryptography (Encryption)** protects the **confidentiality** of the message. However, the resulting encrypted text looks like random characters. Deep Packet Inspection (DPI) firewalls easily notice encrypted traffic and can block or inspect it.
* **Network Steganography** hides the **existence** of the communication itself. The data is hidden inside legitimate protocol fields or between natural packet transmission delays, making it look like normal background network traffic.
* **NETGHOST combines both**: It uses **military-grade AES-256-GCM encryption** first, and then hides that encrypted data using **Network Steganography**.

### 1.3 Why AES-256-GCM Was Chosen (Cipher Comparison)
When building covert channels, selecting the right encryption algorithm is critical. NETGHOST uses **AES-256-GCM** because it solves three major challenges:
1. **Built-in Tamper Detection (AEAD)**: Unlike standard encryption, AES-GCM generates a 16-byte Authentication Tag. If any bit is flipped, corrupted, or tampered with in transit, the receiver immediately flags `TAG MISMATCH` and rejects corrupt data.
2. **Zero Padding Overhead**: GCM operates in counter (stream) mode. A 5-byte message produces exactly 5 bytes of ciphertext without wasting packet space on block padding.
3. **Future-Proof Security**: 256-bit keys provide quantum-resistant protection against brute-force attacks.

#### Encryption Cipher Comparison Table:

| Algorithm / Mode | Confidentiality | Authenticity (Tamper Detection) | Efficiency / Size | Why It Was / Was NOT Chosen |
| :--- | :--- | :--- | :--- | :--- |
| **DES / 3DES** | Weak | None | Small | **Broken & Deprecated** (56-bit keys can be brute-forced in hours). |
| **AES-ECB** | Insecure | None | Block-padded | **Insecure** (Identical plaintext blocks produce identical ciphertext blocks; reveals patterns). |
| **AES-CBC** | Strong | None | Block-padded | **No tamper detection**; vulnerable to padding oracle attacks. Requires a separate HMAC. |
| **RSA (Asymmetric)** | Strong | Via Signatures | Very Large | **Too large & slow** (2048-bit RSA produces a 256-byte ciphertext, which is too large for 16-bit covert channels). |
| **AES-256-GCM** | **Military Grade** | **Built-in (16B Tag)** | **Exact Byte Fit** | **SELECTED**: High speed, compact, tamper-proof, and hardware-accelerated. |

---

# Chapter 2: System Architecture & 4-Stage Pipeline

The entire system operates in 4 sequential stages from the moment a user types a message to the moment it is recovered on the receiver side.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             STAGE 1: ENCRYPTION                             │
│  User Plaintext + Passphrase  ──▶  PBKDF2 Key Derivation + AES-256-GCM       │
│  Output: [ 16B Salt ] + [ 12B Nonce ] + [ Ciphertext ] + [ 16B Auth Tag ]   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│                              STAGE 2: FRAMING                               │
│  Assemble Protocol Frame:                                                   │
│  [ Sync Marker (0xDEAD) ] + [ Length Header (2 Bytes) ] + [ Encrypted Data ]│
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│                            STAGE 3: TRANSMISSION                            │
│  Choose Channel Mode:                                                       │
│    A) IP-ID Header Embedding (Storage Channel: 16 bits per packet)           │
│    B) Temporal IPD (Timing Channel: 1 bit per packet delay)                 │
│  Transmit forged ICMP packets over the network using Scapy raw sockets      │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│                    STAGE 4: RECEPTION & DECRYPTION                          │
│  1. Sniff raw ICMP packets using Scapy                                      │
│  2. Demodulate bytes / bits                                                 │
│  3. Detect 0xDEAD sync marker & extract payload length                      │
│  4. Reassemble full frame buffer (100%)                                     │
│  5. Verify AES-256-GCM Authentication Tag & decrypt plaintext               │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

# Chapter 3: The Two Covert Channels

NETGHOST implements two fundamentally different types of covert channels:

### 3.1 Channel 1: IP-ID Header Embedding (Storage Channel)
* **How it Works**: Every IPv4 packet header contains a 16-bit **Identification (`IP.id`)** field. NETGHOST replaces this field with 2 bytes of the encrypted frame per packet.
* **Characteristics**:
  * **Speed**: Ultra-fast (transmits in milliseconds).
  * **Throughput**: High (16 bits / 2 bytes per packet).
  * **Packet Content**: Standard ICMP Echo Request packets with modified header IDs.

### 3.2 Channel 2: Temporal IPD (Timing Channel)
* **How it Works**: Data is not stored in packet headers or payloads. Instead, data is encoded in the **Inter-Packet Delay (Δt)** — the exact time elapsed between sending one packet and the next.
  * **Bit 0** -> Fast packet delay (~25 ms).
  * **Bit 1** -> Slow packet delay (~125 ms).
* **Characteristics**:
  * **Speed**: Slower (transmits 1 bit per packet over 40 to 100+ seconds).
  * **Throughput**: Low (1 bit per packet).
  * **Stealth**: **Maximum stealth**. The packet contents are 100% normal pings; the covert message exists purely in time.

### 3.3 Channel Comparison Table

| Feature | IP-ID Header Embedding | Temporal IPD (Timing) |
| :--- | :--- | :--- |
| **Steganography Type** | Storage-based | Timing-based |
| **Carrier Field** | IPv4 IP.id Header (16 bits) | Inter-Packet Delay (Time Gap) |
| **Data Rate** | 16 bits per packet | 1 bit per packet |
| **Transmission Speed** | Less than 1 second | 40 to 120 seconds |
| **Detection Resistance** | Evades basic DPI firewalls | **Evades advanced statistical & DPI analysis** |

---

# Chapter 4: Timing Profiles & Delay Mechanisms

In **Temporal IPD Mode**, the receiver uses a decision threshold at **75 ms**:
* Any inter-packet delay **less than 75 ms** is decoded as **Bit 0**.
* Any inter-packet delay **75 ms or greater** is decoded as **Bit 1**.

To prevent an Intrusion Detection System (IDS) from spotting rigid, mechanical delay patterns, NETGHOST provides 4 timing profiles:

```
1. CONSTANT DELAY (Fixed intervals)
   Bit 0: [ 25.0 ms ]
   Bit 1: [ 125.0 ms ]
   • Uses exact mathematical delays. Simple and fast, but produces 2 sharp spikes on an IDS histogram.

2. NORMAL / VARIABLE DELAY (Gaussian Jitter)
   Bit 0: [ 25 ms with natural jitter ]  (e.g., 23.4ms, 26.1ms, 24.8ms)
   Bit 1: [ 125 ms with natural jitter ] (e.g., 121.2ms, 127.5ms, 124.3ms)
   • Adds natural random variation (jitter) so delays look like real Internet traffic fluctuations.

3. GAMMA DELAY (Queue Modeling)
   • Samples delays from a Gamma distribution, accurately mimicking packet queuing delays in network routers.

4. GMM PROFILE (Machine Learning Traffic Shaping)
   • Uses a Gaussian Mixture Model trained on real background network traffic. Delays blend statistically into normal network traffic, making detection virtually impossible.
```

---

# Chapter 5: Understanding Duration & Timers

There are two different duration concepts in NETGHOST:

### 5.1 Receiver "Capture Duration" (Timeout Setting)
* **What it is**: The active listening window for the receiver's Scapy sniffer.
* **Why it matters**:
  * **For IP-ID Header Mode**: `30 s` is more than enough because transmission finishes in less than 1 second.
  * **For Temporal IPD Mode**: A transmission with hundreds of bits takes 60 to 120 seconds. The Capture Duration must be set to **`120 s` or `300 s`** (or stopped manually) so the sniffer does not exit before all bits arrive.

### 5.2 Sender "Transmission Time" (Live Stopwatch)
* **What it is**: The live stopwatch timer displayed on the sender UI.
* **How it works**: Starts when packet #1 is transmitted and automatically stops when the last packet is sent, displaying the exact transmission duration (e.g., `99.40 s`).

---

# Chapter 6: Complete Step-by-Step Example Walkthrough ("HELLO")

Below is an exact trace of what happens when sending the word **`"HELLO"`**:

### Scenario Parameters:
* **Plaintext Message**: `"HELLO"` (5 bytes)
* **Passphrase**: `"netghost2026"`
* **Sender IP**: `192.168.1.5` -> **Receiver IP**: `192.168.1.10`

---

### Step 1: AES-256-GCM Encryption
1. **Key Derivation**: Passphrase `"netghost2026"` + 16-byte random Salt -> (via PBKDF2 with 100k iterations) -> **256-bit AES Key**.
2. **Encryption**: Message `"HELLO"` + 12-byte random Nonce -> (via AES-GCM) -> **5 bytes Ciphertext + 16-byte Auth Tag**.
3. **Encrypted Output Bundle**:
   * Salt (16 Bytes) + Nonce (12 Bytes) + Ciphertext (5 Bytes) + Auth Tag (16 Bytes) = **49 Bytes Total**

---

### Step 2: Protocol Frame Assembly
NETGHOST wraps the 49-byte bundle into a structured frame:

| Field | Size | Value / Content | Purpose |
| :--- | :--- | :--- | :--- |
| **Sync Marker** | 2 Bytes | `0xDEAD` | Tells receiver: "Transmission starts here" |
| **Length Header** | 2 Bytes | `0x0031` (49 in decimal) | Tells receiver: "49 bytes of payload follow" |
| **Encrypted Payload** | 49 Bytes | Salt + Nonce + Ciphertext + Tag | The actual encrypted message bundle |

* **Total Frame Size**: 2 + 2 + 49 = **53 Bytes** (padded to 54 bytes for 16-bit word alignment).

---

### Step 3A: Transmission via Header Channel
* The 54-byte frame is split into **27 chunks of 2 bytes (16-bit words)**.
* Sender transmits 27 ICMP Echo Request packets:
  * **Packet #1**: `IP(dst="192.168.1.10", id=0xDEAD) / ICMP()` -> Sync Marker
  * **Packet #2**: `IP(dst="192.168.1.10", id=0x0031) / ICMP()` -> Length = 49 bytes
  * **Packet #3 to #27**: `IP(dst="192.168.1.10", id=0x...) / ICMP()` -> Payload chunks
* **Time Taken**: ~0.05 seconds.

---

### Step 3B: Transmission via Temporal Channel
* The 53-byte frame is converted to **424 binary bits** (53 bytes * 8 bits = 424 bits).
* Sender transmits 425 ICMP Echo Request packets:
  * **Packet #1**: Sent at time 0.000s (Lead synchronization reference packet).
  * **Packet #2**: Sender sleeps **125 ms**, then sends packet #2 (Encodes Bit 1).
  * **Packet #3**: Sender sleeps **125 ms**, then sends packet #3 (Encodes Bit 1).
  * **Packet #4**: Sender sleeps **25 ms**, then sends packet #4 (Encodes Bit 0).
  * ...
  * **Packet #425**: Final bit packet transmitted.
* **Time Taken**: ~40 seconds.

---

### Step 4: Receiver Demodulation & Decryption
1. **Sniffing**: Scapy intercepts incoming ICMP packets.
2. **Sync Detection**: Receiver spots `0xDEAD` in the incoming stream.
3. **Length Extraction**: Reads length header `0x0031`, learning that exactly 49 bytes follow.
4. **Buffering**: Collects all 49 bytes -> Reassembly reaches **100%**.
5. **Decryption**: Separates Salt, Nonce, Ciphertext, and Auth Tag.
6. **Authentication**: AES-GCM verifies the Auth Tag matches -> **`✓ AUTH_OK`**.
7. **Result**: Plaintext output:
   `> HELLO`

---

# Chapter 7: Failure Scenarios & Security Verification

NETGHOST is built with strict cryptographic integrity checks. Here is how errors are handled:

### Scenario 1: Wrong Passphrase
* **Trigger**: Sender uses `secret_pass`, Receiver uses `wrong_pass`.
* **Behavior**: Key derived via PBKDF2 will not match. The 16-byte AES-GCM Authentication Tag fails verification.
* **UI Indicator**: Displays **`✗ TAG MISMATCH`** / **`AUTHENTICATION FAILED`**. Corrupt data is discarded immediately.

### Scenario 2: Incomplete Transmission / Early Sniffer Stop
* **Trigger**: Sniffer capture duration expires before all packets/bits arrive (e.g., only 200/424 bits captured).
* **Behavior**: Frame buffer remains incomplete; receiver cannot verify the full frame.
* **UI Indicator**: Reassembly stops at intermediate percentage (e.g., `47%`), and decryption is not attempted.

### Scenario 3: Channel Mode Mismatch
* **Trigger**: Sender is on `IP-ID Header`, Receiver is on `Temporal IPD`.
* **Behavior**: Sender sends all packets in milliseconds. The temporal receiver interprets all delays as zeros and never finds the `0xDEAD` preamble.

### Scenario 4: Active In-Flight Tampering
* **Trigger**: An attacker or network device modifies a single bit of the packet header or payload in transit.
* **Behavior**: AES-256-GCM detects ciphertext tampering and raises a MAC check failure, preventing man-in-the-middle attacks.

---

# Chapter 8: Complete Technical Glossary

* **Network Steganography**: The technique of concealing secret messages within legitimate network protocol traffic so that external observers cannot detect that communication is happening.
* **Covert Channel**: A hidden communication path built inside standard network protocols that was never intended for data transfer.
* **IP-ID (IPv4 Identification Field)**: A 16-bit field in the IPv4 header used by NETGHOST as a storage covert channel to carry 2 bytes of encrypted data per packet.
* **IPD (Inter-Packet Delay, Δt)**: The time interval between two consecutive packet arrivals, used in Temporal mode to represent binary `0` and `1`.
* **ICMP (Internet Control Message Protocol)**: The network protocol used by `ping`. NETGHOST uses ICMP packets as the covert transport carrier.
* **Scapy**: A Python packet manipulation tool used for crafting raw packets, modifying IP headers, and sniffing network interfaces.
* **AES-256-GCM (Galois/Counter Mode)**: An Authenticated Encryption algorithm that provides both 256-bit encryption confidentiality and cryptographic tamper-detection (authenticity).
* **PBKDF2 (Password-Based Key Derivation Function 2)**: An algorithm that turns a user's text passphrase into a cryptographic 256-bit key by hashing it 100,000 times with a random Salt.
* **Salt (16 Bytes)**: Random data added to the passphrase before key derivation so that identical passwords generate completely different AES keys.
* **Nonce / IV (Initialization Vector, 12 Bytes)**: A unique random number used in AES-GCM to ensure that encrypting the same text twice produces completely different ciphertexts.
* **Auth Tag / MAC (16 Bytes)**: A cryptographic signature produced during AES-GCM encryption. If any bit of the ciphertext or key is wrong, authentication fails immediately.
* **Sync Marker / Preamble (`0xDEAD`)**: A 2-byte signature placed at the start of every NETGHOST transmission to signal the receiver to begin capturing.
* **Protocol Frame**: The structured container format: `[Sync (0xDEAD)] + [Length (2 Bytes)] + [Encrypted Data]`.
* **Jitter**: Natural, random fluctuations in packet transmission delays caused by network hardware and routing.
* **GMM (Gaussian Mixture Model)**: A machine learning model that clusters real network delay distributions into bell curves to generate realistic, undetectable timing jitter.
* **DPI (Deep Packet Inspection)**: Advanced firewall inspection systems that analyze packet payloads and statistical flow characteristics.

---

# Chapter 9: Libraries and Technologies Used

If the examiner asks: *"Which libraries did you use and what does each one do?"*, here is the exact list and their specific roles in NETGHOST:

| Library | Specific Role & Function in this Project |
| :--- | :--- |
| **`scapy`** | **Raw Packet Crafting & Sniffing**: Forges custom IPv4/ICMP packets, modifies the 16-bit `IP.id` header field, and captures incoming network packets in real time. |
| **`cryptography`** | **Military-Grade Security**: Implements `AES-256-GCM` (Galois/Counter Mode) authenticated encryption, `PBKDF2-HMAC-SHA256` key derivation, and cryptographic random salt/nonce generation. |
| **`scikit-learn` (`sklearn`)** | **Machine Learning Traffic Shaping**: Implements `GaussianMixture` (GMM) models to learn legitimate network delay patterns and generate undetectable timing jitter. |
| **`numpy`** | **Mathematical & Statistical Calculations**: Handles delay arrays, computes inter-packet differences (Δt), and samples random distributions (Normal and Gamma). |
| **`joblib`** | **ML Model Persistence**: Saves (`joblib.dump`) and loads (`joblib.load`) the pre-trained Gaussian Mixture Model (`gmm_timing.pkl`). |
| **`flask`** | **Web Application & Real-Time API**: Hosts the web dashboards, provides REST endpoints (`/send`, `/start`, `/stop`), and broadcasts Server-Sent Events (SSE) via `/stream`. |
| **`ctypes` (Built-in)** | **High-Precision Windows Timer**: Calls `winmm.dll.timeBeginPeriod(1)` to force 1-millisecond timer resolution on Windows for precise packet delay timing. |
| **`pytest`** | **Automated Testing Suite**: Runs 53 automated unit and integration tests covering cryptography, framing, header/temporal channels, and ML profiling. |

---

# Chapter 10: Viva & Presentation Guide

### 9.1 The 30-Second Elevator Pitch
> *"**NETGHOST** is an advanced network steganography system. While standard encryption only protects message contents, NETGHOST conceals the existence of the communication itself. It encrypts payloads with AES-256-GCM and embeds them inside standard IPv4/ICMP network traffic using two covert channels: **IP-ID Header Embedding** for high throughput, and **Temporal Inter-Packet Delays (IPD) with Machine Learning Traffic Shaping** for maximum stealth against Deep Packet Inspection firewalls."*

### 9.2 Live Demonstration Workflow
1. **Receiver Setup**:
   * Set Passphrase to `lab_secret`.
   * Channel: `IP-ID Header Embedding`.
   * Click **Start Capture**.
2. **Sender Setup**:
   * Target IP: `127.0.0.1`.
   * Passphrase: `lab_secret`.
   * Message: `CONFIDENTIAL_INTEL_2026`.
   * Click **Transmit Stream**.
3. **Show Live Flow**:
   * Point out the live packet stream conveyor showing `0xDEAD` and encrypted chunks.
   * Point out the receiver live pipeline stages: **Capture** -> **Sync (`0xDEAD`)** -> **Reassembly (`100%`)** -> **AES Decrypt (`✓ AUTH_OK`)** -> **Message Recovered**.
4. **Show Security (Negative Test)**:
   * Change Sender passphrase to `wrong_secret` and send again.
   * Show the receiver displaying **`✗ TAG MISMATCH`** and rejecting the unauthenticated data.

---

*Document compiled and verified for NETGHOST.*
