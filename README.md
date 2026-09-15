# NETGHOST – Invisible Data Transfer Using Network Steganography

## Project Title
**NETGHOST** - A Controlled Laboratory Demonstration of Network Steganography

## Problem Statement
Traditional encryption protects data confidentiality but does not hide the fact that communication is occurring. Network steganography addresses this by concealing encrypted data within seemingly normal network traffic, making it difficult to detect that covert communication is taking place.

## Motivation
- Demonstrate security implications of covert channels in network protocols
- Explore practical implementation of network steganography techniques
- Study machine learning applications in traffic profiling for covert channels
- Provide hands-on learning for Computer Network Technology concepts

## Objectives
1. Implement AES-256-GCM encryption for secure data protection
2. Demonstrate IPv4 header field steganography using IP Identification field
3. Implement temporal inter-packet delay (IPD) covert channel
4. Develop ML-based traffic profiling using Gaussian Mixture Models
5. Create interactive web dashboards for sender and receiver
6. Validate covert channels using Wireshark packet analysis
7. Measure throughput, capacity, and reliability of covert channels

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      SENDER APPLICATION                      │
│  ┌────────────┐    ┌──────────────┐    ┌────────────────┐  │
│  │  Web UI    │───▶│ AES-256-GCM  │───▶│    Framing     │  │
│  │ (Flask)    │    │  Encryption  │    │  (DE AD + Len) │  │
│  └────────────┘    └──────────────┘    └────────┬───────┘  │
│                                                  │           │
│                         ┌────────────────────────┴──────┐   │
│                         ▼                               ▼   │
│              ┌──────────────────┐         ┌─────────────────┐
│              │  Header Channel  │         │ Temporal Channel│
│              │   (IP.id embed)  │         │  (IPD encode)   │
│              └────────┬─────────┘         └────────┬────────┘
│                       └──────────┬──────────────────┘        │
└───────────────────────────────────┼───────────────────────────┘
                                    ▼
                            ┌──────────────┐
                            │ ICMP Packets │
                            │  (IPv4)      │
                            └──────┬───────┘
                                    ▼
┌───────────────────────────────────┼───────────────────────────┐
│                      RECEIVER APPLICATION                     │
│                       ┌──────────────┐                        │
│                       │ Packet Sniff │                        │
│                       │   (Scapy)    │                        │
│                       └──────┬───────┘                        │
│              ┌───────────────┴────────────────┐               │
│              ▼                                ▼               │
│   ┌──────────────────┐            ┌──────────────────┐       │
│   │ Header Decoder   │            │ Temporal Decoder │       │
│   │ (Extract IP.id)  │            │ (Δt → bits)      │       │
│   └────────┬─────────┘            └────────┬─────────┘       │
│            └──────────────┬────────────────┘                 │
│                           ▼                                   │
│               ┌───────────────────────┐                       │
│               │   Frame Reassembly    │                       │
│               │ (Sync + Length check) │                       │
│               └───────────┬───────────┘                       │
│                           ▼                                   │
│               ┌───────────────────────┐                       │
│               │  AES-256-GCM Decrypt  │                       │
│               └───────────┬───────────┘                       │
│                           ▼                                   │
│               ┌───────────────────────┐                       │
│               │   Original Message    │                       │
│               └───────────────────────┘                       │
│                           │                                   │
│                  ┌────────▼─────────┐                         │
│                  │   Web UI (SSE)   │                         │
│                  └──────────────────┘                         │
└───────────────────────────────────────────────────────────────┘

┌───────────────────────────────────────────────────────────────┐
│                  ML TRAFFIC PROFILER                          │
│                                                               │
│  PCAP File  ──▶  Extract Timestamps  ──▶  Compute Δt        │
│                         │                                     │
│                         ▼                                     │
│              ┌──────────────────────┐                        │
│              │  Gaussian Mixture    │                        │
│              │  Model (GMM)         │                        │
│              │  Training            │                        │
│              └──────────┬───────────┘                        │
│                         ▼                                     │
│              ┌──────────────────────┐                        │
│              │  Save Model          │                        │
│              │  (joblib)            │                        │
│              └──────────┬───────────┘                        │
│                         ▼                                     │
│              Used by Temporal Sender                          │
│              to generate realistic delays                     │
└───────────────────────────────────────────────────────────────┘
```

## Technology Stack

### Core Technologies
- **Python 3.x** - Primary implementation language
- **Scapy** - Packet crafting and sniffing
- **Flask** - Web application framework for UI
- **cryptography** - AES-256-GCM implementation

### Machine Learning
- **NumPy** - Numerical computing
- **scikit-learn** - Gaussian Mixture Model
- **joblib** - Model persistence

### Network Analysis
- **Wireshark** - Packet inspection and verification
- **tcpdump** - Network traffic capture

### Protocols
- **IPv4** - Network layer protocol
- **ICMP** - Carrier protocol for covert channels

### Covert Channels
- **IP Identification Field** - Header-based steganography
- **Inter-Packet Delay (IPD)** - Timing-based steganography

## Installation

### Prerequisites
- Python 3.8 or higher
- Administrator/root privileges (for packet sniffing)
- Wireshark (optional, for verification)
- Linux/macOS/Windows with appropriate network permissions

### Setup Instructions

1. **Create Virtual Environment**
```bash
python -m venv .venv
```

2. **Activate Virtual Environment**

Linux/macOS:
```bash
source .venv/bin/activate
```

Windows:
```cmd
.venv\Scripts\activate
```

3. **Install Dependencies**
```bash
pip install -r requirements.txt
```

4. **Train ML Model (Optional)**
```bash
python ml/train_model.py
```

## Project Structure

```
NetGhost/
│
├── README.md                 # This file
├── requirements.txt          # Python dependencies
├── .gitignore               # Git ignore patterns
├── config.py                # Global configuration
│
├── common/                  # Shared modules
│   ├── __init__.py
│   ├── crypto.py           # AES-256-GCM encryption
│   ├── framing.py          # Data frame protocol
│   ├── utils.py            # Utility functions
│   └── config.py           # Common configuration
│
├── sender/                  # Sender application
│   ├── __init__.py
│   ├── sender_core.py      # Core sending logic
│   ├── sender_app.py       # Flask web application
│   └── templates/
│       └── sender.html     # Sender UI
│
├── receiver/                # Receiver application
│   ├── __init__.py
│   ├── receiver_core.py    # Core receiving logic
│   ├── receiver_app.py     # Flask web application
│   └── templates/
│       └── receiver.html   # Receiver UI
│
├── ml/                      # Machine learning components
│   ├── __init__.py
│   ├── ml_profiler.py      # GMM traffic profiling
│   ├── train_model.py      # Model training script
│   └── models/             # Trained models directory
│
├── tests/                   # Automated tests
│   ├── test_crypto.py
│   ├── test_framing.py
│   ├── test_header_channel.py
│   ├── test_temporal_channel.py
│   └── test_ml.py
│
├── docs/                    # Documentation
│   ├── architecture.md
│   ├── protocol.md
│   ├── testing.md
│   └── viva.md
│
└── screenshots/             # Project screenshots
```

## Cryptography Architecture

### AES-256-GCM Implementation

**Key Derivation Flow:**
```
User Pre-Shared Key (PSK)
          │
          ▼
  PBKDF2-HMAC-SHA256
  (100,000 iterations)
          │
          ▼
    32-byte AES Key
          │
          ▼
    AES-256-GCM
          │
          ▼
  Encrypted Payload + Tag
```

**Encryption Format:**
```
┌──────────────┬─────────────────┬──────────────┐
│  Nonce       │  Ciphertext     │  Auth Tag    │
│  (12 bytes)  │  (N bytes)      │  (16 bytes)  │
└──────────────┴─────────────────┴──────────────┘
```

**Security Features:**
- 256-bit key strength
- Authenticated encryption (AEAD)
- Random nonce per encryption
- Authentication tag verification
- Protection against tampering
- PBKDF2 key derivation with salt

## Framing Protocol

### Frame Structure

```
┌────────────────┬────────────────┬──────────────────────────┐
│  Sync Marker   │ Payload Length │   Encrypted Payload      │
│  (2 bytes)     │  (2 bytes)     │   (N bytes)              │
│  0xDEAD        │  Big-endian    │   AES-GCM output         │
└────────────────┴────────────────┴──────────────────────────┘
```

**Fields:**
- **Sync Marker (0xDEAD)**: Frame synchronization identifier
- **Payload Length**: 16-bit unsigned integer, big-endian
- **Encrypted Payload**: Variable-length AES-256-GCM output

**Maximum Frame Size:** 65,535 bytes (limited by 16-bit length field)

## Header Field Steganography

### IPv4 Identification Field Embedding

The IP.id field is a 16-bit field in the IPv4 header originally used for fragment reassembly.

**Encoding Process:**
1. Encrypt message with AES-256-GCM
2. Create frame (SYNC + LENGTH + ENCRYPTED)
3. Split frame into 16-bit chunks
4. Embed each chunk in IP.id field of ICMP Echo Request
5. Send packets sequentially to target

**Example Encoding:**
```
Frame: DE AD 00 06 48 65 6C 6C 6F 21

Chunk 1: 0xDEAD → IP(id=0xDEAD) / ICMP()
Chunk 2: 0x0006 → IP(id=0x0006) / ICMP()
Chunk 3: 0x4865 → IP(id=0x4865) / ICMP()
Chunk 4: 0x6C6C → IP(id=0x6C6C) / ICMP()
Chunk 5: 0x6F21 → IP(id=0x6F21) / ICMP()
```

**Decoding Process:**
1. Capture ICMP Echo Request packets
2. Extract IP.id field from each packet
3. Convert to 16-bit values
4. Reconstruct byte stream
5. Detect sync marker (0xDEAD)
6. Extract payload length
7. Extract encrypted payload
8. Decrypt with AES-256-GCM
9. Display original message

**Characteristics:**
- **Capacity**: 16 bits per packet
- **Throughput**: Limited by packet rate
- **Robustness**: Tolerant to packet reordering (with sequence numbering)
- **Detectability**: Low (uses normal protocol field)

## Temporal IPD Steganography

### Inter-Packet Delay Encoding

Binary data is encoded in the timing intervals between successive ICMP packets.

**Bit Encoding:**
- Bit **0** → Short delay (e.g., 50 ms)
- Bit **1** → Long delay (e.g., 100 ms)

**Encoding Process:**
1. Encrypt message with AES-256-GCM
2. Create frame (SYNC + LENGTH + ENCRYPTED)
3. Convert frame to bit stream (MSB first)
4. For each bit, send ICMP packet with appropriate delay
5. Log timing information

**Delay Profiles:**

1. **Constant**: Fixed delays (50ms / 100ms)
2. **Normal**: Gaussian jitter around target delays
3. **Gamma**: Gamma distribution (models network latency)
4. **GMM/ML**: Sample from trained Gaussian Mixture Model

**Decoding Process:**
1. Capture ICMP packets
2. Extract packet timestamps
3. Compute inter-packet delays (Δt)
4. Apply threshold classifier:
   - Δt < threshold → bit 0
   - Δt ≥ threshold → bit 1
5. Reconstruct byte stream
6. Detect sync marker
7. Extract and decrypt payload

**Example Timing Sequence:**
```
Bit:   1    0    1    1    0    1    0    0
Δt:   100  50  100  100  50  100  50  50  (ms)
```

**Threshold Selection:**
- Default: midpoint between short and long delay
- Configurable based on network conditions
- Can be optimized using ROC analysis

**Characteristics:**
- **Capacity**: 1 bit per packet
- **Throughput**: Dependent on delay values
- **Robustness**: Sensitive to network jitter
- **Detectability**: Medium (requires statistical analysis)

## ML Traffic Profiling

### Gaussian Mixture Model (GMM)

**Purpose**: Model realistic network timing patterns for covert channel

**Training Process:**
```
PCAP File
    │
    ▼
Extract Packet Timestamps
    │
    ▼
Compute Inter-Arrival Times (Δt)
    │
    ▼
Clean Data (remove outliers)
    │
    ▼
Fit Gaussian Mixture Model
(n_components=3, covariance_type='full')
    │
    ▼
Save Model (joblib)
```

**Model Usage:**
```python
# Load trained model
gmm = load_gmm_model('models/gmm_timing.pkl')

# Generate realistic delay
delay = gmm.sample()[0][0]

# Use in temporal sender
send_packet_with_delay(delay)
```

**Features:**
- Multiple Gaussian components capture varied traffic patterns
- Generates delays matching baseline traffic statistics
- Improves covert channel undetectability
- Can be retrained for different network environments

**Statistics Reported:**
- Number of components
- Mean delay per component
- Variance per component
- Component weights

## Sender Usage

### Starting the Sender

```bash
python sender/sender_app.py
```

Default: http://localhost:5000

### Sender Interface

**Configuration Options:**
- **Target IP**: Destination IP address (default: 127.0.0.1)
- **Pre-Shared Key**: Password for AES-256-GCM encryption
- **Message**: Text to send covertly
- **Mode**: 
  - Header Field Embedding (IP.id)
  - Temporal IPD
- **Timing Profile** (Temporal mode only):
  - Constant
  - Normal (Gaussian jitter)
  - Gamma
  - GMM/ML
- **Bit 0 Delay**: Short delay in milliseconds (default: 50)
- **Bit 1 Delay**: Long delay in milliseconds (default: 100)

**Sending Process:**
1. Enter configuration parameters
2. Click "Send Message"
3. Monitor transmission status
4. View statistics (packets sent, bytes, duration)

## Receiver Usage

### Starting the Receiver

```bash
sudo python receiver/receiver_app.py
```

**Note**: Requires root/administrator privileges for packet capture.

Default: http://localhost:5001

### Receiver Interface

**Configuration:**
- **Pre-Shared Key**: Must match sender's key
- **Mode**: Select Header or Temporal
- **Timing Threshold** (Temporal mode): Delay threshold in ms

**Reception Process:**
1. Enter pre-shared key
2. Select mode
3. Click "Start Listening"
4. Monitor live packet capture
5. View decoded message when complete

**Live Updates (SSE):**
- Packets received
- Synchronization status
- IP.id values (Header mode)
- Inter-packet delays (Temporal mode)
- Decoded bits
- Decryption status
- Recovered plaintext

## Wireshark Verification

### Header Field Mode

**Filter**: `icmp.type == 8`

**Verification Steps:**
1. Start Wireshark capture on appropriate interface
2. Run sender with Header mode
3. In Wireshark, observe ICMP Echo Request packets
4. Expand IPv4 header
5. Check **Identification** field
6. Verify sequential values match frame data

**Expected Observation:**
```
Packet 1: IP.id = 0xDEAD (sync marker)
Packet 2: IP.id = 0x0006 (length)
Packet 3: IP.id = 0x???? (encrypted data)
...
```

### Temporal Mode

**Filter**: `icmp.type == 8`

**Verification Steps:**
1. Start Wireshark capture
2. Run sender with Temporal mode
3. Select column: View → Time Display Format → Seconds Since Previous Displayed Packet
4. Observe inter-packet delays
5. Verify pattern of short/long delays

**Expected Observation:**
```
Time Delta:
0.100 s  (bit 1)
0.050 s  (bit 0)
0.100 s  (bit 1)
0.100 s  (bit 1)
...
```

**Analysis:**
- Export packet timestamps to CSV
- Plot time series
- Verify encoding pattern

## Testing

### Running Automated Tests

```bash
# Install pytest if not already installed
pip install pytest

# Run all tests
pytest

# Run specific test file
pytest tests/test_crypto.py

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=common --cov=sender --cov=receiver --cov=ml
```

### Test Coverage

**Crypto Tests** (`test_crypto.py`):
- Encryption/decryption round trip
- Wrong key detection
- Tampering detection
- Nonce uniqueness

**Framing Tests** (`test_framing.py`):
- Frame creation
- Frame parsing
- Short/long messages
- Invalid frames

**Header Channel Tests** (`test_header_channel.py`):
- Encoding to 16-bit chunks
- Decoding from simulated packets
- Round-trip integrity

**Temporal Channel Tests** (`test_temporal_channel.py`):
- Bit-to-delay encoding
- Delay-to-bit decoding
- Threshold behavior
- Jitter tolerance

**ML Tests** (`test_ml.py`):
- Timing extraction from PCAP
- GMM training
- Model save/load
- Delay sampling

## Experimental Results

### Test Environment
- **OS**: [Your OS]
- **Python Version**: 3.x
- **Network**: localhost (127.0.0.1)
- **Interface**: loopback

### Header Field Mode Results

| Message Length | Encrypted Length | Frame Size | Packets | Time (s) | Throughput | Success |
|----------------|------------------|------------|---------|----------|------------|---------|
| 13 bytes       | ~45 bytes        | 49 bytes   | 25      | ~0.5     | ~196 bps   | ✓       |
| 50 bytes       | ~82 bytes        | 86 bytes   | 43      | ~0.9     | ~478 bps   | ✓       |
| 100 bytes      | ~132 bytes       | 136 bytes  | 68      | ~1.4     | ~582 bps   | ✓       |

**Observations:**
- Reliable delivery over localhost
- Linear scaling with message size
- No packet loss detected

### Temporal Mode Results

| Mode     | Message | Packets | Bit 0 | Bit 1 | Time (s) | Throughput | BER  | Success |
|----------|---------|---------|-------|-------|----------|------------|------|---------|
| Constant | 13 B    | 392     | 50 ms | 100ms | 29.4     | ~3.5 bps   | 0%   | ✓       |
| Normal   | 13 B    | 392     | 50 ms | 100ms | 29.7     | ~3.5 bps   | 0%   | ✓       |
| Gamma    | 13 B    | 392     | 50 ms | 100ms | 31.2     | ~3.3 bps   | 0%   | ✓       |
| GMM      | 13 B    | 392     | varies| varies| 35.8     | ~2.9 bps   | 0%   | ✓       |

**Observations:**
- Lower throughput than header mode (1 bit per packet)
- Constant mode most precise
- GMM mode more realistic timing patterns
- No bit errors over localhost
- Timing accuracy: ±5 ms standard deviation

### Capacity Analysis

**Header Mode:**
- **Bits per packet**: 16
- **Theoretical maximum**: ~16 Kbps at 1000 packets/sec
- **Practical rate**: ~500 bps (limited by ICMP rate limiting)

**Temporal Mode:**
- **Bits per packet**: 1
- **Theoretical maximum**: ~1000 bps at 1000 packets/sec
- **Practical rate**: ~3 bps (dominated by delay values)
- **Optimization potential**: Reduce delays to 10ms/20ms → ~50 bps

## Limitations

### Technical Limitations

1. **Low Bandwidth**
   - Header mode: ~500 bps
   - Temporal mode: ~3 bps
   - Unsuitable for large file transfer

2. **Packet Loss Sensitivity**
   - No error correction implemented
   - Lost packets corrupt frame
   - Requires reliable local network

3. **Network Jitter**
   - Temporal mode affected by network variability
   - Threshold tuning required per network
   - Long-distance links problematic

4. **Synchronization**
   - Receiver must start before sender
   - No handshake protocol
   - Manual mode configuration required

5. **Platform Dependencies**
   - Requires raw socket privileges
   - Interface naming varies by OS
   - Firewall may block ICMP

6. **Detection Risk**
   - Unusual ICMP patterns
   - Statistical anomalies
   - Timing correlations

### Scope Limitations

1. **Localhost/Lab Only**
   - Designed for controlled environments
   - Not tested against enterprise security
   - No real-world firewall/IDS evasion

2. **Single Carrier Protocol**
   - ICMP only (IPv4)
   - No TCP/UDP/DNS channels implemented
   - Protocol diversity not supported

3. **No Adaptive Behavior**
   - Static timing profiles
   - No runtime channel switching
   - No automatic parameter optimization

4. **Security Assumptions**
   - Pre-shared key distribution not addressed
   - No forward secrecy
   - No anti-replay protection

## Future Enhancements

### Potential Improvements

1. **Additional Covert Channels**
   - TCP sequence numbers
   - DNS subdomain encoding
   - HTTP header fields
   - IPv6 flow labels

2. **Error Correction**
   - Forward error correction (FEC)
   - Packet retransmission
   - Reed-Solomon codes
   - CRC checksums per chunk

3. **Advanced ML Techniques**
   - Deep learning timing models (LSTM)
   - Adversarial training for undetectability
   - Real-time adaptive profiling
   - Multi-protocol traffic modeling

4. **Robustness**
   - Automatic synchronization
   - Dynamic threshold adjustment
   - Packet reordering tolerance
   - Missing packet interpolation

5. **Performance**
   - Parallel channels
   - Adaptive rate control
   - Compression before encryption
   - Optimized timing parameters

6. **Security**
   - Key exchange protocol (Diffie-Hellman)
   - Perfect forward secrecy
   - Anti-replay nonces
   - Steganographic key derivation

7. **Detection & Defense**
   - Covert channel detector
   - Statistical anomaly detection
   - Timing pattern analysis
   - Countermeasure research

8. **Usability**
   - Auto-discovery of receiver
   - GUI configuration
   - Mobile app support
   - Cloud deployment

## Ethical Considerations

### Academic Purpose

This project is designed for **educational purposes only** to demonstrate:
- Network security concepts
- Covert channel mechanisms
- Cryptography applications
- Machine learning in security

### Responsible Use

**Authorized Use Only:**
- Controlled laboratory environments
- Networks you own or have permission to test
- Academic research and learning
- Security auditing with authorization

**Prohibited Use:**
- Unauthorized network access
- Malicious data exfiltration
- Privacy violations
- Illegal surveillance
- Any unlawful activities

### Legal Warning

Unauthorized interception or disruption of network communications may violate:
- Computer Fraud and Abuse Act (USA)
- Computer Misuse Act (UK)
- Similar laws in other jurisdictions

**Always obtain proper authorization before testing on any network.**

### Detection & Defense

Organizations should be aware of covert channel risks:
- Implement network monitoring
- Use statistical traffic analysis
- Deploy intrusion detection systems
- Establish security policies
- Conduct regular security audits

## References

1. **Network Steganography**
   - Wendzel, S., et al. "Hidden and Uncontrolled—On the Emergence of Network Steganographic Threats" (2014)
   - Zander, S., et al. "A survey of covert channels and countermeasures in computer network protocols" (2007)

2. **Covert Timing Channels**
   - Cabuk, S., et al. "IP covert timing channels: design and detection" (2004)
   - Shah, G., et al. "Keyboards and covert channels" (2006)

3. **Cryptography**
   - NIST SP 800-38D: "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)"
   - PKCS #5: Password-Based Cryptography Specification

4. **Machine Learning**
   - Bishop, C. M. "Pattern Recognition and Machine Learning" (2006)
   - Scikit-learn documentation: Gaussian Mixture Models

## Contributors

- **Developer**: [Your Name]
- **Course**: Computer Network Technology (CNT)
- **Institution**: [Your Institution]
- **Academic Year**: [Year]

## License

This project is developed for academic purposes. Use responsibly and ethically.

---

**NETGHOST** - Demonstrating Network Steganography for Security Education
