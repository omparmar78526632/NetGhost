# NetGhost System Architecture

## Overview

NetGhost is a network steganography system that demonstrates covert data transfer through ICMP packets using two distinct channels:

1. **Header Field Steganography** - Embeds data in IPv4 Identification field
2. **Temporal IPD Steganography** - Encodes data in packet timing intervals

## System Components

### 1. Common Modules

#### Cryptography Module (`common/crypto.py`)
- **Purpose**: Provides AES-256-GCM authenticated encryption
- **Key Features**:
  - PBKDF2-HMAC-SHA256 key derivation with 100,000 iterations
  - Random 12-byte nonce per encryption
  - 16-byte authentication tag
  - Protection against tampering and wrong-key attempts

**Encryption Flow**:
```
User PSK → PBKDF2 → 32-byte Key → AES-256-GCM → Encrypted + Tag
```

#### Framing Module (`common/framing.py`)
- **Purpose**: Provides message framing protocol
- **Frame Structure**:
```
+----------------+----------------+----------------------+
| Sync Marker    | Payload Length | Encrypted Payload    |
| 0xDEAD (2B)    | uint16 (2B)    | N bytes              |
+----------------+----------------+----------------------+
```

- **Features**:
  - Sync marker for frame detection
  - Length prefix for payload size
  - Maximum payload: 65,535 bytes
  - Robust parsing with garbage tolerance

#### Utilities Module (`common/utils.py`)
- Bit/byte conversion functions
- uint16 list conversion
- Hex dump formatting
- Support for MSB-first bit ordering

### 2. Sender Components

#### Sender Core (`sender/sender_core.py`)

**HeaderChannelSender**:
- Encrypts and frames message
- Splits into 16-bit chunks
- Embeds each chunk in IP.id field of ICMP Echo Request
- Sends packets sequentially with small delays

**TemporalChannelSender**:
- Encrypts and frames message
- Converts to bit stream
- Sends ICMP packets with timing-based encoding
- Supports multiple timing profiles:
  - Constant: Fixed delays
  - Normal: Gaussian jitter
  - Gamma: Network latency simulation
  - GMM: ML-based realistic timing

#### Sender Web Application (`sender/sender_app.py`)
- Flask-based web interface
- Configuration UI for target, PSK, mode selection
- Real-time transmission statistics
- GMM model integration

### 3. Receiver Components

#### Receiver Core (`receiver/receiver_core.py`)

**HeaderChannelReceiver**:
- Captures ICMP Echo Request packets
- Extracts IP.id values
- Reconstructs byte stream
- Parses frame and decrypts payload

**TemporalChannelReceiver**:
- Captures ICMP packets with timestamps
- Computes inter-packet delays
- Classifies bits using threshold
- Reconstructs frame and decrypts

#### Receiver Web Application (`receiver/receiver_app.py`)
- Flask-based web interface with Server-Sent Events
- Real-time packet capture display
- Live status updates
- Message display on successful decoding

### 4. Machine Learning Components

#### Traffic Profiler (`ml/ml_profiler.py`)
- **Purpose**: Model realistic network timing patterns
- **Process**:
  1. Extract inter-arrival times from PCAP
  2. Clean outliers
  3. Train Gaussian Mixture Model (3 components)
  4. Save model using joblib
  5. Generate realistic delay samples

**Training Script** (`ml/train_model.py`):
- Command-line tool for GMM training
- Supports synthetic or real PCAP input
- Reports detailed model statistics
- Saves trained model for sender use

## Data Flow

### Header Field Channel

```
SENDER:
Plaintext
  ↓
AES-256-GCM Encrypt
  ↓
Create Frame (SYNC + LEN + ENCRYPTED)
  ↓
Split into 16-bit chunks
  ↓
For each chunk:
  Create IP(id=chunk) / ICMP()
  Send packet
  
RECEIVER:
Capture ICMP packets
  ↓
Extract IP.id values
  ↓
Reconstruct byte stream
  ↓
Parse frame (find SYNC, extract length, get payload)
  ↓
AES-256-GCM Decrypt
  ↓
Original Plaintext
```

### Temporal IPD Channel

```
SENDER:
Plaintext
  ↓
AES-256-GCM Encrypt
  ↓
Create Frame
  ↓
Convert to bits
  ↓
For each bit:
  bit 0 → short delay (e.g., 50ms)
  bit 1 → long delay (e.g., 100ms)
  Wait delay
  Send ICMP packet
  
RECEIVER:
Capture ICMP packets + timestamps
  ↓
Compute inter-packet delays (Δt)
  ↓
For each Δt:
  Δt < threshold → bit 0
  Δt ≥ threshold → bit 1
  ↓
Reconstruct bit stream
  ↓
Convert bits to bytes
  ↓
Parse frame
  ↓
AES-256-GCM Decrypt
  ↓
Original Plaintext
```

## Network Protocol Stack

```
Application Layer:    NetGhost Sender/Receiver
                          ↓
Security Layer:       AES-256-GCM Encryption
                          ↓
Framing Layer:        SYNC + LENGTH + PAYLOAD
                          ↓
Encoding Layer:       Header (IP.id) or Temporal (IPD)
                          ↓
Network Layer:        IPv4
                          ↓
Transport Layer:      ICMP (Echo Request)
                          ↓
Link Layer:           Ethernet / Loopback
```

## Security Architecture

### Cryptographic Protection
- **Encryption**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: PBKDF2-HMAC-SHA256 (100k iterations)
- **Authentication**: 128-bit authentication tag
- **Nonce**: Random 96-bit nonce per message

### Threat Model
**Protected Against**:
- Passive eavesdropping (encryption)
- Tampering (authentication tag)
- Wrong key decryption attempts

**Not Protected Against**:
- Traffic analysis (packet count, timing patterns)
- Active normalization (IP.id rewriting)
- Statistical anomaly detection
- DPI with covert channel detection

## Timing Profiles

### 1. Constant Profile
- Fixed delays: bit 0 = 50ms, bit 1 = 100ms
- Most precise, lowest jitter
- Most detectable pattern

### 2. Normal Profile
- Gaussian jitter around target delays
- σ = 10% of target delay
- Simulates measurement noise

### 3. Gamma Profile
- Gamma distribution (shape=2, scale=delay/2)
- Models network latency tail distribution
- More realistic than Gaussian

### 4. GMM Profile
- Samples from trained Gaussian Mixture Model
- Matches baseline traffic statistics
- Best for undetectability
- Requires pre-training on PCAP

## Performance Characteristics

### Header Field Channel
- **Capacity**: 16 bits/packet
- **Throughput**: ~500 bps (limited by ICMP rate)
- **Latency**: Low (sequential transmission)
- **Robustness**: High (tolerates packet loss with sequence numbers)

### Temporal IPD Channel
- **Capacity**: 1 bit/packet
- **Throughput**: ~3 bps (dominated by delays)
- **Latency**: High (cumulative delays)
- **Robustness**: Medium (sensitive to jitter)

## Scalability Considerations

### Message Size Limits
- Frame payload: max 65,535 bytes
- Practical limit: ~1 KB for reasonable transmission time
- Large messages require proportionally more packets/time

### Transmission Time Estimates

**Header Mode** (500 bps):
- 100 bytes → ~1.6 seconds
- 1 KB → ~16 seconds

**Temporal Mode** (50ms/100ms delays, 3 bps):
- 100 bytes → ~4 minutes
- 1 KB → ~45 minutes

## Deployment Architecture

### Laboratory Setup
```
┌─────────────┐         Loopback         ┌─────────────┐
│   Sender    │◄────── Interface ───────►│  Receiver   │
│  (Port 5000)│       127.0.0.1          │ (Port 5001) │
└─────────────┘                          └─────────────┘
       │                                        │
       └───────────► ICMP Packets ─────────────┘
                   (IP.id or Timing)
```

### Network Setup
```
┌─────────┐      ┌────────┐      ┌─────────┐
│ Sender  │─────►│ Switch │─────►│Receiver │
│ Host A  │      │  /Hub  │      │ Host B  │
└─────────┘      └────────┘      └─────────┘
   
   Requirements:
   - Same subnet (for direct ICMP)
   - Sender needs raw socket privileges
   - Receiver needs promiscuous mode
```

## Technology Stack Summary

| Layer | Technology |
|-------|------------|
| Programming Language | Python 3.8+ |
| Web Framework | Flask |
| Packet Manipulation | Scapy |
| Cryptography | cryptography library |
| Machine Learning | scikit-learn |
| Model Persistence | joblib |
| Network Protocol | IPv4 + ICMP |
| Encryption | AES-256-GCM |
| Key Derivation | PBKDF2-HMAC-SHA256 |

## Extension Points

### Adding New Covert Channels
1. Implement encoder/decoder in sender_core.py / receiver_core.py
2. Add UI controls in sender.html / receiver.html
3. Add route handlers in Flask apps
4. Create unit tests

### Adding New Timing Profiles
1. Extend TemporalChannelSender.send_message()
2. Add profile selection in UI
3. Optionally train ML model on new distribution

### Multi-Protocol Support
- Abstract carrier protocol layer
- Implement TCP, UDP, DNS channel variants
- Unified API for different protocols
