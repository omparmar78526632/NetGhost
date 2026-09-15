# NetGhost Protocol Specification

## Overview

This document provides detailed specification of the NetGhost covert channel protocols, frame format, and implementation details.

## Encryption Layer

### Algorithm
**AES-256-GCM** (Galois/Counter Mode)

### Key Derivation

**Algorithm**: PBKDF2-HMAC-SHA256

**Parameters**:
- Iterations: 100,000
- Salt: 16 bytes (random)
- Output key length: 32 bytes (256 bits)
- Hash function: SHA-256

**Process**:
```
passphrase (UTF-8) + salt → PBKDF2-HMAC-SHA256 → key (32 bytes)
```

### Encryption Format

**Structure**:
```
┌──────────────┬──────────────┬─────────────────┬──────────────┐
│    Salt      │    Nonce     │   Ciphertext    │   Auth Tag   │
│  16 bytes    │  12 bytes    │   N bytes       │  16 bytes    │
└──────────────┴──────────────┴─────────────────┴──────────────┘
```

**Field Descriptions**:
- **Salt**: Random 16-byte value for key derivation
- **Nonce**: Random 12-byte value for GCM (must be unique per encryption)
- **Ciphertext**: AES-GCM encrypted plaintext
- **Auth Tag**: 16-byte authentication tag (computed by GCM)

**Total Overhead**: 44 bytes + ciphertext length

### Encryption Process

```
Input: plaintext, passphrase
1. Generate random salt (16 bytes)
2. Derive key from passphrase and salt using PBKDF2
3. Generate random nonce (12 bytes)
4. Encrypt plaintext with AES-256-GCM(key, nonce)
5. Output: salt || nonce || ciphertext || tag
```

### Decryption Process

```
Input: encrypted_payload, passphrase
1. Extract salt (first 16 bytes)
2. Extract nonce (next 12 bytes)
3. Extract ciphertext + tag (remaining bytes)
4. Derive key from passphrase and salt
5. Decrypt and verify with AES-256-GCM(key, nonce)
6. If authentication succeeds: output plaintext
7. If authentication fails: raise ValueError
```

## Framing Layer

### Frame Format

```
┌────────────────────┬────────────────────┬─────────────────────────┐
│   Sync Marker      │  Payload Length    │   Encrypted Payload     │
│   2 bytes          │  2 bytes           │   N bytes               │
│   0xDEAD           │  Big-endian uint16 │   AES-GCM output        │
└────────────────────┴────────────────────┴─────────────────────────┘
```

### Field Specifications

**Sync Marker**:
- Value: 0xDEAD
- Size: 2 bytes
- Encoding: Big-endian (network byte order)
- Purpose: Frame synchronization and detection

**Payload Length**:
- Type: Unsigned 16-bit integer
- Size: 2 bytes
- Encoding: Big-endian
- Range: 0 - 65,535 bytes
- Value: Length of encrypted payload in bytes

**Encrypted Payload**:
- Content: Output of AES-256-GCM encryption
- Size: Variable (0 - 65,535 bytes)
- Structure: salt || nonce || ciphertext || tag

### Frame Creation

```python
def create_frame(payload: bytes) -> bytes:
    sync = 0xDEAD.to_bytes(2, 'big')
    length = len(payload).to_bytes(2, 'big')
    return sync + length + payload
```

### Frame Parsing

```python
def parse_frame(data: bytes) -> (bytes, int):
    # Search for sync marker
    for i in range(len(data) - 1):
        if data[i:i+2] == b'\xDE\xAD':
            # Found sync
            if len(data) >= i + 4:
                length = int.from_bytes(data[i+2:i+4], 'big')
                if len(data) >= i + 4 + length:
                    payload = data[i+4:i+4+length]
                    return payload, i + 4 + length
    return None, 0
```

## Header Field Channel Protocol

### Overview

Embeds data in IPv4 Identification field (16 bits per packet).

### Packet Structure

```
IPv4 Header:
┌──────────────────────────────────────────────────────────┐
│ Version | IHL | DSCP | ECN | Total Length                │
│ Identification (16 bits) ← DATA EMBEDDED HERE            │
│ Flags | Fragment Offset                                   │
│ TTL | Protocol | Header Checksum                          │
│ Source IP Address                                         │
│ Destination IP Address                                    │
└──────────────────────────────────────────────────────────┘

ICMP Header:
┌──────────────────────────────────────────────────────────┐
│ Type (8) | Code (0) | Checksum                           │
│ Identifier | Sequence Number                             │
└──────────────────────────────────────────────────────────┘
```

### Encoding Algorithm

```
Input: frame (bytes)
1. If frame length is odd, append 0x00 byte
2. Split frame into 16-bit chunks:
   chunks = [frame[i:i+2] for i in range(0, len(frame), 2)]
3. Convert each chunk to uint16 (big-endian)
4. For each chunk with index i:
   a. Create packet: IP(dst=target, id=chunk) / ICMP(seq=i)
   b. Send packet
   c. Wait 10 ms
5. Complete
```

### Decoding Algorithm

```
Input: ICMP packets (captured)
1. Initialize: uint16_list = []
2. For each ICMP Echo Request packet:
   a. Extract IP.id value
   b. Append to uint16_list
3. Convert uint16_list to bytes (big-endian)
4. Parse frame from bytes
5. If frame valid:
   a. Extract encrypted payload
   b. Decrypt payload
   c. Output plaintext
6. Else: continue receiving
```

### Capacity and Throughput

**Capacity**: 16 bits per packet

**Throughput Calculation**:
```
If packet rate = R packets/second
Throughput (bps) = R × 16

Example:
R = 30 pps (limited by ICMP rate limiting)
Throughput = 30 × 16 = 480 bps
```

**Frame Transmission Time**:
```
Frame size = 4 + encrypted_length bytes
Chunks = ceil(frame_size / 2)
Packets = Chunks
Time = Packets × (1/R + delay)
```

## Temporal IPD Channel Protocol

### Overview

Encodes data in inter-packet delay timing (1 bit per packet).

### Bit Encoding

**Mapping**:
- Bit **0** → Short delay (configurable, default 50 ms)
- Bit **1** → Long delay (configurable, default 100 ms)

**Timing Profiles**:

1. **Constant**:
   ```python
   delay = bit_0_delay if bit == 0 else bit_1_delay
   ```

2. **Normal (Gaussian)**:
   ```python
   target = bit_0_delay if bit == 0 else bit_1_delay
   jitter = random.normal(0, target * 0.1)
   delay = max(0.001, target + jitter)
   ```

3. **Gamma**:
   ```python
   target = bit_0_delay if bit == 0 else bit_1_delay
   shape = 2.0
   scale = target / shape
   delay = max(0.001, random.gamma(shape, scale))
   ```

4. **GMM**:
   ```python
   delay = max(0.001, gmm.sample()[0][0] / 1000.0)
   ```

### Encoding Algorithm

```
Input: frame (bytes), bit_0_delay, bit_1_delay, profile
1. Convert frame to bit array (MSB first)
2. For each bit with index i:
   a. Determine delay based on bit value and profile
   b. If i > 0: wait(delay)
   c. timestamp = current_time()
   d. Create packet: IP(dst=target) / ICMP(seq=i)
   e. Send packet
   f. Log: bit, delay, timestamp
3. Complete
```

### Decoding Algorithm

```
Input: threshold (milliseconds)
1. Initialize: timestamps = [], bits = []
2. For each ICMP Echo Request packet:
   a. Record timestamp
   b. If len(timestamps) > 1:
      - delta = (timestamps[-1] - timestamps[-2]) × 1000
      - bit = 0 if delta < threshold else 1
      - Append bit to bits
3. Convert bits to bytes
4. Parse frame from bytes
5. If frame valid:
   a. Decrypt payload
   b. Output plaintext
6. Else: continue receiving
```

### Threshold Selection

**Midpoint Method**:
```
threshold = (bit_0_delay + bit_1_delay) / 2
```

**Example**:
- bit_0_delay = 50 ms
- bit_1_delay = 100 ms
- threshold = 75 ms

**Optimal Threshold** (if delay distributions known):
```
Minimize: P(error) = P(0→1) + P(1→0)

Where:
P(0→1) = P(delay_0 ≥ threshold)
P(1→0) = P(delay_1 < threshold)
```

### Capacity and Throughput

**Capacity**: 1 bit per packet

**Throughput Calculation**:
```
Average delay = (bit_0_delay + bit_1_delay) / 2
Throughput (bps) = 1 / average_delay

Example:
bit_0_delay = 50 ms, bit_1_delay = 100 ms
Average = 75 ms
Throughput = 1 / 0.075 = 13.3 bps (maximum)

Actual throughput ≈ 3 bps (accounting for overhead)
```

**Frame Transmission Time**:
```
Frame size = 4 + encrypted_length bytes
Bits = frame_size × 8
Average delay = (bit_0_delay + bit_1_delay) / 2
Time = Bits × average_delay
```

## Packet Format Details

### ICMP Echo Request

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
┌───────────────────┬───────────────────┬───────────────────────┐
│  Type (8)         │  Code (0)         │  Checksum             │
├───────────────────┴───────────────────┴───────────────────────┤
│  Identifier                           │  Sequence Number      │
└───────────────────────────────────────┴───────────────────────┘

Type: 8 (Echo Request)
Code: 0
Identifier: Random
Sequence Number: Packet index
```

### IPv4 Header (relevant fields)

```
┌───────────────────────────────────────────────────────────────┐
│  Identification (16 bits) ← Embedded Data (Header Channel)    │
└───────────────────────────────────────────────────────────────┘

Identification: 0x0000 - 0xFFFF
Purpose (Original): Fragment reassembly
Purpose (NetGhost): Data embedding
```

## Error Handling

### Encryption Errors

| Error | Cause | Action |
|-------|-------|--------|
| Authentication failed | Wrong password or tampering | Reject, log error |
| Invalid payload format | Corrupted data | Reject, log error |
| Payload too short | Truncated transmission | Reject, log error |

### Framing Errors

| Error | Cause | Action |
|-------|-------|--------|
| No sync marker | Random data or not yet arrived | Continue receiving |
| Invalid length | Corruption or false sync | Skip, continue search |
| Incomplete frame | Partial transmission | Wait for more data |

### Network Errors

| Error | Cause | Action |
|-------|-------|--------|
| Permission denied | No raw socket privilege | Exit with error message |
| Timeout | No packets received | Stop listening |
| Interface not found | Invalid interface name | Use default or prompt |

## Security Properties

### Confidentiality
- **Provided by**: AES-256-GCM encryption
- **Key strength**: 256 bits
- **Attack resistance**: Brute force infeasible (2^256 operations)

### Integrity
- **Provided by**: GCM authentication tag
- **Tag length**: 128 bits
- **Attack resistance**: Tag forgery probability ≤ 2^-128

### Authentication
- **Provided by**: Pre-shared key + GCM tag
- **Limitation**: No protection against key sharing
- **Future**: Could add Diffie-Hellman key exchange

### Covertness
- **Header Channel**: Uses normal protocol field
- **Temporal Channel**: Mimics network jitter
- **Detection risk**: Statistical analysis, traffic shaping detection
- **Mitigation**: GMM-based timing, traffic normalization

## Protocol Limitations

### Maximum Message Size
- Frame payload limit: 65,535 bytes
- Practical limit: ~1 KB (considering transmission time)
- Workaround: Message fragmentation (not implemented)

### Packet Loss
- **Impact**: Frame corruption, decryption failure
- **Mitigation**: None (no error correction)
- **Future**: Implement FEC or ARQ

### Network Jitter
- **Impact**: Bit errors in temporal channel
- **Mitigation**: Wider delay separation, adaptive threshold
- **Measurement**: BER increases with jitter variance

### Synchronization
- **Current**: Manual configuration (start receiver first)
- **Limitation**: No automatic handshake
- **Future**: Implement connection establishment protocol

## Performance Metrics

### Header Channel
- **Capacity**: 16 bps/packet
- **Throughput**: 480-500 bps
- **Latency**: ~1-2 seconds for 100-byte message
- **Overhead**: 44 bytes (encryption) + 4 bytes (frame) = 48 bytes

### Temporal Channel
- **Capacity**: 1 bps/packet  
- **Throughput**: 3-13 bps (depends on delay values)
- **Latency**: ~30 seconds for 100-bit message (50/100 ms delays)
- **Overhead**: Same as header + timing delay

## Implementation Notes

### Platform Compatibility

**Linux**:
- Interface: "lo" (loopback) or "eth0", "wlan0"
- Privileges: sudo required for raw sockets

**macOS**:
- Interface: "lo0" or "en0"
- Privileges: sudo required

**Windows**:
- Interface: "Loopback" or adapter name
- Privileges: Run as Administrator
- Requirement: Npcap installed

### Timing Accuracy

**Factors Affecting Timing**:
- Python GIL (Global Interpreter Lock)
- OS scheduler preemption
- Network stack processing
- Timer resolution (typically ~1 ms)

**Measured Accuracy**:
- Constant profile: ±2 ms standard deviation
- Normal profile: ±5 ms standard deviation
- GMM profile: Varies with model

### Packet Rate Limiting

**ICMP Rate Limits**:
- Linux: Typically 1000 pps (configurable via sysctl)
- Windows: Lower limits in firewall
- Routers: Often rate-limit ICMP to prevent floods

**Impact**:
- Header channel: Limits throughput
- Temporal channel: Adds additional delay

## Future Protocol Extensions

### Version 2.0 Proposed Features
1. **Multi-channel**: Combine header + temporal
2. **Forward error correction**: Reed-Solomon codes
3. **Adaptive thresholds**: Learn from network conditions
4. **Handshake protocol**: Automatic synchronization
5. **Channel negotiation**: Select best channel dynamically
6. **Fragmentation support**: Large message handling
7. **Sequence numbers**: Packet reordering tolerance
8. **Acknowledgments**: Reliable delivery with ARQ

### Alternative Protocols
- TCP sequence number steganography
- DNS subdomain encoding
- HTTP header/cookie embedding
- TLS timing channels
- IPv6 flow label embedding
