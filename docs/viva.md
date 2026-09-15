# NetGhost Viva Questions and Answers

## Project Overview Questions

### Q1: What is NetGhost?
**A:** NetGhost is a network steganography demonstration system that implements covert data transfer using ICMP packets. It shows how encrypted information can be hidden in network traffic using two techniques: IPv4 header field embedding and temporal inter-packet delay encoding.

### Q2: What is the main purpose of this project?
**A:** The project demonstrates covert channels in network protocols for educational purposes. It shows security implications of network steganography and combines concepts from networking, cryptography, and machine learning to create undetectable communication channels.

### Q3: What are the two covert channels you implemented?
**A:** 
1. **Header Field Channel**: Embeds 16 bits per packet in the IPv4 Identification (IP.id) field
2. **Temporal IPD Channel**: Encodes 1 bit per packet using inter-packet delay timing

## Technical Questions

### Q4: Why did you choose ICMP as the carrier protocol?
**A:** ICMP (Internet Control Message Protocol) was chosen because:
- It's commonly allowed through firewalls for diagnostic purposes
- ICMP Echo Requests (ping) are normal network traffic
- IP.id field is available for embedding data
- Timing between packets appears as natural network latency
- Simple protocol without complex handshakes

### Q5: Explain the AES-256-GCM encryption process.
**A:** 
- User provides a passphrase (PSK)
- PBKDF2-HMAC-SHA256 derives a 256-bit key (100,000 iterations)
- A random 12-byte nonce is generated
- AES-256-GCM encrypts the message with the key and nonce
- Output includes ciphertext + 16-byte authentication tag
- This provides confidentiality, integrity, and authentication

### Q6: What is the frame structure?
**A:**
```
+----------------+----------------+----------------------+
| Sync Marker    | Payload Length | Encrypted Payload    |
| 0xDEAD (2B)    | uint16 (2B)    | N bytes              |
+----------------+----------------+----------------------+
```
- Sync marker (0xDEAD) helps detect frame start
- Length field specifies payload size
- Encrypted payload contains AES-256-GCM output

### Q7: How does header field steganography work?
**A:**
1. Message is encrypted and framed
2. Frame bytes are split into 16-bit chunks
3. Each chunk is embedded in the IP.id field of an ICMP packet
4. Packets are sent sequentially
5. Receiver extracts IP.id values and reconstructs the frame
6. Frame is parsed and payload is decrypted

**Capacity**: 16 bits per packet (~500 bps throughput)

### Q8: How does temporal steganography work?
**A:**
1. Message is encrypted, framed, and converted to bits
2. Each bit is encoded as a timing delay:
   - Bit 0 → short delay (e.g., 50 ms)
   - Bit 1 → long delay (e.g., 100 ms)
3. ICMP packets are sent with appropriate inter-packet delays
4. Receiver measures delays and classifies using threshold:
   - Delay < threshold → bit 0
   - Delay ≥ threshold → bit 1
5. Bits are reconstructed into frame and decrypted

**Capacity**: 1 bit per packet (~3 bps throughput)

### Q9: What is the purpose of the Gaussian Mixture Model?
**A:** The GMM models realistic network traffic timing patterns:
- Trained on baseline PCAP inter-arrival times
- Learns multimodal distribution of packet delays
- Generates realistic timing samples for temporal channel
- Makes covert timing harder to detect statistically
- Blends covert traffic with normal traffic patterns

### Q10: How is the GMM trained?
**A:**
1. Read PCAP file containing baseline traffic
2. Extract packet timestamps
3. Compute inter-arrival times (Δt between packets)
4. Clean data (remove outliers)
5. Fit Gaussian Mixture Model with 3 components
6. Save model using joblib
7. Load in sender to generate realistic delays

## Security Questions

### Q11: What attacks is your encryption resistant to?
**A:**
- Passive eavesdropping (data is encrypted)
- Tampering (authentication tag detects modifications)
- Wrong key attempts (decryption fails with clear error)
- Replay attacks (random nonce per message)

### Q12: What attacks can defeat your system?
**A:**
- **Traffic analysis**: Packet count reveals message length
- **Statistical detection**: Timing patterns may be detectable
- **Active normalization**: Firewalls may rewrite IP.id fields
- **Deep packet inspection**: Anomaly detection may flag unusual patterns
- **Correlation attacks**: Comparing sender and receiver traffic
- **Key compromise**: If PSK is leaked, all messages can be decrypted

### Q13: Why is PBKDF2 used for key derivation?
**A:** PBKDF2 (Password-Based Key Derivation Function 2):
- Converts variable-length passphrase to fixed 256-bit key
- Uses 100,000 iterations to slow down brute-force attacks
- Includes random salt to prevent rainbow table attacks
- Industry standard (NIST approved)
- Makes weak passwords more resistant to cracking

### Q14: What are the limitations of your system?
**A:**
- **Low bandwidth**: Header ~500 bps, Temporal ~3 bps
- **Packet loss**: Lost packets corrupt the message
- **Network jitter**: Affects temporal channel accuracy
- **Synchronization**: Manual configuration required
- **Detection risk**: Statistical analysis may reveal covert channel
- **No error correction**: Single bit error corrupts frame
- **Platform dependency**: Requires raw socket privileges

## Implementation Questions

### Q15: Why did you use Python and Scapy?
**A:**
- **Python**: Rapid development, excellent libraries, clear code
- **Scapy**: Powerful packet manipulation library
  - Easy packet crafting (IP/ICMP)
  - Built-in sniffing capabilities
  - Cross-platform support
  - Interactive packet inspection

### Q16: How does the receiver know when a message is complete?
**A:**
1. Receiver continuously captures packets
2. After each packet, attempts to parse frame
3. Searches for sync marker (0xDEAD)
4. Reads length field
5. Checks if enough data received
6. If complete, extracts payload and decrypts
7. Success indicates message is complete

### Q17: How are timing profiles different?
**A:**
- **Constant**: Fixed delays, most predictable, easiest to detect
- **Normal**: Adds Gaussian jitter, simulates measurement noise
- **Gamma**: Models network latency tail distribution
- **GMM**: Samples from trained model, most realistic, hardest to detect

### Q18: What happens if the wrong password is used?
**A:** AES-256-GCM authentication tag verification fails:
1. Receiver attempts decryption with wrong key
2. Authentication tag doesn't match
3. `cryptography` library raises exception
4. Error displayed: "Decryption failed: authentication failed"
5. No plaintext is revealed (secure failure)

## Networking Questions

### Q19: What is the IPv4 Identification field?
**A:** 
- 16-bit field in IPv4 header
- Originally used for fragment reassembly
- Unique identifier for fragmented packets from same source
- Often sequential or random in modern systems
- Our project embeds data in this field

### Q20: Why use ICMP Echo Request instead of Echo Reply?
**A:** 
- Echo Request (type 8) is sent by the covert sender
- More control over packet creation
- Echo Reply would require running a server
- Request is sufficient for localhost demonstration
- Both sender and receiver can send requests

### Q21: What is inter-packet delay (IPD)?
**A:** 
- Time interval between consecutive packets
- Measured as Δt = timestamp[i] - timestamp[i-1]
- Normal traffic has variable IPD due to processing, buffering
- Our system encodes bits by controlling IPD
- Receiver measures IPD to decode bits

## Machine Learning Questions

### Q22: Why use Gaussian Mixture Model instead of single Gaussian?
**A:**
- Network traffic is multimodal (different types of delays)
- Single Gaussian can't capture multiple patterns
- GMM combines multiple Gaussians with weights
- Better fits real traffic (fast, medium, slow packets)
- More flexible distribution modeling

### Q23: How many components did you use in GMM and why?
**A:** 3 components:
- Represents fast, medium, and slow packet patterns
- Balances model complexity and accuracy
- Prevents overfitting with too many components
- Sufficient to model typical network behavior
- Can be adjusted based on traffic characteristics

### Q24: What is the difference between training and inference?
**A:**
- **Training** (offline): 
  - Read PCAP file
  - Extract timing data
  - Fit GMM parameters
  - Save model
  
- **Inference** (real-time):
  - Load trained model
  - Sample random delay values
  - Use delays to send packets

## Web Application Questions

### Q25: Why did you use Flask for the web interface?
**A:**
- Lightweight Python web framework
- Easy to integrate with existing Python code
- Built-in development server
- Simple routing and templating
- SSE (Server-Sent Events) support for real-time updates

### Q26: How does the receiver UI update in real-time?
**A:** Using Server-Sent Events (SSE):
1. Receiver core calls status_callback() for each packet
2. Callback puts event in queue
3. Flask /stream endpoint yields events as SSE
4. Browser EventSource API receives events
5. JavaScript updates UI elements dynamically

### Q27: What information does the sender UI display?
**A:**
- Configuration: target IP, PSK, message, mode
- Timing parameters (for temporal mode)
- Transmission statistics:
  - Packets sent
  - Duration
  - Throughput (bps)
  - Bit count (temporal)
  - Frame size

## Testing Questions

### Q28: How did you test your project?
**A:**
- **Unit tests**: pytest for crypto, framing, encoding/decoding
- **Integration tests**: End-to-end sender → receiver
- **Wireshark verification**: Visual packet inspection
- **Performance tests**: Throughput and latency measurement
- **Error tests**: Wrong password, tampering, truncation

### Q29: What is the expected throughput for each mode?
**A:**
- **Header Mode**: ~500 bps (measured)
  - Limited by ICMP rate limiting
  - 16 bits per packet
  
- **Temporal Mode**: ~3 bps (measured)
  - Limited by delay values (50/100 ms)
  - 1 bit per packet
  - Could optimize to ~50 bps with 10/20 ms delays

### Q30: How did you verify correctness in Wireshark?
**A:**
**Header Mode**:
1. Filter: `icmp.type == 8`
2. Expand IPv4 header
3. Check Identification field values
4. Verify sequence: 0xDEAD, length, data...

**Temporal Mode**:
1. View → Time Display Format → Since Previous Packet
2. Observe time column
3. Verify pattern of short/long delays
4. Match delays to expected bit pattern

## Future Enhancement Questions

### Q31: What improvements would you make?
**A:**
- **Error correction**: Reed-Solomon or FEC codes
- **Additional protocols**: TCP sequence numbers, DNS, HTTP
- **Adaptive thresholds**: Dynamic adjustment based on network
- **Fragmentation**: Handle large messages automatically
- **Multi-channel**: Combine header + temporal simultaneously
- **Key exchange**: Diffie-Hellman instead of PSK
- **Detection tools**: Build covert channel detector

### Q32: How would you improve undetectability?
**A:**
- Use GMM trained on target network's actual traffic
- Randomize transmission schedule
- Add dummy packets (chaff) to obscure patterns
- Use dynamic channel switching
- Implement traffic normalization resistance
- Match statistical properties of normal traffic more closely

### Q33: What are the ethical implications?
**A:**
- **Legitimate uses**: Censorship circumvention, privacy protection
- **Malicious uses**: Data exfiltration, C&C communication
- **Responsibility**: Only use on authorized networks
- **Education**: Understanding threats helps build defenses
- **Legal**: Unauthorized interception may violate laws
- **Defense**: Organizations should deploy covert channel detection

## Demonstration Questions

### Q34: Can you demonstrate the header mode?
**A:** [Live demonstration]
1. Start receiver (port 5001)
2. Start sender (port 5000)
3. Enter matching PSKs
4. Send short message
5. Show packets captured
6. Show decoded message
7. Show Wireshark IP.id values

### Q35: Can you demonstrate the temporal mode?
**A:** [Live demonstration]
1. Configure receiver with threshold
2. Select temporal mode in sender
3. Send very short message ("Hi")
4. Show inter-packet delays in receiver log
5. Show bit classification
6. Show decoded message
7. Show Wireshark timing pattern

## Comparison Questions

### Q36: Header vs Temporal - which is better?
**A:**
| Aspect | Header | Temporal |
|--------|--------|----------|
| Throughput | Higher (~500 bps) | Lower (~3 bps) |
| Detectability | Medium | Medium-Low |
| Implementation | Simpler | More complex |
| Robustness | Higher | Lower (jitter sensitive) |
| Stealthiness | Moderate | Better with GMM |

**Choice depends on**: Throughput needs, network conditions, detection risk

### Q37: How does your project compare to commercial steganography tools?
**A:**
- **Scope**: Educational demonstration vs production tool
- **Protocols**: ICMP only vs multiple protocols
- **Features**: Basic vs advanced (error correction, adaptive)
- **Performance**: Lower throughput
- **Robustness**: Less resilient to packet loss
- **Purpose**: Learning tool vs operational system

## Closing Questions

### Q38: What did you learn from this project?
**A:**
- Deep understanding of network protocols (IPv4, ICMP)
- Practical cryptography implementation (AES-GCM, key derivation)
- Packet-level programming with Scapy
- Machine learning for traffic modeling
- Web application development with Flask
- System integration and testing
- Security implications of covert channels

### Q39: What was the most challenging part?
**A:**
- Timing accuracy in temporal channel
- Handling network jitter and synchronization
- Debugging packet capture issues
- Ensuring cryptographic correctness
- Creating realistic ML timing model
- Making UI responsive with real-time updates

### Q40: What is the key takeaway from NetGhost?
**A:** Network steganography demonstrates that communication security requires more than just encryption. Even with strong encryption, metadata (packet timing, sizes, patterns) can be exploited for covert communication. Organizations must deploy multi-layered defenses including traffic analysis, anomaly detection, and behavioral monitoring to detect covert channels. This project shows both the offensive capability and the need for defensive awareness.
