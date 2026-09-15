# NetGhost Testing Guide

## Overview

This document describes the testing strategy, test execution, and validation procedures for the NetGhost project.

## Test Structure

### Unit Tests
Located in `tests/` directory:
- `test_crypto.py` - Cryptography module tests
- `test_framing.py` - Frame protocol tests
- `test_header_channel.py` - Header field encoding/decoding tests
- `test_temporal_channel.py` - Temporal IPD encoding/decoding tests
- `test_ml.py` - Machine learning profiler tests

### Test Framework
- **Framework**: pytest
- **Coverage Tool**: pytest-cov
- **Assertions**: Standard pytest assertions

## Running Tests

### Install Test Dependencies
```bash
pip install pytest pytest-cov
```

### Run All Tests
```bash
# From NetGhost/ directory
pytest

# With verbose output
pytest -v

# With coverage report
pytest --cov=common --cov=sender --cov=receiver --cov=ml

# Run specific test file
pytest tests/test_crypto.py
```

### Run Individual Test
```bash
pytest tests/test_crypto.py::TestCrypto::test_encryption_decryption_round_trip -v
```

## Test Coverage

### Cryptography Tests (test_crypto.py)

**Coverage**:
- ✅ Key derivation (PBKDF2)
- ✅ Encryption/decryption round trip
- ✅ Wrong password detection
- ✅ Tampering detection
- ✅ Short messages
- ✅ Long messages
- ✅ Empty messages
- ✅ Special characters
- ✅ Unicode messages
- ✅ Nonce uniqueness
- ✅ Invalid payload handling

**Expected Results**: All tests should pass

### Framing Tests (test_framing.py)

**Coverage**:
- ✅ Frame creation with normal payload
- ✅ Empty payload handling
- ✅ Large payload handling
- ✅ Oversized payload rejection
- ✅ Frame parsing
- ✅ Frame with garbage prefix
- ✅ Incomplete frame handling
- ✅ Missing sync marker
- ✅ Odd-length payloads
- ✅ Round-trip integrity
- ✅ Sync marker detection
- ✅ Multiple consecutive frames

**Expected Results**: All tests should pass

### Header Channel Tests (test_header_channel.py)

**Coverage**:
- ✅ Bytes to uint16 conversion
- ✅ Uint16 to bytes conversion
- ✅ Round-trip conversion
- ✅ Odd-length padding
- ✅ End-to-end simulation
- ✅ Short messages
- ✅ Long messages
- ✅ Binary data

**Expected Results**: All tests should pass

### Temporal Channel Tests (test_temporal_channel.py)

**Coverage**:
- ✅ Bytes to bits conversion
- ✅ Bits to bytes conversion
- ✅ Round-trip bit conversion
- ✅ Bit padding
- ✅ End-to-end simulation
- ✅ Threshold classification
- ✅ Jitter tolerance
- ✅ Timing sequences
- ✅ All zeros/ones
- ✅ Bit count validation

**Expected Results**: All tests should pass

### ML Tests (test_ml.py)

**Coverage**:
- ✅ Timing data cleaning
- ✅ GMM training
- ✅ Sample generation
- ✅ Model statistics extraction
- ✅ Model save/load
- ✅ Multimodal distribution
- ✅ Sample statistics validation

**Expected Results**: All tests should pass (may have minor warnings about convergence)

## Integration Testing

### End-to-End Test: Header Mode

**Setup**:
1. Terminal 1: Start receiver
   ```bash
   sudo python receiver/receiver_app.py
   ```

2. Terminal 2: Start sender (requires admin/root)
   ```bash
   sudo python sender/sender_app.py
   ```

3. Browser: Open sender at http://127.0.0.1:5000
4. Browser: Open receiver at http://127.0.0.1:5001

**Test Procedure**:
1. In receiver UI:
   - Enter PSK: "test123"
   - Select mode: Header Field Embedding
   - Click "Start Listening"

2. In sender UI:
   - Enter PSK: "test123"
   - Enter message: "Hello from NetGhost CNT Project"
   - Select mode: Header Field Embedding
   - Click "Send Message"

3. Verify in receiver UI:
   - Packets captured
   - Sync marker detected
   - Frame extracted
   - Decryption successful
   - Message displayed: "Hello from NetGhost CNT Project"

**Expected Results**:
- Transmission completes in < 2 seconds
- All packets received
- Message decoded correctly
- No errors

### End-to-End Test: Temporal Mode (Constant)

**Test Procedure**:
1. In receiver UI:
   - Enter PSK: "test123"
   - Select mode: Temporal IPD
   - Set threshold: 75 ms
   - Click "Start Listening"

2. In sender UI:
   - Enter PSK: "test123"
   - Enter message: "Hi"
   - Select mode: Temporal IPD
   - Timing profile: Constant
   - Bit 0 delay: 50 ms
   - Bit 1 delay: 100 ms
   - Click "Send Message"

3. Verify:
   - Inter-packet delays captured
   - Bits decoded correctly
   - Message recovered

**Expected Results**:
- Longer transmission time (30-60 seconds for short message)
- Delays match expected pattern
- Message decoded correctly

### End-to-End Test: Temporal Mode with GMM

**Prerequisites**:
1. Train GMM model:
   ```bash
   python ml/train_model.py --create-synthetic
   ```

**Test Procedure**:
1. Follow same steps as constant mode
2. In sender, select timing profile: GMM / ML Model
3. Send message

**Expected Results**:
- Variable delays based on GMM
- Message decoded correctly
- Timing matches baseline traffic characteristics

## Wireshark Verification

### Capture ICMP Traffic

**Setup**:
1. Start Wireshark
2. Capture on loopback interface (lo or Loopback)
3. Apply filter: `icmp.type == 8`

### Verify Header Mode

**What to Look For**:
1. ICMP Echo Request packets
2. IPv4 → Identification field
3. Sequence of IP.id values:
   - First packet: 0xDEAD (sync marker)
   - Second packet: length value
   - Subsequent packets: encrypted data

**Verification Steps**:
1. Right-click packet → Follow → UDP Stream (or manually inspect)
2. Expand "Internet Protocol Version 4"
3. Check "Identification: 0x...." field
4. Record sequence of values
5. Convert to hex and verify matches frame

### Verify Temporal Mode

**What to Look For**:
1. ICMP Echo Request packets
2. Time column: "Time since previous displayed packet"
3. Pattern of short (~50 ms) and long (~100 ms) delays

**Verification Steps**:
1. View → Time Display Format → Seconds Since Previous Displayed Packet
2. Observe "Time" column
3. Record pattern of delays
4. Classify: <75ms = 0, ≥75ms = 1
5. Reconstruct bit stream
6. Verify matches expected message

### Export for Analysis

**Export Packet Details**:
1. File → Export Packet Dissections → As CSV
2. Select columns: No., Time, Source, Destination, Protocol, Info, IP ID
3. Analyze in spreadsheet or Python

**Export PCAP**:
1. File → Save As
2. Use for ML model training or offline analysis

## Performance Testing

### Throughput Measurement

**Header Mode**:
```python
# Expected throughput: ~500 bps
# Test with various message sizes: 10B, 50B, 100B, 500B, 1KB
```

**Temporal Mode**:
```python
# Expected throughput: ~3 bps (with 50/100 ms delays)
# Test with short messages only (long messages take too long)
```

### Latency Measurement

Measure end-to-end time from "Send" click to "Message Decoded".

### Accuracy Measurement

**Temporal Mode Bit Error Rate**:
```
BER = (Incorrect bits) / (Total bits)
```

Expected BER over localhost: 0% (no errors)

## Stress Testing

### Large Message Test
```python
# Test maximum practical message size
# Header mode: up to 1 KB
# Temporal mode: up to 100 bytes
```

### Rapid Successive Transmissions
```python
# Send multiple messages in quick succession
# Verify no mixing/corruption
```

### Network Condition Simulation
```python
# Use tc (traffic control) on Linux to add:
# - Latency: tc qdisc add dev lo root netem delay 50ms
# - Jitter: tc qdisc add dev lo root netem delay 50ms 20ms
# - Loss: tc qdisc add dev lo root netem loss 5%
```

## Error Handling Tests

### Wrong Passphrase
- Sender PSK: "correct"
- Receiver PSK: "wrong"
- Expected: Decryption fails with clear error

### Truncated Transmission
- Stop sender mid-transmission
- Expected: Receiver waits, then times out

### No Receiver Running
- Send without receiver
- Expected: Packets sent, no errors (fire-and-forget)

### Interference Traffic
- Generate unrelated ICMP traffic
- Expected: Receiver filters, continues listening

## Test Automation

### Continuous Integration (Optional)

**.github/workflows/test.yml** (if using GitHub):
```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.8'
      - run: pip install -r requirements.txt
      - run: pytest --cov
```

### Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/bash
pytest tests/
if [ $? -ne 0 ]; then
    echo "Tests failed. Commit aborted."
    exit 1
fi
```

## Troubleshooting Test Failures

### Common Issues

**1. Permission Errors**
```
Solution: Run with sudo/administrator privileges
```

**2. Import Errors**
```
Solution: Ensure PYTHONPATH includes project root
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

**3. Scapy Errors**
```
Solution: Install libpcap/WinPcap
Linux: sudo apt-get install libpcap-dev
Windows: Install Npcap
```

**4. Timeout in Integration Tests**
```
Solution: Check firewall, increase timeout values
```

## Test Checklist

Before declaring project complete:

- [ ] All unit tests pass
- [ ] End-to-end header mode test successful
- [ ] End-to-end temporal mode test successful
- [ ] GMM model trains without errors
- [ ] Wireshark verification shows correct IP.id values
- [ ] Wireshark verification shows correct timing pattern
- [ ] Wrong password properly rejected
- [ ] Tampering properly detected
- [ ] UI responsive and displays correct information
- [ ] Logs are clear and informative

## Test Results Template

```
Test Date: YYYY-MM-DD
Environment: OS, Python version
Tester: Name

Unit Tests:
- Crypto: [PASS/FAIL]
- Framing: [PASS/FAIL]
- Header Channel: [PASS/FAIL]
- Temporal Channel: [PASS/FAIL]
- ML: [PASS/FAIL]

Integration Tests:
- Header Mode E2E: [PASS/FAIL]
  - Message: "..."
  - Packets: X
  - Time: Y seconds
  - Throughput: Z bps
  
- Temporal Mode E2E: [PASS/FAIL]
  - Message: "..."
  - Packets: X
  - Time: Y seconds
  - BER: 0%

Wireshark Verification:
- Header IP.id sequence: [VERIFIED/FAILED]
- Temporal timing pattern: [VERIFIED/FAILED]

Issues Found: None / [List issues]

Overall: [PASS/FAIL]
```
