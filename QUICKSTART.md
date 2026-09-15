# NetGhost - Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Prerequisites
- Python 3.8 or higher
- Administrator/root access (for packet capture)

---

## Step 1: Install Dependencies

```bash
# Navigate to project directory
cd NetGhost

# Create virtual environment
python -m venv .venv

# Activate it
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows

# Install packages
pip install -r requirements.txt
```

**Expected time**: 2 minutes

---

## Step 2: Verify Installation

```bash
python setup.py
```

This will:
- ✓ Check Python version
- ✓ Verify dependencies
- ✓ Test crypto module
- ✓ Test framing module
- ✓ Test ML module

**Expected output**: All checks should pass ✓

---

## Step 3: Train ML Model (Optional)

```bash
python ml/train_model.py --create-synthetic
```

This creates a timing model for the temporal channel.

**Expected time**: 10 seconds  
**Output**: `ml/models/gmm_timing.pkl`

---

## Step 4: Run Your First Demo

### Terminal 1 - Start Receiver

```bash
# Linux/macOS
sudo python receiver/receiver_app.py

# Windows (Run Command Prompt as Administrator)
python receiver/receiver_app.py
```

**Open browser**: http://127.0.0.1:5001

### Terminal 2 - Start Sender

```bash
# Linux/macOS
sudo python sender/sender_app.py

# Windows (Run Command Prompt as Administrator)
python sender/sender_app.py
```

**Open browser**: http://127.0.0.1:5000

---

## Step 5: Send Your First Covert Message

### In Receiver Browser (Port 5001):
1. Enter PSK: `demo123`
2. Select mode: `Header Field Embedding`
3. Click `Start Listening`

### In Sender Browser (Port 5000):
1. Target IP: `127.0.0.1` (default)
2. Enter PSK: `demo123` (must match receiver!)
3. Enter message: `Hello NetGhost!`
4. Select mode: `Header Field Embedding`
5. Click `Send Message`

### Expected Result:
- **Sender**: Shows ~25 packets sent in ~0.5 seconds
- **Receiver**: Displays live packet capture
- **Receiver**: Shows decoded message: `Hello NetGhost!`

🎉 **Success!** You just sent your first covert message!

---

## Understanding the Two Modes

### Mode 1: Header Field Embedding
- **How**: Embeds data in IPv4 Identification field
- **Speed**: ~500 bps (fast)
- **Capacity**: 16 bits per packet
- **Best for**: Moderate-length messages

**Try it**: Send a paragraph-long message

### Mode 2: Temporal IPD
- **How**: Encodes bits in packet timing delays
- **Speed**: ~3 bps (slow)
- **Capacity**: 1 bit per packet
- **Best for**: Very short messages

**Try it**: 
1. Select `Temporal IPD` mode in both sender and receiver
2. Send a very short message: `Hi`
3. Watch the inter-packet delays in receiver log
4. Takes ~30 seconds to transmit

**Timing profiles**:
- `Constant`: Fixed 50/100 ms delays
- `Normal`: Adds Gaussian jitter
- `Gamma`: Network latency simulation
- `GMM/ML`: Uses trained model (most realistic)

---

## Verify with Wireshark (Optional)

### Header Mode Verification:
1. Start Wireshark
2. Capture on `Loopback` (Windows) or `lo` (Linux)
3. Filter: `icmp.type == 8`
4. Send a message
5. Inspect packets → IPv4 → **Identification field**
6. Look for `0xDEAD` (sync marker) followed by data

### Temporal Mode Verification:
1. Same capture setup
2. Filter: `icmp.type == 8`
3. View → Time Display Format → `Seconds Since Previous Displayed Packet`
4. Send a message
5. Observe alternating ~50ms and ~100ms delays
6. Pattern corresponds to bits: short=0, long=1

---

## Troubleshooting

### Error: "Permission denied"
**Solution**: Run with sudo/admin privileges
```bash
sudo python receiver/receiver_app.py
```

### Error: "No module named 'flask'"
**Solution**: Install dependencies
```bash
pip install -r requirements.txt
```

### Receiver shows no packets
**Solutions**:
- Ensure receiver is running before sender
- Check target IP matches (default: 127.0.0.1)
- Verify firewall allows ICMP
- Try running with sudo/admin

### Wrong password error
**Solution**: PSK must match exactly on sender and receiver
- Re-enter password
- Check for typos
- Case-sensitive

### Temporal mode too slow
**Solution**: Use header mode for longer messages
- Temporal mode is intentionally slow (demonstrates concept)
- Good for messages < 20 bytes
- For speed, use header mode

---

## Testing

### Run Automated Tests
```bash
pytest
```

**Expected**: 49 tests pass ✓

### Run Specific Tests
```bash
pytest tests/test_crypto.py -v
pytest tests/test_framing.py -v
pytest tests/test_header_channel.py -v
pytest tests/test_temporal_channel.py -v
pytest tests/test_ml.py -v
```

---

## What to Try Next

### Experiment 1: Wrong Password
1. Start receiver with PSK: `password1`
2. Send with PSK: `password2`
3. **Observe**: Decryption fails (security working!)

### Experiment 2: Different Timing Profiles
1. Use temporal mode
2. Try each timing profile:
   - Constant (most precise)
   - Normal (adds jitter)
   - Gamma (network simulation)
   - GMM (most realistic)
3. **Observe**: Different delay patterns in receiver

### Experiment 3: Measure Throughput
1. Send messages of different lengths
2. Record transmission time
3. Calculate: `throughput = (message_bytes × 8) / time_seconds`
4. **Compare**: Header mode vs Temporal mode

### Experiment 4: Message Size Limits
1. Try sending increasingly long messages
2. Header mode: up to 1 KB works well
3. Temporal mode: keep to < 50 bytes
4. **Observe**: How transmission time scales

---

## Important Commands Reference

```bash
# Setup
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python setup.py

# Train ML
python ml/train_model.py --create-synthetic

# Run Applications
sudo python receiver/receiver_app.py  # Port 5001
sudo python sender/sender_app.py      # Port 5000

# Testing
pytest                                 # All tests
pytest -v                             # Verbose
pytest --cov                          # With coverage

# Individual Module Tests
python common/crypto.py               # Self-test crypto
python common/framing.py              # Self-test framing
python common/utils.py                # Self-test utils
python ml/ml_profiler.py              # Self-test ML
```

---

## URLs

- **Receiver UI**: http://127.0.0.1:5001
- **Sender UI**: http://127.0.0.1:5000

---

## Need More Information?

- **Full documentation**: `README.md`
- **Architecture details**: `docs/architecture.md`
- **Protocol specification**: `docs/protocol.md`
- **Testing guide**: `docs/testing.md`
- **Viva questions**: `docs/viva.md` (40 Q&A)
- **Completion report**: `COMPLETION_REPORT.md`

---

## Project Structure Summary

```
NetGhost/
├── common/           # Crypto, framing, utilities
├── sender/           # Sender core + Flask app + UI
├── receiver/         # Receiver core + Flask app + UI
├── ml/               # GMM traffic profiler
├── tests/            # 49 automated tests
├── docs/             # Comprehensive documentation
├── requirements.txt  # Dependencies
├── setup.py          # Verification script
└── README.md         # Full documentation
```

---

## Safety Reminder

⚠️ **Use only on authorized networks**

This is an educational project. Only use on:
- Your own computer (localhost)
- Lab networks with permission
- Networks you own/administer

Do NOT use on:
- Public networks
- Enterprise networks without authorization
- Any network where you don't have explicit permission

---

## Demo Checklist

For class presentation:

- [ ] Install and verify setup
- [ ] Train ML model
- [ ] Start receiver
- [ ] Start sender
- [ ] Open both UIs
- [ ] Demonstrate header mode
- [ ] Demonstrate temporal mode
- [ ] Show Wireshark verification
- [ ] Show wrong password rejection
- [ ] Show transmission statistics
- [ ] Answer questions from viva.md

---

## Support

If something doesn't work:
1. Check `COMPLETION_REPORT.md` troubleshooting section
2. Verify all tests pass: `pytest`
3. Ensure Python 3.8+
4. Confirm sudo/admin privileges
5. Check firewall allows ICMP

---

**That's it! You're ready to demonstrate network steganography! 🚀**

For detailed information, refer to `README.md` and `docs/` directory.
