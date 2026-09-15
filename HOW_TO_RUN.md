# 🚀 How to Run NetGhost - Complete Guide

## ✅ Prerequisites Check

Before starting, ensure you have:
- ✅ **Python 3.8+** installed (you have Python 3.13.5 ✓)
- ✅ **Administrator/root privileges** (required for packet capture)
- ✅ **Windows with Npcap** or **Linux/macOS with libpcap**

---

## 📦 Installation Complete! ✓

Your installation is already done:
- ✅ Virtual environment created
- ✅ All dependencies installed
- ✅ ML model trained
- ✅ All 49 tests passing
- ✅ Ready to run!

---

## 🎯 Quick Start - 3 Simple Steps

### Step 1: Start the Receiver (Terminal 1)

Open **Command Prompt as Administrator**:

1. Right-click **Command Prompt**
2. Select **"Run as Administrator"**
3. Navigate to project:
   ```cmd
   cd D:\CNT\CNT_CP1\NetGhost
   ```

4. Activate environment and run:
   ```cmd
   .venv\Scripts\activate
   python receiver/receiver_app.py
   ```

**Expected Output**:
```
======================================================================
NETGHOST RECEIVER APPLICATION
======================================================================

Starting receiver web interface...
URL: http://127.0.0.1:5001

IMPORTANT: This application requires root/administrator privileges
           to capture raw packets.

Press Ctrl+C to stop
======================================================================

 * Serving Flask app 'receiver_app'
 * Running on http://127.0.0.1:5001
```

5. **Open browser**: http://127.0.0.1:5001

---

### Step 2: Start the Sender (Terminal 2)

Open **ANOTHER Command Prompt as Administrator**:

1. Right-click **Command Prompt**
2. Select **"Run as Administrator"**
3. Navigate to project:
   ```cmd
   cd D:\CNT\CNT_CP1\NetGhost
   ```

4. Activate environment and run:
   ```cmd
   .venv\Scripts\activate
   python sender/sender_app.py
   ```

**Expected Output**:
```
======================================================================
NETGHOST SENDER APPLICATION
======================================================================

✓ GMM model loaded from ml/models/gmm_timing.pkl

Starting sender web interface...
URL: http://127.0.0.1:5000

NOTE: This application requires root/administrator privileges
      to send raw packets.

Press Ctrl+C to stop
======================================================================

 * Serving Flask app 'sender_app'
 * Running on http://127.0.0.1:5000
```

5. **Open browser**: http://127.0.0.1:5000

---

### Step 3: Send Your First Covert Message!

#### In Receiver Browser (http://127.0.0.1:5001):
1. **Pre-Shared Key**: Enter `demo123`
2. **Mode**: Select `Header Field Embedding`
3. Click **"Start Listening"**
4. You should see: "Starting header channel receiver..."

#### In Sender Browser (http://127.0.0.1:5000):
1. **Target IP**: Keep default `127.0.0.1`
2. **Pre-Shared Key**: Enter `demo123` (must match receiver!)
3. **Message**: Type `Hello from NetGhost CNT Project!`
4. **Mode**: Select `Header Field Embedding`
5. Click **"Send Message"**

#### Watch the Magic! ✨

**Sender will show**:
```
✓ Transmission complete!

Statistics:
- Mode: Header
- Plaintext Length: 34 bytes
- Packets Sent: 25
- Duration: 0.52 seconds
- Throughput: 524 bps
```

**Receiver will show**:
```
Starting header channel receiver...
Packet 1: IP.id=0xDEAD (57005)
Packet 2: IP.id=0x003D (61)
...
✓ Sync marker detected!
✓ Frame extracted: 61 bytes
✓ Decryption successful!
✓ Message: Hello from NetGhost CNT Project!
```

🎉 **SUCCESS!** You just sent your first covert message!

---

## 🔄 Testing Both Modes

### Mode 1: Header Field Embedding (Fast - Recommended)

**Best for**: Messages up to 1 KB  
**Speed**: ~500 bps  
**Time**: ~1 second for 50-byte message

**Configuration**:
- Receiver: Select "Header Field Embedding"
- Sender: Select "Header Field Embedding"

**Test Messages**:
- Short: `Hi`
- Medium: `This is a test of network steganography`
- Long: A paragraph of text

---

### Mode 2: Temporal IPD (Slow - Demonstration)

**Best for**: Very short messages (< 20 bytes)  
**Speed**: ~3 bps  
**Time**: ~30 seconds for 10-byte message

**Configuration**:

**Receiver**:
1. PSK: `demo123`
2. Mode: `Temporal IPD`
3. Timing Threshold: `75` ms
4. Click "Start Listening"

**Sender**:
1. PSK: `demo123`
2. Message: `Hi` (keep it SHORT!)
3. Mode: `Temporal IPD`
4. Timing Profile: `Constant`
5. Bit 0 Delay: `50` ms
6. Bit 1 Delay: `100` ms
7. Click "Send Message"

**Watch in Receiver**:
```
Packet 1: First packet (no delay)
Packet 2: Δt=100.3ms → bit 1
Packet 3: Δt=50.1ms → bit 0
Packet 4: Δt=100.2ms → bit 1
...
✓ Message decoded!
```

---

## 🧪 Testing Different Timing Profiles

### Profile 1: Constant (Most Precise)
- Fixed delays: 50ms and 100ms
- Most predictable, easiest to decode
- Best for localhost testing

### Profile 2: Normal (Gaussian Jitter)
- Adds random variation ±5ms
- Simulates measurement noise
- More realistic

### Profile 3: Gamma (Network Latency)
- Models network delay distribution
- Tail-heavy distribution
- Realistic network simulation

### Profile 4: GMM/ML (Most Realistic) ✨
- Uses trained machine learning model
- Matches baseline traffic patterns
- Best for undetectability
- ⚠️ **Requires ML model trained** (you already did this!)

---

## 🔐 Testing Security Features

### Test 1: Wrong Password Detection

1. **Receiver**: PSK = `correct_password`
2. **Sender**: PSK = `wrong_password`
3. Send message
4. **Expected**: Receiver shows "✗ Decryption failed: authentication failed"

### Test 2: Message Tampering

The system automatically protects against tampering using AES-GCM authentication tags. Any modification to the encrypted data will be detected.

---

## 📊 Performance Experiments

### Experiment 1: Measure Throughput

**Header Mode**:
1. Send 10-byte message → note time
2. Send 50-byte message → note time
3. Send 100-byte message → note time
4. Calculate: `throughput = (bytes × 8) / seconds`

**Expected**: ~500 bps

**Temporal Mode**:
1. Send 5-byte message → note time
2. Calculate: `throughput = (bytes × 8) / seconds`

**Expected**: ~3 bps

---

## 🔍 Wireshark Verification (Optional)

### Setup Wireshark

1. **Install Wireshark** (if not already installed)
2. **Start Wireshark**
3. **Capture Interface**: Select `Adapter for loopback traffic capture`
4. **Filter**: Enter `icmp.type == 8`
5. **Start Capture**

### Verify Header Mode

1. Send a message using Header mode
2. In Wireshark, click on any ICMP packet
3. Expand: `Internet Protocol Version 4`
4. Look at: **Identification: 0x....**
5. First packet should show: `0xDEAD` (sync marker)
6. Subsequent packets contain encrypted data

### Verify Temporal Mode

1. Send a message using Temporal mode
2. In Wireshark: View → Time Display Format → `Seconds Since Previous Displayed Packet`
3. Look at the `Time` column
4. You'll see alternating delays:
   - ~0.050 seconds (bit 0)
   - ~0.100 seconds (bit 1)
5. Pattern encodes the message bits

---

## ⚙️ Advanced Configuration

### Change Target IP

By default, it's `127.0.0.1` (localhost). To test on network:

1. **Receiver**: Run on Machine A (note its IP)
2. **Sender**: Change target IP to Machine A's IP
3. Ensure both machines are on same network
4. Ensure firewall allows ICMP

### Optimize Temporal Mode

For faster temporal transmission:
- Reduce delays: Bit 0 = 10ms, Bit 1 = 20ms
- This increases speed to ~50 bps
- May be less reliable due to timing precision

---

## 🐛 Troubleshooting

### Issue 1: "Permission denied" or "Access denied"

**Solution**: Must run as Administrator

Windows:
1. Close both terminals
2. Right-click Command Prompt
3. Select "Run as Administrator"
4. Run commands again

### Issue 2: Receiver shows no packets

**Checklist**:
- ✅ Is receiver running BEFORE sender?
- ✅ Is PSK identical in both?
- ✅ Is mode identical in both?
- ✅ Did you click "Start Listening" in receiver?
- ✅ Did sender show "Transmission complete"?
- ✅ Running as Administrator?

### Issue 3: "Decryption failed"

**Causes**:
- Password mismatch (most common)
- Message corrupted in transit
- Packet loss

**Solution**:
- Double-check PSK is identical
- Try again with shorter message
- Ensure localhost network is working

### Issue 4: Temporal mode is too slow

**This is normal!** Temporal mode is intentionally slow:
- 50ms + 100ms per bit = ~3 bps
- 10-byte message = 80 bits = ~40 seconds

**Solution**: Use Header mode for longer messages

### Issue 5: GMM/ML option is disabled

**Solution**: Train the model:
```cmd
.venv\Scripts\activate
python ml/train_model.py --create-synthetic
```

---

## 🎓 For Class Demonstration

### Preparation Checklist

- [ ] Both terminals running as Administrator
- [ ] Receiver started first
- [ ] Sender started second
- [ ] Both browser tabs open
- [ ] Test message prepared
- [ ] Wireshark ready (optional)

### Demo Script (5 minutes)

**1. Introduction (30 seconds)**
- Explain what network steganography is
- Mention the two covert channels

**2. Header Mode Demo (2 minutes)**
- Configure receiver
- Configure sender
- Send message: "Hello from NetGhost!"
- Show real-time packet capture
- Show decoded message

**3. Temporal Mode Demo (2 minutes)**
- Switch to temporal mode
- Send very short message: "Hi"
- Explain timing-based encoding
- Show inter-packet delays in receiver

**4. Wireshark Verification (30 seconds)**
- Show ICMP packets
- Point out IP.id values (header mode)
- OR show timing pattern (temporal mode)

**5. Q&A (varies)**
- Answer questions using `docs/viva.md`

---

## 📁 Important Files Reference

| File | Purpose |
|------|---------|
| `receiver/receiver_app.py` | Receiver web application |
| `sender/sender_app.py` | Sender web application |
| `ml/train_model.py` | Train ML timing model |
| `setup.py` | Verification script |
| `tests/` | Automated test suite |
| `docs/viva.md` | 40 viva questions |
| `README.md` | Full documentation |

---

## 🔄 Stopping the Applications

### To Stop Receiver or Sender:

In the terminal running the application:
1. Press `Ctrl + C`
2. Wait for graceful shutdown

**Expected Output**:
```
Keyboard interrupt received, exiting
```

---

## 🧪 Running Automated Tests

To verify everything works:

```cmd
.venv\Scripts\activate
pytest -v
```

**Expected**: All 49 tests pass ✓

To run specific tests:
```cmd
pytest tests/test_crypto.py -v
pytest tests/test_header_channel.py -v
pytest tests/test_temporal_channel.py -v
```

---

## 📊 Quick Reference Commands

```cmd
# Activate environment (do this first in each terminal)
.venv\Scripts\activate

# Start receiver (Terminal 1 - as Admin)
python receiver/receiver_app.py

# Start sender (Terminal 2 - as Admin)
python sender/sender_app.py

# Train ML model
python ml/train_model.py --create-synthetic

# Run tests
pytest

# Run setup verification
python setup.py
```

---

## 🌐 URLs

- **Receiver**: http://127.0.0.1:5001
- **Sender**: http://127.0.0.1:5000

---

## ✅ Success Indicators

You'll know it's working when:

**Sender**:
- Shows "✓ Transmission complete!"
- Displays packet count and throughput
- No error messages

**Receiver**:
- Shows "✓ Sync marker detected!"
- Shows "✓ Decryption successful!"
- Displays the decoded message
- No "✗" error symbols

---

## 📖 Need More Help?

- **Quick Start**: Read `QUICKSTART.md`
- **Full Docs**: Read `README.md`
- **Architecture**: Read `docs/architecture.md`
- **Testing**: Read `docs/testing.md`
- **Viva Prep**: Read `docs/viva.md`

---

## 🎉 You're All Set!

Your NetGhost project is fully installed and ready to demonstrate!

**Current Status**:
✅ Installation complete  
✅ Dependencies installed  
✅ ML model trained  
✅ Tests passing (49/49)  
✅ Ready for presentation  

**Next**: Follow the Quick Start above to send your first covert message!

---

## 💡 Pro Tips

1. **Always start receiver BEFORE sender**
2. **Always use matching PSK on both sides**
3. **For demos, use Header mode** (faster)
4. **Keep temporal messages SHORT** (< 20 bytes)
5. **Run as Administrator** (critical for Windows)
6. **Test before presentation** (end-to-end)

---

**Good luck with your demonstration! 🚀**
