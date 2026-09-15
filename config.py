"""
Global Configuration for NetGhost Project
"""

import os

# Project Root
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Flask Configuration
FLASK_SECRET_KEY = os.urandom(24)

# Network Configuration
DEFAULT_TARGET_IP = "127.0.0.1"
DEFAULT_INTERFACE = "lo"  # Linux loopback; use "Loopback" for Windows

# Sender Configuration
SENDER_HOST = "127.0.0.1"
SENDER_PORT = 5000

# Receiver Configuration
RECEIVER_HOST = "127.0.0.1"
RECEIVER_PORT = 5001

# Timing Configuration (milliseconds)
DEFAULT_BIT_0_DELAY = 50  # 50ms for bit 0
DEFAULT_BIT_1_DELAY = 100  # 100ms for bit 1
DEFAULT_TIMING_THRESHOLD = 75  # Midpoint for classification

# ML Configuration
ML_MODELS_DIR = os.path.join(BASE_DIR, "ml", "models")
GMM_MODEL_FILE = os.path.join(ML_MODELS_DIR, "gmm_timing.pkl")
GMM_N_COMPONENTS = 3

# Frame Configuration
SYNC_MARKER = 0xDEAD
FRAME_MAX_SIZE = 65535

# Crypto Configuration
PBKDF2_ITERATIONS = 100000
AES_KEY_SIZE = 32  # 256 bits
GCM_NONCE_SIZE = 12  # 96 bits
GCM_TAG_SIZE = 16  # 128 bits

# Logging
LOG_LEVEL = "INFO"
