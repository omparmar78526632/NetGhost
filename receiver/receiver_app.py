"""
Receiver Web Application
Provides unified interface & endpoints for receiving and sending covert messages
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from app import app, load_gmm_model

if __name__ == '__main__':
    print("=" * 60)
    print("NETGHOST RECEIVER / CONSOLE")
    print("=" * 60)
    print()
    load_gmm_model()
    print("Starting on: http://127.0.0.1:5001")
    print("=" * 60)
    app.run(host='127.0.0.1', port=5001, debug=False, threaded=True)
