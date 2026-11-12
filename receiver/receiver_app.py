"""
NETGHOST - DEDICATED RECEIVER NODE
Port: 5001 (http://127.0.0.1:5001 or http://127.0.0.1:5001/receiver)
Peer Sender: http://127.0.0.1:5000/sender
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

# Set node environment before importing Flask app
os.environ['NETGHOST_MODE'] = 'receiver'
os.environ['NETGHOST_PORT'] = '5001'

from app import app, load_gmm_model

if __name__ == '__main__':
    print("=" * 65)
    print("  NETGHOST - DEDICATED RECEIVER NODE (PORT 5001)")
    print("=" * 65)
    print("  • Dedicated Receiver URL : http://127.0.0.1:5001/receiver")
    print("  • Root Direct URL        : http://127.0.0.1:5001/")
    print("  • Paired Sender Node     : http://127.0.0.1:5000/sender")
    print("=" * 65)
    load_gmm_model()
    print("  [✓] Receiver node online. Ready to capture and decode packets...")
    print("=" * 65)
    app.run(host='127.0.0.1', port=5001, debug=False, threaded=True)
