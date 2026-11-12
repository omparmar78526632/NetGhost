"""
NETGHOST - DEDICATED SENDER NODE
Port: 5000 (http://127.0.0.1:5000 or http://127.0.0.1:5000/sender)
Peer Receiver: http://127.0.0.1:5001/receiver
"""

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

# Set node environment before importing Flask app
os.environ['NETGHOST_MODE'] = 'sender'
os.environ['NETGHOST_PORT'] = '5000'

from app import app, load_gmm_model

if __name__ == '__main__':
    print("=" * 65)
    print("  NETGHOST - DEDICATED SENDER NODE (PORT 5000)")
    print("=" * 65)
    print("  • Dedicated Sender URL : http://127.0.0.1:5000/sender")
    print("  • Root Direct URL      : http://127.0.0.1:5000/")
    print("  • Paired Receiver Node : http://127.0.0.1:5001/receiver")
    print("=" * 65)
    load_gmm_model()
    print("  [✓] Sender node online. Awaiting covert transmissions...")
    print("=" * 65)
    app.run(host='127.0.0.1', port=5000, debug=False, threaded=True)
