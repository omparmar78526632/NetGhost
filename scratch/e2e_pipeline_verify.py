"""
End-to-End Pipeline Verification (Real Timing + Real Scapy IP/ICMP Packets + PCAP + Receiver).
Captures transmitted Scapy IP/ICMP packets with real wall-clock timestamps into .pcap
when Npcap raw socket requires Administrator elevation, then feeds the .pcap into
HeaderChannelReceiver for full extraction, reassembly, and AES-256-GCM decryption.
"""

import os
import sys
import time
from unittest.mock import patch
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from scapy.all import IP, ICMP, wrpcap, rdpcap
from sender.sender_core import HeaderChannelSender
from receiver.receiver_core import HeaderChannelReceiver
from ml.ml_profiler import TrafficProfiler, create_synthetic_baseline_pcap

SCRATCH_DIR = os.path.join(BASE_DIR, "scratch")
os.makedirs(SCRATCH_DIR, exist_ok=True)
PASSPHRASE = "netghost_e2e_secret"
PLAINTEXT = "OM"


def run_pipeline_test(name: str, timing_profile: str, gmm_model=None, delay_ms: float = 50.0):
    print(f"\n{'='*70}")
    print(f"RUNNING {name} | Profile={timing_profile} | Input='{PLAINTEXT}'")
    print(f"{'='*70}")

    captured_pkts = []
    pcap_path = os.path.join(SCRATCH_DIR, f"pipeline_{timing_profile}.pcap")

    def capture_send(pkt, verbose=False):
        pkt.time = time.time()
        captured_pkts.append(pkt)

    sender = HeaderChannelSender("127.0.0.1")
    with patch("sender.sender_core.send", side_effect=capture_send):
        stats = sender.send_message(
            PLAINTEXT,
            PASSPHRASE,
            timing_profile=timing_profile,
            gmm_model=gmm_model,
            delay_ms=delay_ms,
        )

    wrpcap(pcap_path, captured_pkts)
    reloaded_pkts = rdpcap(pcap_path)

    rx = HeaderChannelReceiver(passphrase=PASSPHRASE)
    for pkt in reloaded_pkts:
        rx._packet_handler(pkt)

    ip_ids = [p[IP].id for p in reloaded_pkts]
    has_sync = 0xDEAD in ip_ids
    plaintext_in_wire = any(PLAINTEXT.encode("utf-8") in bytes(p[ICMP]) for p in reloaded_pkts)

    timestamps = [float(p.time) for p in reloaded_pkts]
    ipds_ms = [(timestamps[i] - timestamps[i - 1]) * 1000.0 for i in range(1, len(timestamps))]

    print(f"  Packets Sent:              {stats['packets_sent']}")
    print(f"  Packets in PCAP:           {len(reloaded_pkts)}")
    print(f"  0xDEAD Sync in IP.id:      {has_sync} (first 4 IP.ids: {[hex(x) for x in ip_ids[:4]]})")
    print(f"  Plaintext in ICMP wire:    {plaintext_in_wire}")
    print(f"  GMM Used:                  {stats.get('gmm_used', False)}")
    print(
        f"  Observed IPD (ms):         count={len(ipds_ms)}, "
        f"mean={np.mean(ipds_ms):.2f}, std={np.std(ipds_ms):.2f}, "
        f"min={np.min(ipds_ms):.2f}, max={np.max(ipds_ms):.2f}"
    )
    print(f"  Receiver Decoded Output:   '{rx.last_message}' (decryption_success={rx.decryption_success})")

    assert rx.decryption_success is True
    assert rx.last_message == PLAINTEXT
    assert len(reloaded_pkts) == stats["packets_sent"]
    assert has_sync
    assert not plaintext_in_wire

    return stats, ipds_ms, rx.last_message


def main():
    # Test A & C: Normal / Variable Load
    _, ipds_norm, _ = run_pipeline_test("Test A/C: IP-ID + Normal/Variable Load", "normal")
    assert np.std(ipds_norm) > 3.0

    # Test B: Constant Delay (50 ms)
    _, ipds_const, _ = run_pipeline_test("Test B: IP-ID + Constant Delay (50ms)", "constant", delay_ms=50.0)
    assert 45.0 <= np.mean(ipds_const) <= 60.0
    assert np.std(ipds_const) < 5.0

    # Test D: GMM Fitted Distribution
    baseline_pcap = os.path.join(BASE_DIR, "ml", "models", "baseline_synthetic.pcap")
    if not os.path.exists(baseline_pcap):
        create_synthetic_baseline_pcap(baseline_pcap, n_packets=500)

    trainer = TrafficProfiler(n_components=3)
    raw_ipds = trainer.extract_timing_from_pcap(baseline_pcap)
    cleaned = trainer.clean_timing_data(raw_ipds)
    trainer.train_gmm(cleaned, dataset_source="baseline_synthetic.pcap")
    model_path = os.path.join(BASE_DIR, "ml", "models", "gmm_timing.pkl")
    trainer.save_model(model_path)

    loaded_profiler = TrafficProfiler()
    loaded_profiler.load_model(model_path)
    gmm_stats = loaded_profiler.get_statistics()
    print(
        f"\n  Loaded GMM Model: samples={gmm_stats['n_samples']}, "
        f"components={gmm_stats['n_components']}, "
        f"log_likelihood={gmm_stats['log_likelihood']}, bic={gmm_stats['bic']}"
    )

    stats_gmm, ipds_gmm, _ = run_pipeline_test("Test D: IP-ID + GMM Fitted Distribution", "gmm", gmm_model=loaded_profiler)
    assert stats_gmm["gmm_used"] is True
    assert np.std(ipds_gmm) > 5.0
    assert all(4.0 <= d <= 520.0 for d in ipds_gmm)

    print("\nALL END-TO-END PIPELINE VERIFICATION TESTS PASSED!")


if __name__ == "__main__":
    main()

