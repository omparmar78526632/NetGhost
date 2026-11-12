"""
End-to-End Live ICMP & PCAP Verification Script for NetGhost.
Actually transmits ICMP Echo Requests over loopback (127.0.0.1), captures them
via Scapy AsyncSniffer (Wireshark-compatible .pcap), inspects IP.id and timestamps,
and verifies Receiver extraction + AES-256-GCM decryption.
"""

import os
import sys
import time
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from scapy.all import AsyncSniffer, IP, ICMP, wrpcap, rdpcap, conf
from sender.sender_core import HeaderChannelSender
from receiver.receiver_core import HeaderChannelReceiver
from ml.ml_profiler import TrafficProfiler, create_synthetic_baseline_pcap

SCRATCH_DIR = os.path.join(BASE_DIR, "scratch")
os.makedirs(SCRATCH_DIR, exist_ok=True)
PASSPHRASE = "netghost_e2e_secret"
PLAINTEXT = "OM"


def wait_for_receiver_message(rx: HeaderChannelReceiver, timeout_s: float = 10.0) -> str:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if rx.decryption_success and rx.last_message is not None:
            return rx.last_message
        if rx.last_error:
            raise RuntimeError(f"Receiver error: {rx.last_error}")
        time.sleep(0.05)
    raise TimeoutError("Timed out waiting for receiver to decode message")


def extract_icmp_echo_requests(pcap_path: str):
    pkts = rdpcap(pcap_path)
    # Filter ICMP Echo Request (type 8) and deduplicate <3ms loopback echoes
    reqs = []
    for p in pkts:
        if p.haslayer(IP) and p.haslayer(ICMP) and p[ICMP].type == 8:
            t = float(p.time)
            if reqs and (t - float(reqs[-1].time)) < 0.003:
                continue
            reqs.append(p)
    return reqs


def run_single_e2e_test(
    test_name: str,
    timing_profile: str,
    gmm_model=None,
    delay_ms: float = 50.0,
):
    print(f"\n{'='*70}")
    print(f"RUNNING {test_name} | Profile={timing_profile} | Input='{PLAINTEXT}'")
    print(f"{'='*70}")

    pcap_path = os.path.join(SCRATCH_DIR, f"capture_{timing_profile}.pcap")
    loopback = getattr(conf, "loopback_name", None)

    rx = HeaderChannelReceiver(passphrase=PASSPHRASE)
    rx.start_listening(interface=loopback, timeout=30)

    sniffer = AsyncSniffer(iface=loopback, filter="icmp", store=True)
    sniffer.start()
    time.sleep(0.6)  # Allow sniffer & receiver threads to initialize

    sender = HeaderChannelSender("127.0.0.1")
    stats = sender.send_message(
        PLAINTEXT,
        PASSPHRASE,
        timing_profile=timing_profile,
        gmm_model=gmm_model,
        delay_ms=delay_ms,
    )

    decoded = wait_for_receiver_message(rx, timeout_s=10.0)
    time.sleep(0.2)
    captured = sniffer.stop()
    rx.stop_listening()

    wrpcap(pcap_path, captured)
    reqs = extract_icmp_echo_requests(pcap_path)

    # Verify plaintext does NOT appear in raw ICMP packet bytes
    plaintext_in_wire = any(PLAINTEXT.encode("utf-8") in bytes(p[ICMP]) for p in reqs)

    # Inspect IP.id values
    ip_ids = [p[IP].id for p in reqs]
    has_sync = 0xDEAD in ip_ids

    # Compute observed IPDs from packet timestamps in PCAP
    timestamps = [float(p.time) for p in reqs]
    ipds_ms = [(timestamps[i] - timestamps[i - 1]) * 1000.0 for i in range(1, len(timestamps))]

    print(f"  Packets Sent (Sender):     {stats['packets_sent']}")
    print(f"  ICMP Echo Req (PCAP):      {len(reqs)}")
    print(f"  0xDEAD Sync in IP.id:      {has_sync} (first 4 IP.ids: {[hex(x) for x in ip_ids[:4]]})")
    print(f"  Plaintext in ICMP wire:    {plaintext_in_wire}")
    print(f"  GMM Used:                  {stats.get('gmm_used', False)}")
    if ipds_ms:
        print(
            f"  Observed IPD (ms):         count={len(ipds_ms)}, "
            f"mean={np.mean(ipds_ms):.2f}, std={np.std(ipds_ms):.2f}, "
            f"min={np.min(ipds_ms):.2f}, max={np.max(ipds_ms):.2f}"
        )
    print(f"  Receiver Decoded Output:   '{decoded}'")

    assert decoded == PLAINTEXT, f"Expected '{PLAINTEXT}', got '{decoded}'"
    assert len(reqs) == stats["packets_sent"], f"Packet count mismatch: {len(reqs)} vs {stats['packets_sent']}"
    assert has_sync, "0xDEAD sync marker missing in captured IP.id"
    assert not plaintext_in_wire, "Plaintext leaked in wire!"

    return {
        "test": test_name,
        "packets_sent": stats["packets_sent"],
        "packets_received": len(reqs),
        "gmm_used": stats.get("gmm_used", False),
        "ipds_ms": ipds_ms,
        "decoded": decoded,
        "pcap": pcap_path,
    }


def main():
    # Test A & C: IP-ID channel with Normal / Variable Load
    res_normal = run_single_e2e_test("Test A/C: IP-ID + Normal/Variable Load", "normal")
    assert np.std(res_normal["ipds_ms"]) > 3.0, "Normal profile IPDs should be variable!"

    # Test B: Constant Delay (50 ms)
    res_const = run_single_e2e_test("Test B: IP-ID + Constant Delay (50ms)", "constant", delay_ms=50.0)
    mean_const = np.mean(res_const["ipds_ms"])
    assert 40.0 <= mean_const <= 65.0, f"Constant delay mean {mean_const:.2f}ms out of expected ~50ms range"

    # Test D: GMM Training -> Save -> Load -> Transmit -> Capture -> Decrypt
    print("\nTraining GMM model for Test D...")
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
        f"  Loaded GMM: samples={gmm_stats['n_samples']}, components={gmm_stats['n_components']}, "
        f"log_likelihood={gmm_stats['log_likelihood']}, bic={gmm_stats['bic']}"
    )

    res_gmm = run_single_e2e_test("Test D: IP-ID + GMM Fitted Distribution", "gmm", gmm_model=loaded_profiler)
    assert res_gmm["gmm_used"] is True
    assert np.std(res_gmm["ipds_ms"]) > 5.0, "GMM sampled IPDs should reflect multi-modal variability!"

    print("\nALL END-TO-END LIVE LOOPBACK TESTS PASSED!")


if __name__ == "__main__":
    main()

