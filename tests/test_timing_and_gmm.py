"""
Unit Tests for Timing Profiles, GMM Validation/Bounds, and Error Handling.
"""

import os
import sys
import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.timing import (
    ConstantTimingProfile,
    NormalVariableTimingProfile,
    GammaTimingProfile,
    GMMTimingProfile,
    create_timing_profile,
)
from ml.ml_profiler import TrafficProfiler
from sender.sender_app import app


class TestTimingProfiles:
    def test_constant_profile_header_and_temporal(self):
        prof = create_timing_profile("constant", delay_ms=40.0, bit_0_ms=25.0, bit_1_ms=125.0)
        assert isinstance(prof, ConstantTimingProfile)
        delays = [prof.next_delay_s() for _ in range(5)]
        assert all(d == pytest.approx(0.040) for d in delays)
        assert prof.next_delay_s(bit=0) == pytest.approx(0.025)
        assert prof.next_delay_s(bit=1) == pytest.approx(0.125)

    def test_normal_variable_profile_is_variable_and_bounded(self):
        prof = create_timing_profile("normal")
        assert isinstance(prof, NormalVariableTimingProfile)
        delays = [prof.next_delay_s() for _ in range(30)]
        assert len(set(round(d, 6) for d in delays)) > 5, "Normal profile must produce variable delays"
        assert all(0.010 <= d <= 0.150 for d in delays)

    def test_gamma_profile_is_variable_and_bounded(self):
        prof = create_timing_profile("gamma")
        assert isinstance(prof, GammaTimingProfile)
        delays = [prof.next_delay_s() for _ in range(30)]
        assert len(set(round(d, 6) for d in delays)) > 5
        assert all(0.010 <= d <= 0.200 for d in delays)

    def test_invalid_timing_profile_raises(self):
        with pytest.raises(ValueError, match="Invalid timing profile"):
            create_timing_profile("nonexistent_profile")

    def test_gmm_profile_requires_trained_model(self):
        untrained = TrafficProfiler()
        with pytest.raises(RuntimeError, match="no trained GMM model"):
            create_timing_profile("gmm", gmm_model=None)
        with pytest.raises(RuntimeError, match="no trained GMM model"):
            create_timing_profile("gmm", gmm_model=untrained)

    def test_gmm_profile_samples_within_bounds(self):
        np.random.seed(42)
        data = np.concatenate([
            np.random.normal(20.0, 4.0, 200),
            np.random.normal(90.0, 12.0, 200),
            np.random.normal(200.0, 25.0, 100),
        ])
        profiler = TrafficProfiler(n_components=3, min_bound_ms=5.0, max_bound_ms=500.0)
        profiler.train_gmm(data, dataset_source="unit_test")

        stats = profiler.get_statistics()
        assert stats["n_samples"] == len(data[data > 0])
        assert stats["n_components"] == 3
        assert stats["log_likelihood"] is not None
        assert stats["aic"] is not None
        assert stats["bic"] is not None

        prof = create_timing_profile("gmm", gmm_model=profiler)
        assert isinstance(prof, GMMTimingProfile)
        delays = [prof.next_delay_s() for _ in range(50)]
        assert all(0.005 <= d <= 0.500 for d in delays)
        assert len(set(round(d, 6) for d in delays)) > 10

    def test_insufficient_samples_raises(self):
        profiler = TrafficProfiler(n_components=3)
        with pytest.raises(ValueError, match="Insufficient valid IPD samples"):
            profiler.train_gmm(np.array([10.0, 20.0, 30.0]))

    def test_untrained_sample_bit_delay_raises(self):
        profiler = TrafficProfiler()
        with pytest.raises(RuntimeError, match="not trained"):
            profiler.sample_bit_delay(0)


class TestFlaskErrorHandling:
    def test_send_rejects_invalid_timing_profile(self):
        client = app.test_client()
        res = client.post("/send", json={
            "target_ip": "127.0.0.1",
            "passphrase": "secret",
            "message": "OM",
            "mode": "header",
            "timing_profile": "bogus_profile",
        })
        assert res.status_code == 400
        assert "Invalid timing profile" in res.get_json()["error"]

    def test_send_rejects_gmm_when_missing(self, monkeypatch):
        import sender.sender_app as sender_module
        monkeypatch.setattr(sender_module, "gmm_model", None)
        monkeypatch.setattr(sender_module, "load_gmm_model", lambda: False)

        client = app.test_client()
        res = client.post("/send", json={
            "target_ip": "127.0.0.1",
            "passphrase": "secret",
            "message": "OM",
            "mode": "header",
            "timing_profile": "gmm",
        })
        assert res.status_code == 400
        # Accept either error message variant
        err = res.get_json()["error"]
        assert "GMM" in err or "gmm" in err.lower()

    def test_gmm_status_and_train_endpoint(self):
        # /api/profiler/train lives on the receiver app — use its test client
        import receiver.receiver_app as receiver_module
        rclient = receiver_module.app.test_client()
        res = rclient.post("/api/profiler/train", json={"preset": "http", "components": 3})
        assert res.status_code == 200
        data = res.get_json()
        assert data["success"] is True
        assert "statistics" in data
        assert data["statistics"]["n_samples"] > 0

        status_res = rclient.get("/gmm_status")
        assert status_res.status_code == 200
        st = status_res.get_json()
        assert st["available"] is True
        assert st["loaded"] is True
        assert st["status"] == "Trained"

        load_res = rclient.post("/api/profiler/load")
        assert load_res.status_code == 200
        ld = load_res.get_json()
        assert ld["success"] is True


class TestReceiverDeduplicationAndReset:
    def test_duplicate_seq_packets_and_stale_buffer_do_not_break_aes_gcm(self):
        from scapy.all import IP, ICMP
        from common.crypto import encrypt_message
        from common.framing import create_frame
        from common.utils import bytes_to_uint16_list
        from receiver.receiver_core import HeaderChannelReceiver
        import time

        passphrase = "test_gmm_dedup_secret"
        rx = HeaderChannelReceiver(passphrase=passphrase)

        # Inject stale garbage fragments before the real transmission
        base_t = time.time()
        for idx, junk_id in enumerate([0xDEAD, 0x0010, 0x1234, 0x5678]):
            rx._packet_handler(IP(id=junk_id, dst="127.0.0.1") / ICMP(type=8, seq=idx))

        # Now send real "OM" frame with seq=0..N-1 AND inject a duplicate > 10ms later
        encrypted = encrypt_message("OM", passphrase)
        frame = create_frame(encrypted)
        chunks = bytes_to_uint16_list(frame)

        t = base_t + 1.0
        for seq_i, chunk in enumerate(chunks):
            pkt = IP(id=chunk, dst="127.0.0.1") / ICMP(type=8, seq=seq_i)
            pkt.time = t
            rx._packet_handler(pkt)
            # Simulate Npcap multi-adapter duplicate arriving 10ms later
            if seq_i in (2, 5, 10):
                dup = IP(id=chunk, dst="127.0.0.1") / ICMP(type=8, seq=seq_i)
                dup.time = t + 0.010
                rx._packet_handler(dup)
            t += 0.050

        assert rx.decryption_success is True
        assert rx.last_message == "OM"
        assert rx.last_error is None

