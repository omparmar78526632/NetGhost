"""
Tests for Real-Time Event Pipeline & Live Flow Callbacks
Verifies that HeaderChannelSender, TemporalChannelSender, HeaderChannelReceiver,
and TemporalChannelReceiver emit the exact event signatures expected by the UI.
"""

import sys
import os
import pytest
import time

# Add root directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sender.sender_core import HeaderChannelSender, TemporalChannelSender
from receiver.receiver_core import HeaderChannelReceiver, TemporalChannelReceiver
from common.crypto import encrypt_message
from common.framing import create_frame
from common.utils import bytes_to_uint16_list
from scapy.all import IP, ICMP

class TestLiveFlowEvents:

    def test_header_sender_events(self):
        events = []
        def callback(evt):
            events.append(evt)

        sender = HeaderChannelSender(target_ip="127.0.0.1")
        plaintext = "Test Message"
        passphrase = "test_password"
        
        from unittest.mock import patch
        with patch("sender.sender_core.send") as mock_send:
            result = sender.send_message(plaintext, passphrase, packet_callback=callback)

        assert result["packets_sent"] > 0
        assert len(events) > 0

        event_types = [e.get("type") for e in events]
        assert "tx_started" in event_types
        assert "tx_encrypt_complete" in event_types
        assert "tx_fragment_complete" in event_types
        assert "tx_packet" in event_types
        assert "tx_completed" in event_types
        
        # Check packet event structure
        packet_events = [e for e in events if e.get("type") == "tx_packet"]
        assert len(packet_events) == result["packets_sent"]
        first_pkt = packet_events[0]
        assert "ip_id_hex" in first_pkt
        assert "ip_id" in first_pkt
        assert "index" in first_pkt
        assert "total" in first_pkt
        assert "channel" in first_pkt

    def test_temporal_sender_events(self):
        events = []
        def callback(evt):
            events.append(evt)

        sender = TemporalChannelSender(target_ip="127.0.0.1")
        plaintext = "Hi"
        passphrase = "test_password"

        from unittest.mock import patch
        with patch("sender.sender_core.send") as mock_send, patch("sender.sender_core.time.sleep") as mock_sleep:
            result = sender.send_message(plaintext, passphrase, packet_callback=callback)

        assert result["packets_sent"] > 0
        event_types = [e.get("type") for e in events]
        assert "tx_started" in event_types
        assert "tx_encrypt_complete" in event_types
        assert "tx_fragment_complete" in event_types
        assert "tx_packet" in event_types
        assert "tx_completed" in event_types

        packet_events = [e for e in events if e.get("type") == "tx_packet"]
        assert len(packet_events) == result["packets_sent"]
        
        # Check second packet (first timed bit packet)
        second_pkt = packet_events[1]
        assert "bit" in second_pkt
        assert second_pkt["bit"] in (0, 1)
        assert "intended_delay_ms" in second_pkt
        assert "timing_profile" in second_pkt

    def test_header_receiver_events(self):
        events = []
        def callback(evt):
            events.append(evt)

        passphrase = "receiver_test_pass"
        receiver = HeaderChannelReceiver(passphrase=passphrase)
        receiver.set_event_callback(callback)

        # Generate a valid payload and frame
        encrypted = encrypt_message("Secret Reception Test", passphrase)
        frame = create_frame(encrypted)
        ip_ids = bytes_to_uint16_list(frame)

        # Simulate receiving IP-IDs via Scapy IP/ICMP packets
        base_time = time.time()
        for idx, ip_id in enumerate(ip_ids):
            pkt = IP(id=ip_id, src="127.0.0.1", dst="127.0.0.1") / ICMP(type=8)
            pkt.time = base_time + idx * 0.05
            receiver._packet_handler(pkt)

        event_types = [e.get("type") for e in events]
        assert "rx_packet" in event_types
        assert "rx_sync_detected" in event_types
        assert "rx_fragment" in event_types
        assert "rx_reassembly" in event_types
        assert "rx_auth_status" in event_types
        assert "rx_message_recovered" in event_types

        recovered_ev = next(e for e in events if e.get("type") == "rx_message_recovered")
        assert recovered_ev["message"] == "Secret Reception Test"

        auth_ev = next(e for e in events if e.get("type") == "rx_auth_status")
        assert auth_ev["auth"] == "SUCCESS"
        assert auth_ev["decrypt"] == "SUCCESS"

    def test_header_receiver_auth_failure_event(self):
        events = []
        def callback(evt):
            events.append(evt)

        # Sender encrypts with pass A, Receiver decrypts with pass B
        encrypted = encrypt_message("Tampered Message", "correct_pass")
        frame = create_frame(encrypted)
        ip_ids = bytes_to_uint16_list(frame)

        receiver = HeaderChannelReceiver(passphrase="wrong_pass")
        receiver.set_event_callback(callback)

        base_time = time.time()
        for idx, ip_id in enumerate(ip_ids):
            pkt = IP(id=ip_id, src="127.0.0.1", dst="127.0.0.1") / ICMP(type=8)
            pkt.time = base_time + idx * 0.05
            receiver._packet_handler(pkt)

        auth_events = [e for e in events if e.get("type") == "rx_auth_status"]
        assert len(auth_events) > 0
        assert auth_events[0]["auth"] == "FAILED"
        assert auth_events[0]["decrypt"] == "FAILED"
        assert "error" in auth_events[0]
