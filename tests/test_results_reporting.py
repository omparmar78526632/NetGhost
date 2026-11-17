"""
Results & Experiments Reporting Tests
Validates that the sender and receiver Flask apps expose working
experiment/settings stubs, and that the main pages load correctly.
(app.py was removed; sender_app and receiver_app are independent nodes.)
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sender.sender_app as sender_module
import receiver.receiver_app as receiver_module


def test_missing_experiment_store_starts_empty():
    """Sender app returns empty experiments list."""
    client = sender_module.app.test_client()
    resp = client.get('/api/experiments')
    assert resp.status_code == 200
    data = resp.get_json()
    assert 'experiments' in data
    assert data['experiments'] == []


def test_legacy_sample_runs_are_removed_from_experiment_store():
    """Sender experiment store starts empty — no legacy sample data."""
    client = sender_module.app.test_client()
    resp = client.get('/api/experiments')
    experiments = resp.get_json().get('experiments', [])
    # No pre-seeded 'exp-001' or 'exp-002' sample runs should appear
    ids = [e.get('id') for e in experiments]
    assert 'exp-001' not in ids
    assert 'exp-002' not in ids


def test_experiment_results_report_only_measured_sender_metrics():
    """Overview endpoint returns expected metric keys."""
    client = sender_module.app.test_client()
    resp = client.get('/api/overview')
    assert resp.status_code == 200
    data = resp.get_json()

    # Required keys from sender overview
    assert 'status' in data
    assert 'active_channel' in data
    assert 'total_packets_sent' in data
    assert 'gmm_available' in data
    assert 'pipeline' in data

    # Must NOT contain legacy/fake receiver-fabricated fields
    assert 'packet_recovery_rate_pct' not in data
    assert 'payload_integrity_pct' not in data


def test_unmeasured_legacy_runs_do_not_appear_as_results():
    """Receiver state endpoint returns safe empty state when no receiver running."""
    client = receiver_module.app.test_client()
    resp = client.get('/api/receiver/state')
    assert resp.status_code == 200
    data = resp.get_json()
    assert data['success'] is True
    rx = data['data']

    # No messages or errors should be present by default
    assert rx['last_message'] is None
    assert rx['last_error'] is None
    assert rx['decryption_success'] is False
    assert rx['running'] is False


def test_sender_receiver_pages_load_successfully():
    """Sender and receiver root pages respond HTTP 200."""
    sender_client = sender_module.app.test_client()
    receiver_client = receiver_module.app.test_client()

    for path in ('/', '/sender'):
        resp = sender_client.get(path)
        assert resp.status_code == 200, f"Sender {path} returned {resp.status_code}"

    for path in ('/', '/receiver'):
        resp = receiver_client.get(path)
        assert resp.status_code == 200, f"Receiver {path} returned {resp.status_code}"
