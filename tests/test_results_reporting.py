import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as app_module


def test_missing_experiment_store_starts_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, 'EXPERIMENTS_FILE', str(tmp_path / 'experiments.json'))

    assert app_module.load_experiments() == []
    assert not (tmp_path / 'experiments.json').exists()
    empty_results = app_module.app.test_client().get('/api/results/data').get_json()
    assert empty_results['available'] is False
    assert empty_results['series'] == []


def test_legacy_sample_runs_are_removed_from_experiment_store(tmp_path, monkeypatch):
    store = tmp_path / 'experiments.json'
    store.write_text(json.dumps([
        {'id': 'exp-001', 'name': 'Sample run'},
        {'id': 'exp-real', 'name': 'Actual run'}
    ]), encoding='utf-8')
    monkeypatch.setattr(app_module, 'EXPERIMENTS_FILE', str(store))

    assert app_module.load_experiments() == [{'id': 'exp-real', 'name': 'Actual run'}]
    assert json.loads(store.read_text(encoding='utf-8')) == [
        {'id': 'exp-real', 'name': 'Actual run'}
    ]


def test_experiment_results_report_only_measured_sender_metrics(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, 'EXPERIMENTS_FILE', str(tmp_path / 'experiments.json'))
    client = app_module.app.test_client()

    created = client.post('/api/experiments/create', json={
        'name': 'Reporting check',
        'channel': 'header',
        'payload': 'café',
        'target_ip': '127.0.0.1'
    })
    assert created.status_code == 200
    experiment_id = created.get_json()['experiment']['id']

    class FakeSender:
        def __init__(self, target_ip):
            self.target_ip = target_ip

        def send_message(self, payload, passphrase):
            return {
                'packets_sent': 4,
                'duration_seconds': 1.25,
                'throughput_bps': 32.0,
                'transmission_log': [
                    {'actual_delay_ms': 0.0},
                    {'actual_delay_ms': 10.0},
                    {'actual_delay_ms': 20.0},
                    {'actual_delay_ms': 30.0}
                ]
            }

    monkeypatch.setattr(app_module, 'HeaderChannelSender', FakeSender)
    run = client.post(f'/api/experiments/{experiment_id}/run')
    assert run.status_code == 200
    results = run.get_json()['experiment']['results']
    assert results == {
        'measurement_source': 'sender',
        'payload_bytes': 5,
        'packets_sent': 4,
        'duration_s': 1.25,
        'throughput_bps': 32.0,
        'avg_inter_packet_delay_ms': 20.0
    }

    listed = client.get('/api/experiments/list').get_json()['experiments']
    assert listed[0]['id'] == experiment_id
    viewed = client.get(f'/api/experiments/{experiment_id}/view').get_json()
    assert viewed['experiment']['results']['measurement_source'] == 'sender'

    analytics = client.get('/api/results/data')
    assert analytics.status_code == 200
    data = analytics.get_json()
    assert data['available'] is True
    assert data['experiments_count'] == 1
    assert data['total_packets_transmitted'] == 4
    assert data['avg_throughput_bps'] == 32.0
    assert data['avg_duration_s'] == 1.25
    assert data['avg_inter_packet_delay_ms'] == 20.0
    assert data['series'][0]['payload_bytes'] == 5
    assert 'packet_recovery_rate_pct' not in data
    assert 'payload_integrity_pct' not in data
    assert 'avg_stealth_score' not in data

    report = client.get('/api/results/export_report')
    assert report.status_code == 200
    assert 'Payload Size (bytes)' in report.get_data(as_text=True)
    assert 'Stealth Index' not in report.get_data(as_text=True)


def test_unmeasured_legacy_runs_do_not_appear_as_results(monkeypatch):
    monkeypatch.setattr(app_module, 'load_experiments', lambda: [{
        'id': 'old-run',
        'status': 'Completed',
        'results': {'packets_sent': 100, 'packet_loss_pct': 0.0}
    }])

    data = app_module.app.test_client().get('/api/results/data').get_json()

    assert data['available'] is False
    assert data['experiments_count'] == 0
    assert data['series'] == []


def test_sender_receiver_and_unified_pages_use_real_results_ui():
    client = app_module.app.test_client()

    for path in ('/', '/sender', '/receiver'):
        response = client.get(path)
        assert response.status_code == 200
        page = response.get_data(as_text=True)
        assert 'Packets Sent by Experiment' in page
        assert 'resultsPacketCount' in page
        assert 'experimentTotalCount' in page
        assert 'Header Embedding Test' not in page
        assert 'Transmission Accuracy' not in page
