"""
tests/test_data_generator.py — Unit tests for the synthetic data generator.

Validates structure, field presence, score ranges, and volume of generated
records to ensure the test data is realistic and well-formed.
"""
from __future__ import annotations

import pytest

from tests.data_generator import (
    generate_normal_log,
    generate_normal_logs,
    generate_port_scan,
    generate_data_exfiltration,
    generate_lateral_movement,
    generate_anomaly_findings,
    generate_baseline_chunks,
    deterministic_embed,
    BASELINE_TEXTS,
)


class TestNormalLogGenerator:
    def test_single_log_structure(self):
        log = generate_normal_log()
        assert "@timestamp" in log
        assert "source" in log
        assert "destination" in log
        assert "network" in log
        assert "host" in log
        assert "_id" in log

    def test_network_bytes_positive(self):
        for _ in range(50):
            log = generate_normal_log()
            assert log["network"]["bytes"] > 0

    def test_bulk_count(self):
        logs = generate_normal_logs(n=100)
        assert len(logs) == 100

    def test_all_have_timestamps(self):
        logs = generate_normal_logs(n=50)
        for log in logs:
            assert "@timestamp" in log
            assert log["@timestamp"]  # not empty

    def test_unique_ids(self):
        logs = generate_normal_logs(n=200)
        ids = [log["_id"] for log in logs]
        assert len(set(ids)) == 200

    def test_destination_ports_are_common(self):
        from tests.data_generator import COMMON_PORTS
        logs = generate_normal_logs(n=100)
        for log in logs:
            port = log["destination"]["port"]
            assert port in COMMON_PORTS

    def test_protocols_are_valid(self):
        valid = {"tcp", "udp", "icmp"}
        logs = generate_normal_logs(n=100)
        for log in logs:
            assert log["network"]["transport"] in valid


class TestAnomalousGenerators:
    def test_port_scan_count(self):
        records = generate_port_scan()
        assert len(records) == 150

    def test_port_scan_type_label(self):
        records = generate_port_scan()
        for r in records:
            assert r["_anomaly_type"] == "port_scan"

    def test_port_scan_unique_ports(self):
        records = generate_port_scan()
        ports = [r["destination"]["port"] for r in records]
        # Should have variety
        assert len(set(ports)) > 50

    def test_exfiltration_high_bytes(self):
        records = generate_data_exfiltration()
        for r in records:
            assert r["source"]["bytes"] >= 5_000_000

    def test_exfiltration_port_443(self):
        records = generate_data_exfiltration()
        for r in records:
            assert r["destination"]["port"] == 443

    def test_lateral_movement_rdp_ssh_smb(self):
        valid_ports = {3389, 22, 445}
        records = generate_lateral_movement()
        for r in records:
            assert r["destination"]["port"] in valid_ports

    def test_lateral_movement_count(self):
        records = generate_lateral_movement()
        assert len(records) == 10


class TestAnomalyFindings:
    def test_total_count(self):
        findings = generate_anomaly_findings(n_normal=5, n_high=3, n_critical=2)
        total = 5 + 3 + 2
        assert len(findings) == total

    def test_score_range_normal(self):
        findings = generate_anomaly_findings(n_normal=20, n_high=0, n_critical=0)
        for f in findings:
            score = f["anomaly_score"]
            assert 0.1 <= score <= 0.65, f"Normal score out of range: {score}"

    def test_score_range_high(self):
        findings = generate_anomaly_findings(n_normal=0, n_high=20, n_critical=0)
        for f in findings:
            score = f["anomaly_score"]
            assert 0.78 <= score <= 0.89, f"High score out of range: {score}"

    def test_score_range_critical(self):
        findings = generate_anomaly_findings(n_normal=0, n_high=0, n_critical=20)
        for f in findings:
            score = f["anomaly_score"]
            assert 0.92 <= score <= 0.99, f"Critical score out of range: {score}"

    def test_required_fields(self):
        findings = generate_anomaly_findings(n_normal=2, n_high=2, n_critical=1)
        required = ["detector_id", "anomaly_score", "entity", "data_start_time", "data_end_time"]
        for f in findings:
            for field in required:
                assert field in f, f"Missing field {field!r} in finding"

    def test_entity_has_value(self):
        findings = generate_anomaly_findings(n_normal=5, n_high=3, n_critical=2)
        for f in findings:
            entity = f.get("entity", {})
            assert "value" in entity
            assert entity["value"]  # not empty

    def test_feature_data_present(self):
        findings = generate_anomaly_findings(n_normal=5, n_high=5, n_critical=5)
        for f in findings:
            assert isinstance(f.get("feature_data"), list)
            assert len(f["feature_data"]) >= 1


class TestBaselineChunks:
    def test_count_matches_source(self):
        chunks = generate_baseline_chunks()
        assert len(chunks) == len(BASELINE_TEXTS)

    def test_chunk_has_required_fields(self):
        chunks = generate_baseline_chunks()
        for c in chunks:
            assert "text" in c
            assert "category" in c
            assert "_id" in c
            assert c["category"] == "network_baseline"

    def test_chunk_ids_are_unique(self):
        chunks = generate_baseline_chunks()
        ids = [c["_id"] for c in chunks]
        assert len(set(ids)) == len(chunks)

    def test_chunk_ids_are_deterministic(self):
        c1 = generate_baseline_chunks()
        c2 = generate_baseline_chunks()
        assert [c["_id"] for c in c1] == [c["_id"] for c in c2]

    def test_chunk_texts_not_empty(self):
        chunks = generate_baseline_chunks()
        for c in chunks:
            assert len(c["text"]) > 50


class TestDeterministicEmbed:
    def test_reproducibility(self):
        text = "This is a reproducibility test"
        v1 = deterministic_embed(text)
        v2 = deterministic_embed(text)
        assert v1 == v2

    def test_dimensions(self):
        for dims in [32, 64, 128, 256]:
            v = deterministic_embed("test", dims=dims)
            assert len(v) == dims

    def test_normalized(self):
        import math
        v = deterministic_embed("normalization check", dims=64)
        norm = math.sqrt(sum(x * x for x in v))
        assert abs(norm - 1.0) < 1e-6

    def test_different_texts_different_embeddings(self):
        v1 = deterministic_embed("text one")
        v2 = deterministic_embed("completely different text")
        # At least one dimension should differ
        assert any(abs(a - b) > 1e-6 for a, b in zip(v1, v2))
