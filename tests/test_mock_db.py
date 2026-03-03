"""
tests/test_mock_db.py — Unit tests for MockDBConnector.

Validates:
  - Document indexing and retrieval
  - Range query filtering
  - k-NN vector search (cosine similarity ranking)
  - Anomaly findings pagination
  - Bulk indexing
"""
from __future__ import annotations

import math
import uuid
from datetime import datetime, timezone, timedelta

import pytest

from tests.mock_opensearch import MockDBConnector, _cosine_sim
from tests.data_generator import deterministic_embed, generate_normal_logs


class TestCosineSimHelper:
    def test_identical_vectors(self):
        v = [1.0, 0.0, 0.0]
        assert math.isclose(_cosine_sim(v, v), 1.0)

    def test_orthogonal_vectors(self):
        assert math.isclose(_cosine_sim([1.0, 0.0], [0.0, 1.0]), 0.0)

    def test_opposite_vectors(self):
        assert math.isclose(_cosine_sim([1.0], [-1.0]), -1.0)

    def test_zero_vector(self):
        assert _cosine_sim([0.0, 0.0], [1.0, 0.0]) == 0.0


class TestDocumentStorage:
    def test_index_and_retrieve(self, mock_db):
        doc = {"text": "hello", "value": 42}
        mock_db.index_document("test-idx", "doc1", doc)
        results = mock_db.all_documents("test-idx")
        assert len(results) == 1
        assert results[0]["text"] == "hello"

    def test_overwrite_document(self, mock_db):
        mock_db.index_document("test-idx", "doc1", {"v": 1})
        mock_db.index_document("test-idx", "doc1", {"v": 2})
        docs = mock_db.all_documents("test-idx")
        assert len(docs) == 1
        assert docs[0]["v"] == 2

    def test_document_count(self, mock_db):
        for i in range(5):
            mock_db.index_document("test-idx", f"doc{i}", {"n": i})
        assert mock_db.document_count("test-idx") == 5

    def test_empty_index_returns_empty(self, mock_db):
        assert mock_db.all_documents("nonexistent") == []

    def test_bulk_index(self, mock_db):
        docs = [{"_id": f"b{i}", "val": i} for i in range(10)]
        result = mock_db.bulk_index("bulk-idx", docs)
        assert result["success"] == 10
        assert mock_db.document_count("bulk-idx") == 10


class TestSearch:
    def test_match_all(self, mock_db):
        logs = generate_normal_logs(n=50)
        mock_db.seed_documents("logs", logs)
        result = mock_db.search("logs", {"query": {"match_all": {}}}, size=100)
        assert len(result) == 50

    def test_size_limiting(self, mock_db):
        logs = generate_normal_logs(n=100)
        mock_db.seed_documents("logs", logs)
        result = mock_db.search("logs", {}, size=10)
        assert len(result) == 10

    def test_range_filter_timestamp(self, mock_db):
        now = datetime.now(timezone.utc)
        old = (now - timedelta(hours=8)).isoformat()
        recent = (now - timedelta(hours=2)).isoformat()

        mock_db.index_document("logs", "old", {"@timestamp": old, "label": "old"})
        mock_db.index_document("logs", "new", {"@timestamp": recent, "label": "new"})

        threshold_ms = int((now - timedelta(hours=4)).timestamp() * 1000)
        query = {
            "query": {
                "range": {
                    "@timestamp": {"gte": threshold_ms, "format": "epoch_millis"}
                }
            }
        }
        result = mock_db.search("logs", query)
        labels = [r["label"] for r in result]
        assert "new" in labels
        assert "old" not in labels

    def test_term_filter(self, mock_db):
        mock_db.index_document("idx", "a", {"category": "alpha", "val": 1})
        mock_db.index_document("idx", "b", {"category": "beta", "val": 2})
        result = mock_db.search("idx", {"query": {"term": {"category": "alpha"}}})
        assert len(result) == 1
        assert result[0]["val"] == 1

    def test_bool_must_filter(self, mock_db):
        mock_db.index_document("idx", "1", {"category": "net", "severity": "high"})
        mock_db.index_document("idx", "2", {"category": "net", "severity": "low"})
        mock_db.index_document("idx", "3", {"category": "auth", "severity": "high"})

        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"category": "net"}},
                        {"term": {"severity": "high"}},
                    ]
                }
            }
        }
        result = mock_db.search("idx", query)
        assert len(result) == 1
        assert result[0]["severity"] == "high"


class TestKNNSearch:
    def test_returns_most_similar(self, mock_db):
        dims = 64
        anchor = deterministic_embed("port scan detection", dims=dims)
        similar = deterministic_embed("port scanning activity", dims=dims)
        unrelated = deterministic_embed("purple elephant dancing", dims=dims)

        mock_db.index_document(
            "vecs", "a1",
            {"text": "port scanning activity", "embedding": similar, "category": "net"}
        )
        mock_db.index_document(
            "vecs", "a2",
            {"text": "purple elephant dancing", "embedding": unrelated, "category": "net"}
        )

        results = mock_db.knn_search("vecs", anchor, k=2)
        assert results[0]["text"] == "port scanning activity"

    def test_category_filter(self, mock_db):
        vec = deterministic_embed("test", dims=64)
        mock_db.index_document("vecs", "x1", {"text": "alpha", "embedding": vec, "category": "net"})
        mock_db.index_document("vecs", "x2", {"text": "beta", "embedding": vec, "category": "auth"})

        results = mock_db.knn_search("vecs", vec, k=5, filters={"term": {"category": "net"}})
        assert all(r["category"] == "net" for r in results)
        assert len(results) == 1

    def test_knn_respects_k(self, mock_db):
        vec = deterministic_embed("x", dims=64)
        for i in range(20):
            mock_db.index_document("vecs", f"doc{i}", {"embedding": vec, "text": f"doc{i}"})
        results = mock_db.knn_search("vecs", vec, k=5)
        assert len(results) <= 5

    def test_knn_scores_sorted_descending(self, mock_db):
        vec = deterministic_embed("baseline", dims=64)
        for i in range(10):
            v2 = deterministic_embed(f"text number {i}", dims=64)
            mock_db.index_document("vecs", f"d{i}", {"embedding": v2, "text": f"t{i}"})
        results = mock_db.knn_search("vecs", vec, k=10)
        scores = [r["_score"] for r in results]
        assert scores == sorted(scores, reverse=True)


class TestAnomalyFindings:
    def test_fetch_all_findings(self, mock_db):
        from tests.data_generator import generate_anomaly_findings
        findings = generate_anomaly_findings(
            detector_id="det-1", n_normal=5, n_high=2, n_critical=1
        )
        mock_db.seed_anomaly_findings(findings)
        result = mock_db.get_anomaly_findings("det-1", size=50)
        assert len(result) == 8

    def test_wrong_detector_returns_empty(self, mock_db):
        from tests.data_generator import generate_anomaly_findings
        findings = generate_anomaly_findings(detector_id="det-A")
        mock_db.seed_anomaly_findings(findings)
        result = mock_db.get_anomaly_findings("det-Z")
        assert result == []

    def test_from_epoch_ms_cursor(self, mock_db):
        from tests.data_generator import _epoch_ms
        now = datetime.now(timezone.utc)
        old_ts = int((now - timedelta(hours=2)).timestamp() * 1000)
        new_ts = int(now.timestamp() * 1000)

        mock_db.seed_anomaly_findings([
            {"detector_id": "d", "anomaly_score": 0.9, "data_end_time": old_ts},
            {"detector_id": "d", "anomaly_score": 0.8, "data_end_time": new_ts},
        ])
        cursor = int((now - timedelta(minutes=30)).timestamp() * 1000)
        results = mock_db.get_anomaly_findings("d", from_epoch_ms=cursor)
        assert len(results) == 1
        assert results[0]["data_end_time"] == new_ts
