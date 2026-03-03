"""
tests/test_rag.py — Tests for the RAGEngine using mock DB and mock LLM.

Validates:
  - Storing embeddings in the vector index
  - Retrieving similar chunks (semantic relevance ordering)
  - Category-filtered retrieval
  - Context string formatting
  - Bulk store
  - Deterministic embedding stability
"""
from __future__ import annotations

import pytest

from core.rag_engine import RAGEngine
from tests.data_generator import (
    deterministic_embed,
    generate_baseline_chunks,
    BASELINE_TEXTS,
)


class TestDeterministicEmbed:
    def test_same_input_same_output(self):
        v1 = deterministic_embed("network scan detected", dims=64)
        v2 = deterministic_embed("network scan detected", dims=64)
        assert v1 == v2

    def test_different_inputs_differ(self):
        v1 = deterministic_embed("port scan", dims=64)
        v2 = deterministic_embed("normal backup job", dims=64)
        assert v1 != v2

    def test_output_is_normalized(self):
        import math
        v = deterministic_embed("some text here", dims=64)
        norm = math.sqrt(sum(x * x for x in v))
        assert abs(norm - 1.0) < 1e-6

    def test_output_length(self):
        v = deterministic_embed("hello", dims=128)
        assert len(v) == 128

    def test_default_length(self):
        v = deterministic_embed("hello")
        assert len(v) == 64


class TestRAGStore:
    def test_store_creates_document(self, mock_db, mock_llm):
        rag = RAGEngine(db=mock_db, llm=mock_llm)
        doc_id = rag.store("Normal traffic uses HTTPS on port 443.", category="net")
        assert mock_db.document_count("securityclaw-vectors") == 1
        docs = mock_db.all_documents("securityclaw-vectors")
        assert docs[0]["text"] == "Normal traffic uses HTTPS on port 443."
        assert docs[0]["category"] == "net"
        assert len(docs[0]["embedding"]) == 64

    def test_store_returns_consistent_id(self, mock_db, mock_llm):
        rag = RAGEngine(db=mock_db, llm=mock_llm)
        id1 = rag.store("stable text", category="test")
        id2 = rag.store("stable text", category="test")
        assert id1 == id2  # SHA256 of same text yields same ID

    def test_bulk_store(self, mock_db, mock_llm):
        rag = RAGEngine(db=mock_db, llm=mock_llm)
        texts = [f"chunk number {i}" for i in range(10)]
        ids = rag.bulk_store(texts, category="test", source="unit")
        assert len(ids) == 10
        assert mock_db.document_count("securityclaw-vectors") == 10

    def test_store_includes_source(self, mock_db, mock_llm):
        rag = RAGEngine(db=mock_db, llm=mock_llm)
        rag.store("some text", category="x", source="my_skill")
        doc = mock_db.all_documents("securityclaw-vectors")[0]
        assert doc["source"] == "my_skill"

    def test_store_includes_timestamp(self, mock_db, mock_llm):
        rag = RAGEngine(db=mock_db, llm=mock_llm)
        rag.store("text with timestamp", category="x")
        doc = mock_db.all_documents("securityclaw-vectors")[0]
        assert "timestamp" in doc


class TestRAGRetrieve:
    def _seed_baseline(self, mock_db, mock_llm):
        """Seed vector index with baseline texts using mock embedder."""
        rag = RAGEngine(db=mock_db, llm=mock_llm)
        for text in BASELINE_TEXTS:
            mock_db.index_document(
                "securityclaw-vectors",
                text[:20],
                {
                    "text": text,
                    "embedding": mock_llm.embed(text),
                    "category": "network_baseline",
                    "source": "test",
                },
            )
        return rag

    def test_retrieve_returns_results(self, mock_db, mock_llm):
        rag = self._seed_baseline(mock_db, mock_llm)
        results = rag.retrieve("port scan activity detected")
        assert len(results) > 0

    def test_most_relevant_chunk_ranked_first(self, mock_db, mock_llm):
        """
        Query about port scanning should rank the port-scan chunk highest.
        Because the mock embedder is deterministic, text similarity maps to
        embedding similarity in a consistent (though not semantic) way.
        We seed two chunks with strongly similar and strongly dissimilar texts,
        then verify ordering.
        """
        mock_db.index_document(
            "securityclaw-vectors",
            "scan",
            {
                "text": "port scanning detection",
                "embedding": deterministic_embed("port scanning detection", dims=64),
                "category": "network_baseline",
            },
        )
        mock_db.index_document(
            "securityclaw-vectors",
            "unrelated",
            {
                "text": "coffee machine maintenance schedule",
                "embedding": deterministic_embed("coffee machine maintenance schedule", dims=64),
                "category": "network_baseline",
            },
        )
        rag = RAGEngine(db=mock_db, llm=mock_llm)
        # query embedding = embed("port scanning detection") → same as "scan" doc
        results = rag.retrieve("port scanning detection", k=2)
        assert results[0]["text"] == "port scanning detection"

    def test_category_filter_restricts_results(self, mock_db, mock_llm):
        mock_db.index_document(
            "securityclaw-vectors",
            "c1",
            {"text": "a", "embedding": mock_llm.embed("a"), "category": "net"},
        )
        mock_db.index_document(
            "securityclaw-vectors",
            "c2",
            {"text": "b", "embedding": mock_llm.embed("b"), "category": "auth"},
        )
        rag = RAGEngine(db=mock_db, llm=mock_llm)
        results = rag.retrieve("test", category="net")
        assert all(r["category"] == "net" for r in results)

    def test_retrieve_empty_index(self, mock_db, mock_llm):
        rag = RAGEngine(db=mock_db, llm=mock_llm)
        results = rag.retrieve("anything")
        assert results == []

    def test_retrieve_respects_k(self, mock_db, mock_llm):
        for i in range(20):
            mock_db.index_document(
                "securityclaw-vectors",
                f"d{i}",
                {"text": f"doc {i}", "embedding": mock_llm.embed(f"doc {i}"), "category": "x"},
            )
        rag = RAGEngine(db=mock_db, llm=mock_llm)
        results = rag.retrieve("doc", k=3)
        assert len(results) <= 3


class TestRAGContextString:
    def test_context_string_not_empty(self, mock_db, mock_llm):
        mock_db.index_document(
            "securityclaw-vectors",
            "x",
            {"text": "baseline info", "embedding": mock_llm.embed("baseline info"), "category": "c"},
        )
        rag = RAGEngine(db=mock_db, llm=mock_llm)
        ctx = rag.build_context_string("baseline info")
        assert "baseline info" in ctx

    def test_context_string_empty_index(self, mock_db, mock_llm):
        rag = RAGEngine(db=mock_db, llm=mock_llm)
        ctx = rag.build_context_string("anything")
        assert "No relevant context" in ctx

    def test_context_string_has_numbered_items(self, mock_db, mock_llm):
        for i in range(3):
            t = f"chunk {i}"
            mock_db.index_document(
                "securityclaw-vectors",
                f"c{i}",
                {"text": t, "embedding": mock_llm.embed(t), "category": "z"},
            )
        rag = RAGEngine(db=mock_db, llm=mock_llm)
        ctx = rag.build_context_string("chunk", k=3)
        assert "1." in ctx
        assert "2." in ctx
