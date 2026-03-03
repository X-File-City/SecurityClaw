"""
tests/test_mock_llm.py — Tests for MockLLMProvider.

Ensures the mock produces valid, parseable JSON for each skill path
and that embeddings are deterministic and normalized.
"""
from __future__ import annotations

import json
import math

import pytest

from tests.mock_llm import MockLLMProvider


@pytest.fixture
def llm():
    return MockLLMProvider(dims=64)


class TestEmbedding:
    def test_returns_correct_dims(self, llm):
        v = llm.embed("test text")
        assert len(v) == 64

    def test_deterministic(self, llm):
        v1 = llm.embed("same text")
        v2 = llm.embed("same text")
        assert v1 == v2

    def test_different_texts(self, llm):
        v1 = llm.embed("text one about ports")
        v2 = llm.embed("text two about elephants")
        assert v1 != v2

    def test_normalized(self, llm):
        v = llm.embed("normalization test")
        norm = math.sqrt(sum(x * x for x in v))
        assert abs(norm - 1.0) < 1e-6

    def test_logged_in_call_log(self, llm):
        llm.embed("logged text")
        assert any(c["type"] == "embed" for c in llm.call_log)


class TestChatBaseline:
    def test_baseline_response_valid_json(self, llm):
        messages = [{"role": "user", "content": "Produce a normal behavior baseline summary."}]
        response = llm.chat(messages)
        data = json.loads(response)
        assert "summary" in data
        assert "typical_ports" in data
        assert "category" in data
        assert data["category"] == "network_baseline"

    def test_baseline_ports_are_list_of_ints(self, llm):
        messages = [{"role": "user", "content": "baseline summary"}]
        data = json.loads(llm.chat(messages))
        assert isinstance(data["typical_ports"], list)
        assert all(isinstance(p, int) for p in data["typical_ports"])


class TestChatAnomalyEnrich:
    def test_anomaly_enrich_valid_json(self, llm):
        messages = [
            {"role": "user",
             "content": "Enrich this anomaly detection finding: { ... }"}
        ]
        data = json.loads(llm.chat(messages))
        assert "severity" in data
        assert "description" in data
        assert data["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_entity_field_present(self, llm):
        messages = [{"role": "user", "content": "Enrich this anomaly detection finding"}]
        data = json.loads(llm.chat(messages))
        assert "entity" in data


class TestChatVerdict:
    def test_verdict_valid_json(self, llm):
        messages = [
            {"role": "user",
             "content": "Provide your verdict: is this a false positive or true threat?"}
        ]
        data = json.loads(llm.chat(messages))
        assert data["verdict"] in ("TRUE_THREAT", "FALSE_POSITIVE")
        assert 0 <= data["confidence"] <= 100
        assert "reasoning" in data
        assert "recommended_action" in data

    def test_reasoning_non_empty(self, llm):
        messages = [{"role": "user", "content": "verdict please"}]
        data = json.loads(llm.chat(messages))
        assert len(data["reasoning"]) > 10


class TestCallLog:
    def test_all_calls_logged(self, llm):
        llm.embed("e1")
        llm.chat([{"role": "user", "content": "baseline summary"}])
        llm.embed("e2")
        assert len(llm.call_log) == 3

    def test_call_types_recorded(self, llm):
        llm.embed("x")
        llm.chat([{"role": "user", "content": "verdict"}])
        types = [c["type"] for c in llm.call_log]
        assert "embed" in types
        assert "chat" in types
