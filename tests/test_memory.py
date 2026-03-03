"""
tests/test_memory.py — Unit tests for AgentMemory.

Tests the full lifecycle of SITUATION.md:
  - Section reading/writing
  - Status transitions
  - Finding and decision append
  - Escalation flow
  - Snapshot
  - File creation on first use
"""
from __future__ import annotations

import pytest
from pathlib import Path

from core.memory import AgentMemory


@pytest.fixture
def tmp_memory(tmp_path) -> AgentMemory:
    return AgentMemory(path=tmp_path / "SITUATION.md")


class TestMemoryInitialization:
    def test_file_created_on_init(self, tmp_path):
        mem = AgentMemory(path=tmp_path / "NEW.md")
        assert (tmp_path / "NEW.md").exists()

    def test_initial_status_idle(self, tmp_memory):
        snap = tmp_memory.snapshot()
        assert snap["status"] == "IDLE"

    def test_initial_sections_exist(self, tmp_memory):
        content = tmp_memory.read()
        for section in ["Current Focus", "Open Findings", "Recent Decisions", "Escalation Queue"]:
            assert section in content


class TestSectionOperations:
    def test_get_section_returns_body(self, tmp_memory):
        body = tmp_memory.get_section("Current Focus")
        assert isinstance(body, str)

    def test_set_section_persists(self, tmp_memory):
        tmp_memory.set_section("Current Focus", "Investigating port scan on 10.0.1.5")
        assert "Investigating port scan" in tmp_memory.get_section("Current Focus")

    def test_set_section_overwrites(self, tmp_memory):
        tmp_memory.set_section("Current Focus", "First value")
        tmp_memory.set_section("Current Focus", "Second value")
        body = tmp_memory.get_section("Current Focus")
        assert "Second value" in body
        assert "First value" not in body

    def test_append_to_section_creates_bullets(self, tmp_memory):
        tmp_memory.append_to_section("Open Findings", "New finding A")
        tmp_memory.append_to_section("Open Findings", "New finding B")
        body = tmp_memory.get_section("Open Findings")
        assert "New finding A" in body
        assert "New finding B" in body

    def test_append_adds_timestamp(self, tmp_memory):
        tmp_memory.append_to_section("Open Findings", "Test item")
        body = tmp_memory.get_section("Open Findings")
        # timestamp is in format [YYYY-MM-DD HH:MM:SS UTC]
        assert "[20" in body  # year starts with 20xx


class TestStatusTransitions:
    def test_set_status_updates_header(self, tmp_memory):
        tmp_memory.set_status("INVESTIGATING")
        content = tmp_memory.read()
        assert "**Agent Status:** INVESTIGATING" in content

    def test_set_focus_changes_status(self, tmp_memory):
        tmp_memory.set_focus("Anomaly on 10.0.1.50")
        snap = tmp_memory.snapshot()
        assert snap["status"] == "INVESTIGATING"
        assert "Anomaly on 10.0.1.50" in snap["focus"]

    def test_clear_focus_returns_to_idle(self, tmp_memory):
        tmp_memory.set_focus("Something")
        tmp_memory.clear_focus()
        snap = tmp_memory.snapshot()
        assert snap["status"] == "IDLE"
        assert "None" in snap["focus"]

    def test_escalate_sets_escalating_status(self, tmp_memory):
        tmp_memory.escalate("Critical threat on web server")
        snap = tmp_memory.snapshot()
        assert snap["status"] == "ESCALATING"
        assert "Critical threat" in snap["escalation"]

    def test_set_status_updates_timestamp(self, tmp_memory):
        tmp_memory.set_status("ACTIVE")
        content = tmp_memory.read()
        assert "**Last Updated:**" in content
        assert "UTC" in content


class TestConvenienceMethods:
    def test_add_finding(self, tmp_memory):
        tmp_memory.add_finding("Port scan detected from 192.168.1.1")
        body = tmp_memory.get_section("Open Findings")
        assert "Port scan detected" in body

    def test_add_decision(self, tmp_memory):
        tmp_memory.add_decision("Marked finding #42 as FALSE_POSITIVE")
        body = tmp_memory.get_section("Recent Decisions")
        assert "FALSE_POSITIVE" in body

    def test_multiple_findings_accumulate(self, tmp_memory):
        for i in range(5):
            tmp_memory.add_finding(f"Finding #{i}")
        body = tmp_memory.get_section("Open Findings")
        for i in range(5):
            assert f"Finding #{i}" in body


class TestSnapshot:
    def test_snapshot_keys(self, tmp_memory):
        snap = tmp_memory.snapshot()
        assert "status" in snap
        assert "focus" in snap
        assert "findings" in snap
        assert "decisions" in snap
        assert "escalation" in snap

    def test_snapshot_reflects_writes(self, tmp_memory):
        tmp_memory.add_finding("test finding")
        tmp_memory.add_decision("test decision")
        snap = tmp_memory.snapshot()
        assert "test finding" in snap["findings"]
        assert "test decision" in snap["decisions"]


class TestReadWrite:
    def test_write_full_replaces_content(self, tmp_memory):
        new_content = "# CLEAN SLATE\n\n## Current Focus\nNew focus\n"
        tmp_memory.write_full(new_content)
        assert tmp_memory.read() == new_content

    def test_read_returns_string(self, tmp_memory):
        content = tmp_memory.read()
        assert isinstance(content, str)
        assert len(content) > 0
