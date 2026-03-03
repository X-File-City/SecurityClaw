"""
tests/test_runner.py — Integration tests for the Runner conductor.

Validates:
  - Skill discovery and wiring
  - Context building (db, llm, memory injected)
  - Manual dispatch via runner
  - Graceful handling of empty skills directory
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from core.runner import Runner
from tests.mock_llm import MockLLMProvider
from tests.mock_opensearch import MockDBConnector


@pytest.fixture
def minimal_skills_dir(tmp_path) -> Path:
    skills = tmp_path / "skills"
    skills.mkdir()

    # Skill A — returns a fixed result
    sa = skills / "skill_alpha"
    sa.mkdir()
    (sa / "instruction.md").write_text("---\nschedule_interval_seconds: 999\n---\n# Alpha")
    (sa / "logic.py").write_text("def run(ctx): return {'skill': 'alpha', 'has_db': ctx['db'] is not None}\n")

    # Skill B — returns the memory status
    sb = skills / "skill_beta"
    sb.mkdir()
    (sb / "instruction.md").write_text("---\nschedule_interval_seconds: 999\n---\n# Beta")
    (sb / "logic.py").write_text(
        "def run(ctx): return {'status': ctx['memory'].snapshot()['status']}\n"
    )
    return skills


class TestRunnerSetup:
    def test_discovers_skills(self, minimal_skills_dir, tmp_path):
        runner = Runner(
            db_connector=MockDBConnector(),
            llm_provider=MockLLMProvider(),
            skills_dir=minimal_skills_dir,
            situation_path=tmp_path / "SIT.md",
        )
        runner.setup()
        assert "skill_alpha" in runner._skills
        assert "skill_beta" in runner._skills

    def test_empty_skills_dir_no_crash(self, tmp_path):
        empty_skills = tmp_path / "empty_skills"
        empty_skills.mkdir()
        runner = Runner(
            db_connector=MockDBConnector(),
            llm_provider=MockLLMProvider(),
            skills_dir=empty_skills,
            situation_path=tmp_path / "SIT.md",
        )
        runner.setup()  # Should not raise
        assert runner._skills == {}


class TestRunnerDispatch:
    def test_dispatch_skill_alpha(self, minimal_skills_dir, tmp_path):
        runner = Runner(
            db_connector=MockDBConnector(),
            llm_provider=MockLLMProvider(),
            skills_dir=minimal_skills_dir,
            situation_path=tmp_path / "SIT.md",
        )
        runner.setup()
        result = runner.dispatch("skill_alpha")
        assert result["skill"] == "alpha"
        assert result["has_db"] is True

    def test_dispatch_injects_db_and_llm(self, minimal_skills_dir, tmp_path):
        db = MockDBConnector()
        llm = MockLLMProvider()
        runner = Runner(
            db_connector=db,
            llm_provider=llm,
            skills_dir=minimal_skills_dir,
            situation_path=tmp_path / "SIT.md",
        )
        runner.setup()
        result = runner.dispatch("skill_alpha")
        assert result["has_db"] is True

    def test_dispatch_injects_memory(self, minimal_skills_dir, tmp_path):
        runner = Runner(
            db_connector=MockDBConnector(),
            llm_provider=MockLLMProvider(),
            skills_dir=minimal_skills_dir,
            situation_path=tmp_path / "SIT.md",
        )
        runner.setup()
        result = runner.dispatch("skill_beta")
        # Memory is initialized — status should be non-empty string
        assert isinstance(result["status"], str)
        assert len(result["status"]) > 0

    def test_dispatch_unknown_skill_raises(self, minimal_skills_dir, tmp_path):
        runner = Runner(
            db_connector=MockDBConnector(),
            llm_provider=MockLLMProvider(),
            skills_dir=minimal_skills_dir,
            situation_path=tmp_path / "SIT.md",
        )
        runner.setup()
        with pytest.raises(KeyError):
            runner.dispatch("nonexistent_skill")

    def test_dispatch_with_explicit_context(self, minimal_skills_dir, tmp_path):
        skills = tmp_path / "ctx_skills"
        skills.mkdir()
        sk = skills / "ctx_sk"
        sk.mkdir()
        (sk / "instruction.md").write_text("")
        (sk / "logic.py").write_text("def run(ctx): return ctx.get('extra_key')\n")

        runner = Runner(
            db_connector=MockDBConnector(),
            llm_provider=MockLLMProvider(),
            skills_dir=skills,
            situation_path=tmp_path / "SIT.md",
        )
        runner.setup()
        ctx = runner._build_context()
        ctx["extra_key"] = "hello"
        result = runner.dispatch("ctx_sk", context=ctx)
        assert result == "hello"
