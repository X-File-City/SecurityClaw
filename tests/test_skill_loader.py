"""
tests/test_skill_loader.py — Tests for dynamic skill discovery.

Validates:
  - Correct skill discovery from directory
  - instruction.md loading
  - schedule_interval_seconds extraction from front-matter
  - Graceful handling of missing logic.py or broken modules
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from core.skill_loader import SkillLoader


@pytest.fixture
def skills_root(tmp_path) -> Path:
    """Create a temporary skills directory for isolated tests."""
    skills = tmp_path / "skills"
    skills.mkdir()
    return skills


def _make_skill(root: Path, name: str, instruction: str = "", run_body: str = "return {}") -> Path:
    """Helper to create a minimal skill subdirectory."""
    skill_dir = root / name
    skill_dir.mkdir()
    (skill_dir / "instruction.md").write_text(instruction)
    (skill_dir / "logic.py").write_text(
        textwrap.dedent(f"""\
        def run(context):
            {run_body}
        """)
    )
    return skill_dir


class TestSkillDiscovery:
    def test_empty_directory_returns_empty(self, skills_root):
        loader = SkillLoader(skills_dir=skills_root)
        result = loader.discover()
        assert result == {}

    def test_single_skill_loaded(self, skills_root):
        _make_skill(skills_root, "my_skill", instruction="# My Skill")
        loader = SkillLoader(skills_dir=skills_root)
        result = loader.discover()
        assert "my_skill" in result

    def test_multiple_skills_loaded(self, skills_root):
        for name in ["skill_a", "skill_b", "skill_c"]:
            _make_skill(skills_root, name)
        loader = SkillLoader(skills_dir=skills_root)
        result = loader.discover()
        assert set(result.keys()) == {"skill_a", "skill_b", "skill_c"}

    def test_directory_without_logic_skipped(self, skills_root):
        bad_dir = skills_root / "no_logic"
        bad_dir.mkdir()
        (bad_dir / "instruction.md").write_text("# no logic here")
        loader = SkillLoader(skills_dir=skills_root)
        result = loader.discover()
        assert "no_logic" not in result

    def test_files_in_root_not_loaded(self, skills_root):
        # A file (not a directory) should be ignored
        (skills_root / "stray_file.py").write_text("print('hello')")
        loader = SkillLoader(skills_dir=skills_root)
        result = loader.discover()
        assert "stray_file" not in result

    def test_nonexistent_directory_returns_empty(self, tmp_path):
        loader = SkillLoader(skills_dir=tmp_path / "does_not_exist")
        result = loader.discover()
        assert result == {}


class TestInstructionLoading:
    def test_instruction_content_loaded(self, skills_root):
        _make_skill(skills_root, "inst_skill", instruction="# Title\nSome instruction text.")
        loader = SkillLoader(skills_dir=skills_root)
        result = loader.discover()
        assert "Some instruction text." in result["inst_skill"].instruction

    def test_missing_instruction_file_ok(self, skills_root):
        skill_dir = skills_root / "no_md"
        skill_dir.mkdir()
        (skill_dir / "logic.py").write_text("def run(c): return {}")
        loader = SkillLoader(skills_dir=skills_root)
        result = loader.discover()
        assert "no_md" in result
        assert result["no_md"].instruction == ""


class TestIntervalParsing:
    def test_parses_schedule_interval(self, skills_root):
        instruction = "---\nschedule_interval_seconds: 120\n---\n# Skill"
        _make_skill(skills_root, "timed_skill", instruction=instruction)
        loader = SkillLoader(skills_dir=skills_root)
        result = loader.discover()
        assert result["timed_skill"].schedule_interval_seconds == 120

    def test_no_interval_returns_none(self, skills_root):
        _make_skill(skills_root, "no_interval", instruction="# No interval here")
        loader = SkillLoader(skills_dir=skills_root)
        result = loader.discover()
        assert result["no_interval"].schedule_interval_seconds is None


class TestRunFunction:
    def test_skill_run_callable(self, skills_root):
        _make_skill(skills_root, "callable_skill", run_body="return {'status': 'ok'}")
        loader = SkillLoader(skills_dir=skills_root)
        result = loader.discover()
        output = result["callable_skill"].run({"db": None, "llm": None})
        assert output == {"status": "ok"}

    def test_skill_run_receives_context(self, skills_root):
        skill_dir = skills_root / "ctx_skill"
        skill_dir.mkdir()
        (skill_dir / "instruction.md").write_text("")
        (skill_dir / "logic.py").write_text(
            "def run(context):\n    return {'got': context.get('key')}\n"
        )
        loader = SkillLoader(skills_dir=skills_root)
        result = loader.discover()
        output = result["ctx_skill"].run({"key": "value_from_runner"})
        assert output == {"got": "value_from_runner"}

    def test_broken_logic_module_skipped(self, skills_root):
        skill_dir = skills_root / "broken_skill"
        skill_dir.mkdir()
        (skill_dir / "instruction.md").write_text("")
        (skill_dir / "logic.py").write_text("this is not valid python !!!")
        loader = SkillLoader(skills_dir=skills_root)
        result = loader.discover()
        assert "broken_skill" not in result

    def test_missing_run_function_skipped(self, skills_root):
        skill_dir = skills_root / "no_run_fn"
        skill_dir.mkdir()
        (skill_dir / "instruction.md").write_text("")
        (skill_dir / "logic.py").write_text("def not_run(): pass\n")
        loader = SkillLoader(skills_dir=skills_root)
        result = loader.discover()
        assert "no_run_fn" not in result
