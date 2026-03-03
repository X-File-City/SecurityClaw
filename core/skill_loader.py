"""
core/skill_loader.py — Dynamic skill discovery and registry.

Each skill lives in skills/<skill_name>/ and contains:
  - logic.py        Python module with a `run(context: dict) -> dict` function
  - instruction.md  LLM system-prompt / guidance for that skill
"""
from __future__ import annotations

import importlib.util
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from core.config import Config

logger = logging.getLogger(__name__)


@dataclass
class Skill:
    name: str
    instruction: str
    run: Callable[[dict], dict]
    schedule_interval_seconds: Optional[int] = None
    metadata: dict = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"<Skill name={self.name!r} interval={self.schedule_interval_seconds}s>"


class SkillLoader:
    """
    Scans the skills directory, loads each skill's instruction.md and
    logic.py, and returns a registry of Skill objects.
    """

    def __init__(self, skills_dir: Optional[Path] = None) -> None:
        cfg = Config()
        default = Path(cfg.get("agent", "skills_dir", default="skills"))
        self.skills_dir = skills_dir or default
        if not self.skills_dir.is_absolute():
            self.skills_dir = Path(__file__).parent.parent / self.skills_dir
        self._registry: dict[str, Skill] = {}

    def discover(self) -> dict[str, Skill]:
        """Walk the skills directory and load all valid skills."""
        self._registry = {}
        if not self.skills_dir.exists():
            logger.warning("Skills directory not found: %s", self.skills_dir)
            return self._registry

        for skill_dir in sorted(self.skills_dir.iterdir()):
            if not skill_dir.is_dir():
                continue
            logic_path = skill_dir / "logic.py"
            instruction_path = skill_dir / "instruction.md"

            if not logic_path.exists():
                logger.debug("Skipping %s — no logic.py", skill_dir.name)
                continue

            instruction = ""
            if instruction_path.exists():
                instruction = instruction_path.read_text(encoding="utf-8")

            run_fn = self._load_run_fn(skill_dir.name, logic_path)
            if run_fn is None:
                continue

            interval = self._extract_interval(instruction)
            skill = Skill(
                name=skill_dir.name,
                instruction=instruction,
                run=run_fn,
                schedule_interval_seconds=interval,
                metadata={"dir": str(skill_dir)},
            )
            self._registry[skill.name] = skill
            logger.info("Loaded skill: %s (interval=%ss)", skill.name, interval)

        return self._registry

    @property
    def registry(self) -> dict[str, Skill]:
        return self._registry

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load_run_fn(
        self, skill_name: str, logic_path: Path
    ) -> Optional[Callable[[dict], dict]]:
        module_name = f"skills.{skill_name}.logic"
        try:
            spec = importlib.util.spec_from_file_location(module_name, logic_path)
            module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
            sys.modules[module_name] = module
            spec.loader.exec_module(module)  # type: ignore[union-attr]

            if not hasattr(module, "run"):
                logger.warning("Skill %s: logic.py has no `run` function", skill_name)
                return None

            return module.run
        except Exception as exc:
            logger.error("Failed to load skill %s: %s", skill_name, exc)
            return None

    @staticmethod
    def _extract_interval(instruction: str) -> Optional[int]:
        """
        Parse an optional YAML-like front-matter block from instruction.md.

        Example front-matter:
            ---
            schedule_interval_seconds: 60
            ---
        """
        import re

        match = re.search(
            r"schedule_interval_seconds:\s*(\d+)", instruction
        )
        if match:
            return int(match.group(1))
        return None
