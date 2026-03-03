"""
core/memory.py — Manages SITUATION.md as the agent's written working memory.

The SITUATION file is a human-readable Markdown document that records
what the agent is currently investigating, open findings, and recent
decisions. It is read by skill prompts for context and written to after
major state transitions.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from core.config import Config


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class AgentMemory:
    """
    Read/write interface to SITUATION.md.

    Sections tracked:
        - Agent Status      (IDLE | INVESTIGATING | ESCALATING)
        - Active Investigation
        - Open Findings     (list)
        - Recent Decisions  (list)
        - Escalation Queue  (list)
    """

    SECTIONS = [
        "Agent Status",
        "Current Focus",
        "Open Findings",
        "Recent Decisions",
        "Escalation Queue",
    ]

    def __init__(self, path: Optional[Path] = None) -> None:
        cfg = Config()
        default = Path(cfg.get("agent", "situation_file", default="SITUATION.md"))
        self.path = path or default
        if not self.path.is_absolute():
            self.path = Path(__file__).parent.parent / self.path
        self._ensure_exists()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def read(self) -> str:
        """Return the full raw Markdown content."""
        return self.path.read_text(encoding="utf-8")

    def write_full(self, content: str) -> None:
        """Replace the entire file with new content."""
        self.path.write_text(content, encoding="utf-8")

    def get_section(self, section: str) -> str:
        """Return the body text of a named ## section."""
        content = self.read()
        pattern = rf"##\s+{re.escape(section)}\n(.*?)(?=\n##|\Z)"
        match = re.search(pattern, content, re.DOTALL)
        return match.group(1).strip() if match else ""

    def set_section(self, section: str, body: str) -> None:
        """Replace the body of a named ## section."""
        content = self.read()
        replacement = f"## {section}\n{body}\n"
        pattern = rf"##\s+{re.escape(section)}\n.*?(?=\n##|\Z)"
        new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)
        if f"## {section}" not in new_content:
            new_content = new_content.rstrip() + f"\n\n## {section}\n{body}\n"
        self.write_full(new_content)

    def append_to_section(self, section: str, item: str) -> None:
        """Append a bullet-list item to a named ## section."""
        current = self.get_section(section)
        bullet = f"- [{_now()}] {item}"
        new_body = (current + "\n" + bullet).strip()
        self.set_section(section, new_body)

    def set_status(self, status: str) -> None:
        """Update **Agent Status** and timestamp in the header."""
        content = self.read()
        content = re.sub(
            r"\*\*Agent Status:\*\*.*",
            f"**Agent Status:** {status}",
            content,
        )
        content = re.sub(
            r"\*\*Last Updated:\*\*.*",
            f"**Last Updated:** {_now()}",
            content,
        )
        self.write_full(content)

    def set_focus(self, focus: str) -> None:
        self.set_section("Current Focus", focus)
        self.set_status("INVESTIGATING")

    def clear_focus(self) -> None:
        self.set_section("Current Focus", "None")
        self.set_status("IDLE")

    def add_finding(self, finding: str) -> None:
        self.append_to_section("Open Findings", finding)

    def add_decision(self, decision: str) -> None:
        self.append_to_section("Recent Decisions", decision)

    def escalate(self, item: str) -> None:
        self.append_to_section("Escalation Queue", item)
        self.set_status("ESCALATING")

    def snapshot(self) -> dict:
        """Return a dict summary of current state."""
        return {
            "status": self._extract_header("Agent Status"),
            "focus": self.get_section("Current Focus"),
            "findings": self.get_section("Open Findings"),
            "decisions": self.get_section("Recent Decisions"),
            "escalation": self.get_section("Escalation Queue"),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_header(self, field: str) -> str:
        content = self.read()
        match = re.search(rf"\*\*{re.escape(field)}:\*\*\s*(.*)", content)
        return match.group(1).strip() if match else "UNKNOWN"

    def _ensure_exists(self) -> None:
        if not self.path.exists():
            self.path.write_text(
                f"# SITUATION — Agent Working Memory\n\n"
                f"**Last Updated:** {_now()}  \n"
                f"**Agent Status:** IDLE  \n"
                f"**Active Investigation:** None  \n\n"
                f"---\n\n"
                f"## Current Focus\nNone\n\n"
                f"## Open Findings\nNone\n\n"
                f"## Recent Decisions\nNone\n\n"
                f"## Escalation Queue\nNone\n",
                encoding="utf-8",
            )
