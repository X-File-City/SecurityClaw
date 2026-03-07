"""
core/memory.py — Compact structured working memory persisted under /data.

The memory store is intentionally bounded so it remains useful for agent
reasoning without growing until it becomes expensive to serialize into model
context. The on-disk format is JSON, while the public API still exposes the
section-oriented helpers that existing skills rely on.
"""
from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from core.config import Config

STORE_VERSION = 2
DEFAULT_MEMORY_PATH = "data/agent_memory.json"

LIST_SECTION_KEYS = {
    "Open Findings": "findings",
    "Recent Decisions": "decisions",
    "Escalation Queue": "escalations",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _display_timestamp(value: str | None) -> str:
    if not value:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if value.endswith("UTC"):
        return value
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return value


class AgentMemory:
    """Bounded structured memory with a backwards-compatible section API."""

    SECTIONS = [
        "Agent Status",
        "Current Focus",
        "Open Findings",
        "Recent Decisions",
        "Escalation Queue",
    ]

    def __init__(self, path: Optional[Path] = None) -> None:
        cfg = Config()
        default = Path(cfg.get("memory", "path", default=DEFAULT_MEMORY_PATH))
        self.path = path or default
        if not self.path.is_absolute():
            self.path = Path(__file__).parent.parent / self.path

        self.max_entry_chars = int(cfg.get("memory", "max_entry_chars", default=280) or 280)
        self.max_focus_chars = int(cfg.get("memory", "max_focus_chars", default=400) or 400)
        self.render_entry_limit = int(cfg.get("memory", "render_entry_limit", default=8) or 8)
        self.max_context_chars = int(cfg.get("memory", "max_context_chars", default=4000) or 4000)
        self.section_limits = {
            "Open Findings": int(cfg.get("memory", "findings_limit", default=50) or 50),
            "Recent Decisions": int(cfg.get("memory", "decisions_limit", default=50) or 50),
            "Escalation Queue": int(cfg.get("memory", "escalations_limit", default=25) or 25),
        }
        self._lock = threading.RLock()
        self._ensure_exists()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def read(self) -> str:
        """Return a compact markdown snapshot of the current memory state."""
        with self._lock:
            store = self._load_store()
            return self._render_markdown(store)

    def compact_context(self, max_chars: Optional[int] = None) -> str:
        """Return a bounded memory snapshot suitable for prompt injection."""
        with self._lock:
            store = self._load_store()
            return self._render_markdown(store, max_chars=max_chars or self.max_context_chars)

    def write_full(self, content: str) -> None:
        """Replace the entire memory snapshot, accepting markdown or JSON input."""
        with self._lock:
            store = self._parse_content(content)
            self._save_store(store)

    def get_section(self, section: str) -> str:
        """Return the rendered body text for a named memory section."""
        with self._lock:
            store = self._load_store()
            if section == "Agent Status":
                return store["status"]
            if section == "Current Focus":
                return store["focus"] or "None"
            section_key = LIST_SECTION_KEYS.get(section)
            if not section_key:
                return ""
            return self._render_entries(store["sections"][section_key])

    def set_section(self, section: str, body: str) -> None:
        """Replace the body of a named memory section."""
        with self._lock:
            store = self._load_store()
            if section == "Agent Status":
                store["status"] = self._normalize_scalar(body, max_chars=32) or "UNKNOWN"
            elif section == "Current Focus":
                store["focus"] = self._normalize_scalar(body, max_chars=self.max_focus_chars) or "None"
            else:
                section_key = LIST_SECTION_KEYS.get(section)
                if not section_key:
                    return
                store["sections"][section_key] = self._parse_section_entries(body, limit=self.section_limits[section])
            self._touch(store)
            self._save_store(store)

    def append_to_section(self, section: str, item: str) -> None:
        """Append a timestamped item to one of the list-style sections."""
        if section not in LIST_SECTION_KEYS:
            self.set_section(section, item)
            return

        with self._lock:
            store = self._load_store()
            section_key = LIST_SECTION_KEYS[section]
            entries = store["sections"][section_key]
            text = self._normalize_scalar(item, max_chars=self.max_entry_chars)
            if not text:
                return
            entries.append({"timestamp": _now_iso(), "text": text})
            limit = self.section_limits[section]
            if len(entries) > limit:
                del entries[:-limit]
            self._touch(store)
            self._save_store(store)

    def set_status(self, status: str) -> None:
        """Update the agent status and refresh the timestamp."""
        with self._lock:
            store = self._load_store()
            store["status"] = self._normalize_scalar(status, max_chars=32) or "UNKNOWN"
            self._touch(store)
            self._save_store(store)

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

    def snapshot(self) -> dict[str, str]:
        """Return a string-based summary of the current memory state."""
        return {
            "status": self.get_section("Agent Status"),
            "focus": self.get_section("Current Focus"),
            "findings": self.get_section("Open Findings"),
            "decisions": self.get_section("Recent Decisions"),
            "escalation": self.get_section("Escalation Queue"),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _default_store(self) -> dict[str, Any]:
        return {
            "version": STORE_VERSION,
            "last_updated": _now_iso(),
            "status": "IDLE",
            "focus": "None",
            "sections": {
                "findings": [],
                "decisions": [],
                "escalations": [],
            },
        }

    def _ensure_exists(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._save_store(self._default_store())
            return
        self._load_store()

    def _load_store(self) -> dict[str, Any]:
        raw = self.path.read_text(encoding="utf-8").strip()
        if not raw:
            store = self._default_store()
            self._save_store(store)
            return store
        try:
            payload = json.loads(raw)
            return self._normalize_store(payload)
        except json.JSONDecodeError:
            store = self._parse_markdown(raw)
            self._save_store(store)
            return store

    def _save_store(self, store: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(self._normalize_store(store), indent=2), encoding="utf-8")

    def _normalize_store(self, payload: dict[str, Any]) -> dict[str, Any]:
        store = self._default_store()
        store["last_updated"] = payload.get("last_updated") or _now_iso()
        store["status"] = self._normalize_scalar(payload.get("status", "IDLE"), max_chars=32) or "IDLE"
        store["focus"] = self._normalize_scalar(payload.get("focus", "None"), max_chars=self.max_focus_chars) or "None"

        source_sections = payload.get("sections", {}) if isinstance(payload.get("sections"), dict) else {}
        for section_name, section_key in LIST_SECTION_KEYS.items():
            store["sections"][section_key] = self._normalize_entries(
                source_sections.get(section_key, []),
                limit=self.section_limits[section_name],
            )
        return store

    def _normalize_entries(self, values: Any, *, limit: int) -> list[dict[str, str]]:
        entries: list[dict[str, str]] = []
        if isinstance(values, str):
            return self._parse_section_entries(values, limit=limit)
        if not isinstance(values, list):
            return entries

        for item in values:
            if isinstance(item, dict):
                text = self._normalize_scalar(item.get("text", ""), max_chars=self.max_entry_chars)
                if not text:
                    continue
                entries.append({
                    "timestamp": item.get("timestamp") or _now_iso(),
                    "text": text,
                })
            elif isinstance(item, str):
                text = self._normalize_scalar(item, max_chars=self.max_entry_chars)
                if text:
                    entries.append({"timestamp": _now_iso(), "text": text})
        if len(entries) > limit:
            return entries[-limit:]
        return entries

    def _parse_content(self, content: str) -> dict[str, Any]:
        text = (content or "").strip()
        if not text:
            return self._default_store()
        try:
            return self._normalize_store(json.loads(text))
        except json.JSONDecodeError:
            return self._parse_markdown(text)

    def _parse_markdown(self, content: str) -> dict[str, Any]:
        store = self._default_store()
        status_match = re.search(r"\*\*Agent Status:\*\*\s*(.*)", content)
        if status_match:
            store["status"] = self._normalize_scalar(status_match.group(1), max_chars=32) or "IDLE"

        updated_match = re.search(r"\*\*Last Updated:\*\*\s*(.*)", content)
        if updated_match:
            store["last_updated"] = updated_match.group(1).strip() or _now_iso()

        focus = self._extract_markdown_section(content, "Current Focus")
        store["focus"] = self._normalize_scalar(focus, max_chars=self.max_focus_chars) or "None"

        for section_name, section_key in LIST_SECTION_KEYS.items():
            body = self._extract_markdown_section(content, section_name)
            store["sections"][section_key] = self._parse_section_entries(body, limit=self.section_limits[section_name])

        self._touch(store)
        return store

    def _extract_markdown_section(self, content: str, section: str) -> str:
        pattern = rf"##\s+{re.escape(section)}\n(.*?)(?=\n##|\Z)"
        match = re.search(pattern, content, re.DOTALL)
        return match.group(1).strip() if match else ""

    def _parse_section_entries(self, body: str, *, limit: int) -> list[dict[str, str]]:
        text = (body or "").strip()
        if not text or text == "None":
            return []

        entries: list[dict[str, str]] = []
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        bullet_lines = [line for line in lines if line.startswith("-")]

        if bullet_lines:
            for line in bullet_lines:
                match = re.match(r"-\s+\[(.*?)\]\s+(.*)", line)
                if match:
                    timestamp, item_text = match.groups()
                else:
                    timestamp, item_text = _now_iso(), line.lstrip("- ").strip()
                item_text = self._normalize_scalar(item_text, max_chars=self.max_entry_chars)
                if item_text and not item_text.startswith("..."):
                    entries.append({"timestamp": timestamp, "text": item_text})
        else:
            normalized = self._normalize_scalar(text, max_chars=self.max_entry_chars)
            if normalized and normalized != "None":
                entries.append({"timestamp": _now_iso(), "text": normalized})

        if len(entries) > limit:
            return entries[-limit:]
        return entries

    def _normalize_scalar(self, value: Any, *, max_chars: int) -> str:
        text = " ".join(str(value or "").strip().split())
        if len(text) <= max_chars:
            return text
        return text[: max_chars - 1].rstrip() + "…"

    def _render_entries(self, entries: list[dict[str, str]], max_items: Optional[int] = None) -> str:
        if not entries:
            return "None"
        selected = entries if max_items is None else entries[-max_items:]
        lines = [f"- [{_display_timestamp(item.get('timestamp'))}] {item.get('text', '')}" for item in selected]
        omitted = len(entries) - len(selected)
        if omitted > 0:
            lines.append(f"- ... {omitted} older item(s) omitted")
        return "\n".join(lines)

    def _render_markdown(self, store: dict[str, Any], max_chars: Optional[int] = None) -> str:
        content = (
            "# Agent Memory\n\n"
            f"**Last Updated:** {_display_timestamp(store['last_updated'])}  \n"
            f"**Agent Status:** {store['status']}  \n"
            f"**Storage Path:** {self.path.name}  \n\n"
            f"## Current Focus\n{store['focus'] or 'None'}\n\n"
            f"## Open Findings\n{self._render_entries(store['sections']['findings'], max_items=self.render_entry_limit)}\n\n"
            f"## Recent Decisions\n{self._render_entries(store['sections']['decisions'], max_items=self.render_entry_limit)}\n\n"
            f"## Escalation Queue\n{self._render_entries(store['sections']['escalations'], max_items=self.render_entry_limit)}\n"
        )
        budget = max_chars or self.max_context_chars
        if len(content) <= budget:
            return content
        return content[: budget - 1].rstrip() + "…"

    def _touch(self, store: dict[str, Any]) -> None:
        store["last_updated"] = _now_iso()
        if not store.get("focus"):
            store["focus"] = "None"
