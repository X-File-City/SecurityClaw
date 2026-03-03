"""
skills/threat_analyst/logic.py

RAG-powered reasoning loop that reviews HIGH/CRITICAL findings queued
by AnomalyWatcher, retrieves behavioral baseline context, and issues
a verdict (FALSE_POSITIVE | TRUE_THREAT).

Context keys consumed:
    context["db"]     -> BaseDBConnector
    context["llm"]    -> BaseLLMProvider
    context["memory"] -> AgentMemory
    context["config"] -> Config
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

INSTRUCTION_PATH = Path(__file__).parent / "instruction.md"
SKILL_NAME = "threat_analyst"


def run(context: dict) -> dict:
    """Entry point called by the Runner."""
    db = context.get("db")
    llm = context.get("llm")
    memory = context.get("memory")
    cfg = context.get("config")

    if db is None or llm is None:
        logger.warning("[%s] db or llm not available — skipping.", SKILL_NAME)
        return {"status": "skipped", "reason": "no db/llm"}

    instruction = INSTRUCTION_PATH.read_text(encoding="utf-8")

    # ── 1. Read escalation queue from memory ──────────────────────────────────
    escalations = _parse_escalations(memory)
    if not escalations:
        logger.debug("[%s] No escalations pending.", SKILL_NAME)
        return {"status": "ok", "analyzed": 0}

    logger.info("[%s] Analyzing %d escalation(s)…", SKILL_NAME, len(escalations))

    from core.rag_engine import RAGEngine

    rag = RAGEngine(db=db, llm=llm)
    verdicts = []

    for item in escalations:
        verdict = _analyze_finding(item, instruction, rag, llm)
        verdicts.append(verdict)

        # ── 2. Write verdict back to memory ───────────────────────────────────
        if memory:
            v = verdict.get("verdict", "UNKNOWN")
            conf = verdict.get("confidence", 0)
            rec = verdict.get("recommended_action", "")
            memory.add_decision(
                f"[{v}] confidence={conf}% | {item[:80]} | action: {rec}"
            )
            if v == "TRUE_THREAT":
                memory.set_focus(f"Active threat investigation: {item[:120]}")

    # ── 3. Clear processed escalations ────────────────────────────────────────
    if memory and verdicts:
        memory.set_section("Escalation Queue", "None")

    return {
        "status": "ok",
        "analyzed": len(verdicts),
        "verdicts": verdicts,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Core reasoning loop (one finding)
# ──────────────────────────────────────────────────────────────────────────────

def _analyze_finding(finding_desc: str, instruction: str, rag, llm) -> dict:
    """
    Retrieve RAG context and ask the LLM for a verdict on one finding.
    """
    # Retrieve relevant baseline context
    rag_context = rag.build_context_string(
        query=finding_desc,
        category="network_baseline",
    )

    messages = [
        {"role": "system", "content": instruction},
        {
            "role": "user",
            "content": (
                f"**Anomaly Finding:**\n{finding_desc}\n\n"
                f"{rag_context}\n\n"
                "Based on the above, provide your verdict."
            ),
        },
    ]

    try:
        response = llm.chat(messages)
        parsed = _parse_json(response)
        if parsed:
            parsed["_finding"] = finding_desc[:200]
            return parsed
        return {
            "verdict": "UNKNOWN",
            "confidence": 0,
            "reasoning": response[:500],
            "_finding": finding_desc[:200],
        }
    except Exception as exc:
        logger.error("[%s] LLM analysis failed: %s", SKILL_NAME, exc)
        return {
            "verdict": "ERROR",
            "confidence": 0,
            "reasoning": str(exc),
            "_finding": finding_desc[:200],
        }


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _parse_escalations(memory) -> list[str]:
    """Extract non-empty escalation items from agent memory."""
    if memory is None:
        return []
    raw = memory.get_section("Escalation Queue")
    if not raw or raw.strip() == "None":
        return []
    items = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("- ["):
            # Strip bullet and timestamp prefix
            # Format: - [2026-03-02 12:00:00 UTC] [HIGH] Needs ThreatAnalyst…
            match = re.match(r"- \[.*?\]\s+(.*)", line)
            items.append(match.group(1) if match else line[2:])
    return [i for i in items if i]


def _parse_json(text: str) -> Optional[dict]:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except Exception:
            pass
    return None
