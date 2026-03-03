"""
skills/chat_router/logic.py

Intelligent skill router for conversational SOC queries.
Routes user questions to appropriate skills, handles multi-skill workflows,
and maintains conversation context.

This is not a periodic skill—it's invoked interactively via the chat command.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

INSTRUCTION_PATH = Path(__file__).parent / "instruction.md"
SKILL_NAME = "chat_router"


def route_question(
    user_question: str,
    available_skills: list[dict],
    llm: Any,
    instruction: str,
) -> dict:
    """
    Analyze user question and decide which skill(s) to invoke.
    
    Returns dict with:
      - reasoning: Why this skill was chosen
      - skills: List of skill names to invoke (can be multiple for workflows)
      - parameters: Parameters to pass to skills (includes the question)
    """
    skills_description = "\n".join([
        f"- {s['name']}: {s['description']}"
        for s in available_skills
    ])

    prompt = f"""Analyze this security question and decide which available skills to use.

Question: "{user_question}"

Available skills:
{skills_description}

Skills can be chained if needed (e.g., first baselining, then analyzing).

Respond with ONLY a JSON object (no markdown, no extra text):
{{
  "reasoning": "Why you chose these skills",
  "skills": ["skill_name_1", "skill_name_2"],
  "parameters": {{"question": "{user_question}", "any_param": "value"}}
}}

Only include skills that are relevant. If no skill matches, use empty list.
Always include the user question in parameters."""

    messages = [
        {"role": "system", "content": instruction},
        {"role": "user", "content": prompt},
    ]

    response = llm.chat(messages)
    
    try:
        result = json.loads(response)
        # Ensure parameters has the question
        if "parameters" not in result:
            result["parameters"] = {}
        if "question" not in result["parameters"]:
            result["parameters"]["question"] = user_question
        return result
    except json.JSONDecodeError:
        logger.warning("[%s] Failed to parse LLM routing response: %s", SKILL_NAME, response)
        # Fallback: try to extract JSON from response
        try:
            import re
            match = re.search(r"\{.*\}", response, re.DOTALL)
            if match:
                result = json.loads(match.group(0))
                if "parameters" not in result:
                    result["parameters"] = {}
                if "question" not in result["parameters"]:
                    result["parameters"]["question"] = user_question
                return result
        except:
            pass
        
        # If all else fails, return no skills
        return {
            "reasoning": "Unable to determine relevant skill",
            "skills": [],
            "parameters": {"question": user_question},
        }


def execute_skill_workflow(
    skills: list[str],
    runner: Any,
    context: dict,
    routing_decision: dict,
) -> dict:
    """
    Execute one or more skills in sequence, passing context between them.
    
    Args:
        skills: List of skill names to execute
        runner: Runner instance
        context: Shared context dict
        routing_decision: Dict with 'parameters' key for skill inputs
    
    Returns dict with results from each skill execution.
    """
    results = {}
    params = routing_decision.get("parameters", {})
    
    for skill_name in skills:
        logger.info("[%s] Executing skill: %s", SKILL_NAME, skill_name)
        
        try:
            # Build context with parameters
            skill_context = runner._build_context()
            skill_context["parameters"] = params
            
            # Dispatch skill with context
            result = runner.dispatch(skill_name, context=skill_context)
            results[skill_name] = result
            logger.info("[%s] Skill %s completed with status: %s", 
                       SKILL_NAME, skill_name, result.get("status"))
        except Exception as e:
            logger.error("[%s] Skill %s failed: %s", SKILL_NAME, skill_name, e)
            results[skill_name] = {
                "status": "error",
                "error": str(e),
            }
    
    return results


def format_response(
    user_question: str,
    routing_decision: dict,
    skill_results: dict,
    llm: Any,
) -> str:
    """
    Format skill results into a natural language response to the user.
    """
    if not routing_decision.get("skills"):
        return "I couldn't determine which skills would help with that question. Available skills are: network_baseliner, anomaly_watcher, threat_analyst."
    
    # Build context from skill results
    results_text = "\n".join([
        f"\n[{skill_name}]\n{json.dumps(result, indent=2)}"
        for skill_name, result in skill_results.items()
    ])
    
    prompt = f"""Based on these skill execution results, provide a concise, natural response to the user's question.

User question: "{user_question}"

Skill results:
{results_text}

Provide a clear, actionable answer (2-4 sentences). Focus on key findings and next steps."""

    messages = [
        {"role": "system", "content": "You are a helpful SOC analyst. Provide clear, actionable insights."},
        {"role": "user", "content": prompt},
    ]
    
    response = llm.chat(messages)
    return response


# ──────────────────────────────────────────────────────────────────────────────
# Conversation Memory Management
# ──────────────────────────────────────────────────────────────────────────────

CONVERSATIONS_DIR = Path(__file__).parent.parent.parent / "conversations"


def _ensure_conversations_dir():
    """Create conversations directory if it doesn't exist."""
    CONVERSATIONS_DIR.mkdir(parents=True, exist_ok=True)


def load_conversation_history(conversation_id: str) -> list[dict]:
    """Load conversation history from disk."""
    _ensure_conversations_dir()
    conv_file = CONVERSATIONS_DIR / f"{conversation_id}.json"
    
    if not conv_file.exists():
        return []
    
    try:
        with open(conv_file, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error("Failed to load conversation %s: %s", conversation_id, e)
        return []


def save_conversation_history(conversation_id: str, history: list[dict]) -> None:
    """Save conversation history to disk."""
    _ensure_conversations_dir()
    conv_file = CONVERSATIONS_DIR / f"{conversation_id}.json"
    
    try:
        with open(conv_file, "w") as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        logger.error("Failed to save conversation %s: %s", conversation_id, e)


def list_conversations() -> list[dict]:
    """List all saved conversations with metadata."""
    _ensure_conversations_dir()
    conversations = []
    
    for conv_file in sorted(CONVERSATIONS_DIR.glob("*.json")):
        try:
            with open(conv_file, "r") as f:
                history = json.load(f)
            
            if history:
                conversations.append({
                    "id": conv_file.stem,
                    "messages": len(history),
                    "first_question": history[0].get("question", "Unknown"),
                    "last_update": history[-1].get("timestamp", "Unknown"),
                })
        except Exception as e:
            logger.warning("Failed to read conversation file %s: %s", conv_file, e)
    
    return conversations


def add_to_history(conversation_id: str, question: str, answer: str, 
                  routing: dict, skill_results: dict) -> None:
    """Add a Q&A exchange to conversation history."""
    from datetime import datetime, timezone
    
    history = load_conversation_history(conversation_id)
    
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "question": question,
        "routing": routing,
        "skill_results": skill_results,
        "answer": answer,
    }
    
    history.append(entry)
    save_conversation_history(conversation_id, history)


def get_context_summary(conversation_id: str, last_n: int = 3) -> str:
    """Get summary of recent conversation for context injection."""
    history = load_conversation_history(conversation_id)
    
    if not history:
        return ""
    
    recent = history[-last_n:]
    summary_lines = []
    
    for entry in recent:
        summary_lines.append(f"Q: {entry.get('question', '')}")
        answer = entry.get('answer', '')
        # Truncate long answers
        if len(answer) > 200:
            answer = answer[:200] + "..."
        summary_lines.append(f"A: {answer}")
    
    return "\n".join(summary_lines)
