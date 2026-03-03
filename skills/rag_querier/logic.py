"""
skills/rag_querier/logic.py

Data-agnostic RAG querier skill. Searches stored baseline knowledge
to answer user questions about network/system behavior.

Context keys consumed:
    context["db"]         -> BaseDBConnector
    context["llm"]        -> BaseLLMProvider
    context["memory"]     -> AgentMemory
    context["config"]     -> Config
    context["parameters"] -> {"question": "user question"}
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

INSTRUCTION_PATH = Path(__file__).parent / "instruction.md"
SKILL_NAME = "rag_querier"


def run(context: dict) -> dict:
    """Entry point called by the Runner."""
    db = context.get("db")
    llm = context.get("llm")
    cfg = context.get("config")
    parameters = context.get("parameters", {})

    if db is None or llm is None:
        logger.warning("[%s] db or llm not available — skipping.", SKILL_NAME)
        return {"status": "skipped", "reason": "no db/llm"}

    user_question = parameters.get("question")
    if not user_question:
        logger.warning("[%s] No question provided in parameters.", SKILL_NAME)
        return {"status": "no_question"}

    instruction = INSTRUCTION_PATH.read_text(encoding="utf-8")
    logs_index = cfg.get("db", "logs_index", default="securityclaw-logs")
    vector_index = cfg.get("db", "vector_index", default="securityclaw-vectors")

    # ── 1. Generate search embeddings from the user question ──────────────────
    logger.info("[%s] Searching for: %s", SKILL_NAME, user_question)
    
    query_embedding = None
    embedding_available = True
    try:
        query_embedding = llm.embed(user_question)
    except Exception as exc:
        logger.warning("[%s] Embedding unavailable, will skip RAG search: %s", SKILL_NAME, exc)
        embedding_available = False

    # ── 2. Search RAG for relevant baselines (only if embedding works) ────────
    rag_docs = []
    if embedding_available and query_embedding:
        try:
            from core.rag_engine import RAGEngine
            rag = RAGEngine(db=db, llm=llm)
            rag_docs = rag.retrieve(query_embedding, k=5)
            logger.info("[%s] Found %d relevant baselines in RAG.", SKILL_NAME, len(rag_docs))
        except Exception as exc:
            logger.warning("[%s] RAG retrieval failed: %s", SKILL_NAME, exc)
            # Continue with raw logs even if RAG fails
    elif not embedding_available:
        logger.info("[%s] Skipping RAG search (embedding unavailable).", SKILL_NAME)

    # ── 3. Search raw logs for matching data ──────────────────────────────────
    raw_logs = []
    try:
        raw_logs = _search_raw_logs(user_question, db, logs_index)
        logger.info("[%s] Found %d matching records in logs.", SKILL_NAME, len(raw_logs))
    except Exception as exc:
        logger.error("[%s] Raw log search failed: %s", SKILL_NAME, exc)

    # ── 4. If neither RAG nor raw logs have data, return no_data ──────────────
    if not rag_docs and not raw_logs:
        logger.info("[%s] No data found (RAG or logs).", SKILL_NAME)
        return {
            "status": "no_data",
            "findings": {
                "question": user_question,
                "answer": "No data found to answer this question.",
                "confidence": 0.0,
            },
        }

    # ── 5. Analyze combined data with LLM to extract answer ──────────────────
    combined_context = _format_combined_context(rag_docs, raw_logs, user_question)
    answer = _extract_answer_from_data(user_question, combined_context, instruction, llm)

    findings = {
        "question": user_question,
        "answer": answer,
        "rag_sources": len(rag_docs),
        "log_records": len(raw_logs),
        "confidence": 0.85 if (rag_docs or raw_logs) else 0.0,
        "summary": {
            "baseline_insights": len(rag_docs),
            "raw_observations": len(raw_logs),
        },
    }

    logger.info(
        "[%s] Answer compiled from %d baselines and %d log records.",
        SKILL_NAME,
        len(rag_docs),
        len(raw_logs),
    )

    return {
        "status": "ok",
        "findings": findings,
    }


def _search_raw_logs(question: str, db: Any, logs_index: str) -> list[dict]:
    """
    Search raw logs for data matching the user question.
    Intelligently extracts keywords from the question and searches.
    """
    # Extract potential search terms from the question
    search_terms = _extract_search_terms(question)
    
    if not search_terms:
        return []
    
    import re as _re
    ip_pattern = r'^(?:\d{1,3}\.){3}\d{1,3}$'
    port_pattern = r'^\d{1,5}$'
    protocol_names = {'tcp', 'udp', 'icmp', 'http', 'https', 'dns', 'ssh', 'rdp', 'smb'}

    # Build a broad should query across all relevant fields
    should_clauses = []

    for term in search_terms:
        if _re.match(ip_pattern, term):
            # IP addresses — use term queries (exact match on keyword/ip fields)
            should_clauses += [
                {"term": {"destination.ip": term}},
                {"term": {"source.ip": term}},
                {"term": {"destination.ip.keyword": term}},
                {"term": {"source.ip.keyword": term}},
            ]
        elif _re.match(port_pattern, term):
            # Port numbers — numeric term
            try:
                port_int = int(term)
                should_clauses += [
                    {"term": {"destination.port": port_int}},
                    {"term": {"source.port": port_int}},
                ]
            except ValueError:
                pass
        elif term.lower() in protocol_names:
            # Protocols — term on keyword field
            should_clauses += [
                {"term": {"network.protocol": term.lower()}},
                {"term": {"network.protocol.keyword": term.lower()}},
                {"match": {"network.transport": term.lower()}},
            ]
        else:
            # Hostnames, domains, other strings — full-text match
            should_clauses += [
                {"match": {"host.hostname": {"query": term}}},
                {"match": {"agent.name": {"query": term}}},
                {"match": {"dns.question.name": {"query": term}}},
                {"match": {"url.domain": {"query": term}}},
                {"wildcard": {"host.hostname.keyword": {"value": f"*{term}*"}}},
            ]

    if not should_clauses:
        return []

    query = {
        "query": {
            "bool": {
                "should": should_clauses,
                "minimum_should_match": 1,
                "filter": {
                    "range": {
                        "@timestamp": {"gte": "now-24h"}
                    }
                },
            }
        },
        "size": 50,
    }
    
    try:
        results = db.search(logs_index, query, size=50)
        return results
    except Exception as exc:
        logger.warning("[%s] Raw log search error: %s", SKILL_NAME, exc)
        return []


def _extract_search_terms(question: str) -> list[str]:
    """
    Extract potential search terms from a user question.
    Looks for IPs, hostnames, ports, protocols, etc.
    Returns each as a string; _search_raw_logs categorises them.
    """
    import re

    terms = []
    remaining = question

    # 1. Extract IPv4 addresses first (remove them so octets don't get picked up again)
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, remaining)
    terms.extend(ips)
    remaining = re.sub(ip_pattern, ' ', remaining)

    # 2. Extract explicit port numbers ("port 443", ":8080")
    port_pattern = r'\bport\s+(\d{1,5})\b|:(\d{2,5})\b'
    for m in re.finditer(port_pattern, remaining):
        port_num = m.group(1) or m.group(2)
        if port_num:
            terms.append(port_num)
    remaining = re.sub(port_pattern, ' ', remaining)

    # 3. Extract known protocol names
    protocols = ['tcp', 'udp', 'icmp', 'http', 'https', 'dns', 'ssh', 'rdp', 'smb', 'ftp', 'smtp', 'ntp']
    for proto in protocols:
        if re.search(rf'\b{proto}\b', remaining, re.IGNORECASE):
            terms.append(proto)

    # 4. Extract hostnames / domain names (must contain at least one letter)
    hostname_pattern = r'\b([a-zA-Z][a-zA-Z0-9\-]{1,62}(?:\.[a-zA-Z0-9][a-zA-Z0-9\-]{0,62})*)\b'
    for m in re.finditer(hostname_pattern, remaining):
        terms.append(m.group(1))

    # 5. Deduplicate and strip noise
    stopwords = {
        'what', 'is', 'there', 'any', 'traffic', 'to', 'from', 'the', 'a',
        'are', 'on', 'in', 'for', 'if', 'and', 'or', 'not', 'was', 'were',
        'have', 'has', 'had', 'past', 'hours', 'last', 'days', 'recent',
        'show', 'me', 'check', 'find', 'network', 'do',
    }
    seen = set()
    unique = []
    for t in terms:
        t_low = t.lower()
        if t_low not in stopwords and t_low not in seen and len(t) > 1:
            seen.add(t_low)
            unique.append(t_low)

    return unique


def _format_combined_context(rag_docs: list[dict], raw_logs: list[dict], question: str) -> str:
    """Format both RAG baseline data and raw logs for LLM analysis."""
    context_parts = []
    
    if rag_docs:
        context_parts.append("=== BASELINE KNOWLEDGE (from stored baselines) ===")
        for i, doc in enumerate(rag_docs[:3], 1):  # Top 3 RAG docs
            category = doc.get("category", "unknown")
            source = doc.get("source", "unknown")
            text = doc.get("text", "")
            similarity = doc.get("similarity", 0.0)
            context_parts.append(
                f"[Baseline {i} | {source} | {category} | Match: {similarity:.1%}]\n{text}"
            )
    
    if raw_logs:
        context_parts.append("\n=== OBSERVED DATA (from recent logs) ===")
        context_parts.append(_summarize_raw_logs(raw_logs, question))
    
    return "\n\n".join(context_parts)


def _summarize_raw_logs(logs: list[dict], question: str) -> str:
    """Summarize raw logs to highlight relevant fields."""
    if not logs:
        return "No recent log records found."
    
    summary_lines = [f"Found {len(logs)} recent log records:"]
    
    # Show sample records with relevant fields
    for i, log in enumerate(logs[:5], 1):  # Show first 5 records
        relevant_fields = [
            ("src", log.get("source.ip") or log.get("src_ip")),
            ("dst", log.get("destination.ip") or log.get("dest_ip")),
            ("port", log.get("destination.port") or log.get("dest_port")),
            ("proto", log.get("network.protocol") or log.get("protocol")),
            ("host", log.get("host.hostname") or log.get("hostname")),
            ("time", log.get("@timestamp")[:10] if log.get("@timestamp") else "?"),
        ]
        
        fields_str = " | ".join(
            f"{k}={v}" for k, v in relevant_fields if v
        )
        summary_lines.append(f"  {i}. {fields_str}")
    
    if len(logs) > 5:
        summary_lines.append(f"  ... and {len(logs) - 5} more records")
    
    return "\n".join(summary_lines)


def _extract_answer_from_data(
    question: str,
    context_text: str,
    instruction: str,
    llm: Any,
) -> str:
    """Use LLM to extract answer from both RAG baselines and raw logs."""
    prompt = f"""You are a SOC analyst answering questions about network behavior.
    
User Question: "{question}"

Available Context (both baselines and observed data):
{context_text}

Based on the above data, answer the user's question concisely (1-3 sentences).
Reference both baseline patterns and observed data. Be specific with IP addresses, ports, and protocols when relevant."""

    messages = [
        {"role": "system", "content": instruction},
        {"role": "user", "content": prompt},
    ]

    try:
        response = llm.chat(messages)
        return response.strip()
    except Exception as exc:
        logger.error("Failed to extract answer: %s", exc)
        return f"Error analyzing data: {exc}"
