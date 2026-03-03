"""
skills/network_baseliner/logic.py

Field-agnostic network behavior baseliner. Discovers available fields
in logs, performs comprehensive network analytics (IP-to-IP relationships,
port patterns, protocols, direction, GeoIP, DNS, service identification),
and stores the result in the RAG vector index for ThreatAnalyst retrieval.

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
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

INSTRUCTION_PATH = Path(__file__).parent / "instruction.md"
SKILL_NAME = "network_baseliner"


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
    logs_index = cfg.get("db", "logs_index", default="securityclaw-logs")
    vector_index = cfg.get("db", "vector_index", default="securityclaw-vectors")

    # ── 1. Fetch recent logs (last 6 hours) ──────────────────────────────────
    since = _epoch_ms_ago(hours=6)
    query = {
        "query": {
            "range": {"@timestamp": {"gte": since, "format": "epoch_millis"}}
        },
    }
    raw_logs = db.search(logs_index, query, size=10000)

    if not raw_logs:
        logger.info("[%s] No logs found in the last 6 hours.", SKILL_NAME)
        return {"status": "no_data"}

    # ── 2. Detect network/sensor identifier and group logs ────────────────────
    identifier_field = _detect_identifier_field(raw_logs)
    grouped_logs = _group_logs_by_identifier(raw_logs, identifier_field)
    
    logger.info(
        "[%s] Detected identifier field: %s. Found %d networks/sensors.",
        SKILL_NAME,
        identifier_field,
        len(grouped_logs),
    )

    # ── 3. Generate baselines for each network/sensor ────────────────────────
    from core.rag_engine import RAGEngine

    rag = RAGEngine(db=db, llm=llm)
    rag.db.ensure_vector_index(vector_index)

    all_stored_docs = []
    for identifier, logs_group in grouped_logs.items():
        if not logs_group:
            continue
        
        logger.info(
            "[%s] Processing %s (%d logs)…",
            SKILL_NAME,
            identifier,
            len(logs_group),
        )
        
        # Analyze this network/sensor's logs
        analytics = _analyze_network_logs(logs_group)
        analytics_text = _format_analytics(analytics)

        # Generate baselines specific to this network/sensor
        baselines = _generate_baseline_documents(
            analytics,
            analytics_text,
            llm,
            instruction,
        )

        if not baselines:
            logger.warning(
                "[%s] Failed to generate baselines for %s",
                SKILL_NAME,
                identifier,
            )
            continue

        # Store all baselines with network/sensor context
        for baseline in baselines:
            doc_id = rag.store(
                text=baseline["summary"],
                category=baseline["category"],
                source=SKILL_NAME,
                metadata={
                    "identifier_field": identifier_field,
                    "identifier_value": identifier,
                    "dimension": baseline["category"].replace("network_baseline_", ""),
                },
            )
            all_stored_docs.append(
                {
                    "category": baseline["category"],
                    "identifier": identifier,
                    "doc_id": doc_id,
                }
            )
            logger.info(
                "[%s] Stored %s for %s (id=%s)",
                SKILL_NAME,
                baseline["category"],
                identifier,
                doc_id[:8],
            )

    # ── 4. Update agent memory ────────────────────────────────────────────────
    if memory:
        memory.add_decision(
            f"NetworkBaseliner analyzed {len(grouped_logs)} networks/sensors across "
            f"{len(raw_logs)} logs. Stored {len(all_stored_docs)} baseline documents "
            f"with context: {identifier_field}={', '.join(grouped_logs.keys())}"
        )

    return {
        "status": "ok",
        "records_processed": len(raw_logs),
        "networks_analyzed": len(grouped_logs),
        "documents_stored": len(all_stored_docs),
        "identifier_field": identifier_field,
        "identifiers": list(grouped_logs.keys()),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Network/Sensor Detection and Grouping
# ──────────────────────────────────────────────────────────────────────────────

def _detect_identifier_field(logs: list[dict]) -> str:
    """
    Detect which field is the likely network/sensor identifier.
    
    Candidates (in order of preference):
      1. agent_id, sensor_id, client_id, source_id - explicit identifiers
      2. host.hostname, hostname - machine identity
      3. host.ip, source.ip (first octet or /24) - network segment
      4. event.source - log source
      5. None - treat all logs as single network
    """
    if not logs:
        return "sensor_id"  # Default fallback
    
    # Sample first 100 logs to check for identifier fields
    sample = logs[:100]
    
    # Candidate fields to check
    candidates = [
        ("agent_id", "exact"),
        ("sensor_id", "exact"),
        ("client_id", "exact"),
        ("source_id", "exact"),
        ("host.hostname", "exact"),
        ("hostname", "exact"),
        ("event.source", "exact"),
        ("source.ip", "subnet"),  # Group by /24 subnet
        ("host.ip", "subnet"),
    ]
    
    for field_path, mode in candidates:
        found_values = set()
        populated_count = 0
        
        for log in sample:
            value = _extract_value(log, [field_path])
            if value is not None:
                populated_count += 1
                if mode == "subnet":
                    # Extract /24 subnet from IP
                    if isinstance(value, str):
                        parts = value.split(".")
                        if len(parts) == 4:
                            value = ".".join(parts[:3]) + ".0"
                found_values.add(value)
        
        # If this field is populated in >80% of samples and has multiple distinct values
        if populated_count >= len(sample) * 0.8 and len(found_values) > 1:
            logger.info(
                "[%s] Auto-detected identifier field: %s (found %d distinct values)",
                SKILL_NAME,
                field_path,
                len(found_values),
            )
            return field_path
    
    # No good identifier field found - treat all as one network
    logger.info("[%s] No multi-network identifier detected; treating all logs as single network", SKILL_NAME)
    return "sensor_id"


def _group_logs_by_identifier(logs: list[dict], identifier_field: str) -> dict[str, list[dict]]:
    """
    Group logs by the identified field to separate network/sensor baselines.
    
    Returns dict mapping identifier value → list of logs for that network/sensor.
    """
    groups = defaultdict(list)
    
    for log in logs:
        value = _extract_value(log, [identifier_field])
        
        if value is None:
            value = "unknown"
        
        # For subnet grouping, extract /24
        if "." in str(value):
            parts = str(value).split(".")
            if len(parts) == 4 and identifier_field in ("source.ip", "host.ip"):
                try:
                    int(parts[0])  # Verify it's an IP
                    value = ".".join(parts[:3]) + ".0"
                except ValueError:
                    pass
        
        groups[str(value)].append(log)
    
    return dict(groups)


# ──────────────────────────────────────────────────────────────────────────────

def _generate_baseline_documents(
    analytics: dict,
    analytics_text: str,
    llm,
    instruction: str,
) -> list[dict]:
    """
    Generate multiple baseline documents covering different network dimensions.
    Each document is a focused analysis of a specific aspect, enabling better RAG retrieval.
    
    Returns list of dicts with "summary" and "category" for each baseline.
    """
    baselines = []
    
    # ── Baseline 1: Protocol & Service Baseline ────────────────────────────────
    protocols = analytics.get("protocols", {})
    services = analytics.get("services", {})
    top_ports = analytics.get("dest_ports", {})
    
    if protocols or top_ports:
        proto_section = "\n".join([
            f"{proto}: {count} flows" for proto, count in list(protocols.items())[:5]
        ])
        port_section = "\n".join([
            f"{services.get(port, 'unknown')}/{port}: {count} flows"
            for port, count in list(top_ports.items())[:10]
        ])
        
        proto_prompt = f"""Analyze the protocol and service landscape based on:

PROTOCOLS:
{proto_section}

TOP PORTS:
{port_section}

Produce a single-sentence summary of the typical protocols and services in use."""
        
        response = llm.chat([
            {"role": "system", "content": "You are a network analyst. Produce concise, factual summaries."},
            {"role": "user", "content": proto_prompt},
        ])
        baselines.append({
            "summary": response,
            "category": "network_baseline_protocols_services",
        })
    
    # ── Baseline 2: Port Landscape Baseline ────────────────────────────────────
    if top_ports:
        port_detail = "\n".join([
            f"{port} ({services.get(port, 'unknown')}): {count} flows"
            for port, count in list(top_ports.items())[:15]
        ])
        
        port_prompt = f"""Analyze this port landscape showing typical destination ports and their usage:

{port_detail}

Produce a clear summary of the port distribution and which services are most active."""
        
        response = llm.chat([
            {"role": "system", "content": "You are a network analyst. Be specific and factual."},
            {"role": "user", "content": port_prompt},
        ])
        baselines.append({
            "summary": response,
            "category": "network_baseline_port_landscape",
        })
    
    # ── Baseline 3: IP Communication Baseline ──────────────────────────────────
    src_ips = analytics.get("source_ips", {})
    dst_ips = analytics.get("dest_ips", {})
    ip_pairs = analytics.get("ip_pairs", {})
    
    if src_ips and dst_ips and ip_pairs:
        src_detail = "\n".join([f"{ip}: {count} flows" for ip, count in list(src_ips.items())[:10]])
        dst_detail = "\n".join([f"{ip}: {count} flows" for ip, count in list(dst_ips.items())[:10]])
        pair_detail = "\n".join([
            f"{src} → {dst}: {count} flows" for (src, dst), count in list(ip_pairs.items())[:10]
        ])
        
        ip_prompt = f"""Analyze the IP communication patterns:

TOP SOURCE IPs (clients):
{src_detail}

TOP DESTINATION IPs (servers):
{dst_detail}

COMMON COMMUNICATION PAIRS:
{pair_detail}

Summarize the typical source IPs, destination IPs, and common communication paths."""
        
        response = llm.chat([
            {"role": "system", "content": "You are a network analyst. Focus on communication patterns."},
            {"role": "user", "content": ip_prompt},
        ])
        baselines.append({
            "summary": response,
            "category": "network_baseline_ip_communication",
        })
    
    # ── Baseline 4: Traffic Direction Baseline ─────────────────────────────────
    directions = analytics.get("directions", {})
    flow_stats = analytics.get("flow_stats", {})
    
    if directions and flow_stats:
        total_flows = flow_stats.get("total_flows", 1)
        direction_detail = "\n".join([
            f"{direction}: {count} flows ({(count/total_flows)*100:.1f}%)"
            for direction, count in directions.items()
        ])
        
        direction_prompt = f"""Analyze the traffic direction breakdown:

{direction_detail}

Summarize the typical traffic direction mix (inbound/outbound/internal percentages)."""
        
        response = llm.chat([
            {"role": "system", "content": "You are a network analyst."},
            {"role": "user", "content": direction_prompt},
        ])
        baselines.append({
            "summary": response,
            "category": "network_baseline_traffic_direction",
        })
    
    # ── Baseline 5: External Contacts Baseline (GeoIP) ────────────────────────
    geoip = analytics.get("geoip_data", {})
    dst_ips_list = list(analytics.get("dest_ips", {}).items())
    
    if geoip or dst_ips_list:
        external_ips = [ip for ip in dict(dst_ips_list).keys() 
                       if not _is_private_ip(ip)][:10]
        
        geo_detail = "\n".join([
            f"{ip}: {geoip.get(ip, 'Unknown')}" for ip in external_ips if ip in geoip
        ]) or "No GeoIP data available"
        
        external_prompt = f"""Analyze the external IP contacts:

EXTERNAL DESTINATION IPs:
{', '.join(external_ips) if external_ips else 'Primarily internal communication'}

GEO DATA:
{geo_detail}

Summarize which external systems/regions are contacted and their frequency."""
        
        response = llm.chat([
            {"role": "system", "content": "You are a network analyst."},
            {"role": "user", "content": external_prompt},
        ])
        baselines.append({
            "summary": response,
            "category": "network_baseline_external_contacts",
        })
    
    # ── Baseline 6: DNS Activity Baseline ──────────────────────────────────────
    dns = analytics.get("dns_queries", {})
    
    if dns:
        dns_detail = "\n".join([
            f"{domain}: {count} queries" for domain, count in list(dns.items())[:15]
        ])
        
        dns_prompt = f"""Analyze the DNS query patterns:

{dns_detail}

Summarize the typical DNS queries and domains being resolved."""
        
        response = llm.chat([
            {"role": "system", "content": "You are a network analyst."},
            {"role": "user", "content": dns_prompt},
        ])
        baselines.append({
            "summary": response,
            "category": "network_baseline_dns_activity",
        })
    
    return baselines


def _is_private_ip(ip: str) -> bool:
    """Check if IP is in private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)."""
    if not isinstance(ip, str):
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first = int(parts[0])
        second = int(parts[1]) if first == 172 else 0
        return (first == 10 or 
                (first == 172 and 16 <= second <= 31) or 
                first == 192)
    except (ValueError, IndexError):
        return False


# ──────────────────────────────────────────────────────────────────────────────

def _epoch_ms_ago(hours: int = 6) -> int:
    dt = datetime.now(timezone.utc) - timedelta(hours=hours)
    return int(dt.timestamp() * 1000)


def _extract_value(obj: Any, paths: list[str]) -> Any:
    """Recursively extract value from nested dict using multiple potential paths."""
    for path in paths:
        current = obj
        for key in path.split("."):
            if isinstance(current, dict):
                current = current.get(key)
            else:
                current = None
                break
        if current is not None:
            return current
    return None


def _analyze_network_logs(logs: list[dict]) -> dict:
    """
    Perform comprehensive field-agnostic network analytics.
    
    Returns dict with:
      - source_ips: {ip: count}
      - dest_ips: {ip: count}
      - source_ports: {port: count}
      - dest_ports: {port: count}
      - protocols: {protocol: count}
      - directions: {direction: count}
      - ip_pairs: [(src, dst): count]
      - ip_port_pairs: {ip: {port: count}}
      - services: {port: name}
      - geoip_data: {ip: location}
      - dns_queries: {domain: count}
      - flow_stats: {metric: value}
    """
    source_ips = Counter()
    dest_ips = Counter()
    source_ports = Counter()
    dest_ports = Counter()
    protocols = Counter()
    directions = Counter()
    ip_pairs = Counter()
    ip_port_connections = defaultdict(Counter)  # src_ip -> {dest_ip: count}
    ip_port_usage = defaultdict(Counter)  # ip -> {port: count}
    services = {}
    geoip_data = {}
    dns_queries = Counter()
    
    total_bytes = 0
    total_packets = 0
    durations = []

    for log in logs:
        # ── Extract source info (multiple possible field paths) ────────────────
        src_ip = _extract_value(log, ["source.ip", "src_ip", "source_address"])
        src_port = _extract_value(log, ["source.port", "src_port", "source_port"])
        
        # ── Extract destination info ───────────────────────────────────────────
        dst_ip = _extract_value(log, ["destination.ip", "dest_ip", "destination_address"])
        dst_port = _extract_value(log, ["destination.port", "dest_port", "destination_port"])
        
        # ── Extract protocol/service info ──────────────────────────────────────
        protocol = _extract_value(log, ["network.transport", "protocol", "transport"])
        service = _extract_value(log, ["network.protocol", "service"])
        
        # ── Extract direction ──────────────────────────────────────────────────
        direction = _extract_value(log, ["network.direction", "direction", "flow_direction"])
        
        # ── Extract volume metrics ─────────────────────────────────────────────
        src_bytes = _extract_value(log, ["source.bytes", "bytes_sent", "src_bytes"])
        dst_bytes = _extract_value(log, ["destination.bytes", "bytes_recv", "bytes_received"])
        total_net_bytes = _extract_value(log, ["network.bytes", "bytes_total"])
        packets = _extract_value(log, ["network.packets", "packets_total", "event.packets"])
        duration = _extract_value(log, ["event.duration", "duration_us", "duration_ms"])
        
        # ── Extract GeoIP info if available ────────────────────────────────────
        dst_geo = _extract_value(log, ["destination.geo"])
        if dst_ip and dst_geo:
            geo_info = dst_geo
            if isinstance(dst_geo, dict):
                geo_info = f"{dst_geo.get('country_name', '?')} {dst_geo.get('city_name', '')}".strip()
            geoip_data[dst_ip] = geo_info
        
        # ── Extract DNS info if available ──────────────────────────────────────
        dns_question = _extract_value(log, ["dns.question.name", "dns.query"])
        if dns_question:
            dns_queries[dns_question] += 1
        
        # ── Aggregate counters ─────────────────────────────────────────────────
        if src_ip:
            source_ips[src_ip] += 1
        if dst_ip:
            dest_ips[dst_ip] += 1
        if src_port:
            source_ports[src_port] += 1
        if dst_port:
            dest_ports[dst_port] += 1
        if protocol:
            protocols[protocol] += 1
        if direction:
            directions[direction] += 1
        
        # ── Track IP-to-IP relationships ───────────────────────────────────────
        if src_ip and dst_ip:
            ip_pairs[(src_ip, dst_ip)] += 1
            ip_port_connections[src_ip][dst_ip] += 1
        
        # ── Track port usage per IP ────────────────────────────────────────────
        if src_ip and src_port:
            ip_port_usage[src_ip][src_port] += 1
        if dst_ip and dst_port:
            ip_port_usage[dst_ip][dst_port] += 1
        
        # ── Map service names to ports ────────────────────────────────────────
        if dst_port and service:
            services[dst_port] = service
        
        # ── Accumulate volume stats ────────────────────────────────────────────
        if src_bytes and isinstance(src_bytes, (int, float)):
            total_bytes += src_bytes
        if dst_bytes and isinstance(dst_bytes, (int, float)):
            total_bytes += dst_bytes
        if total_net_bytes and isinstance(total_net_bytes, (int, float)):
            total_bytes += total_net_bytes
        if packets and isinstance(packets, (int, float)):
            total_packets += packets
        if duration and isinstance(duration, (int, float)):
            durations.append(duration)

    # ── Compute flow statistics ────────────────────────────────────────────────
    avg_duration = sum(durations) / len(durations) if durations else 0
    flow_stats = {
        "total_flows": len(logs),
        "total_bytes": total_bytes,
        "total_packets": total_packets,
        "avg_bytes_per_flow": total_bytes / max(len(logs), 1),
        "avg_duration_us": avg_duration,
    }

    return {
        "source_ips": dict(source_ips.most_common(50)),
        "dest_ips": dict(dest_ips.most_common(50)),
        "source_ports": dict(source_ports.most_common(30)),
        "dest_ports": dict(dest_ports.most_common(30)),
        "protocols": dict(protocols.most_common(10)),
        "directions": dict(directions.most_common(5)),
        "ip_pairs": dict(ip_pairs.most_common(50)),
        "ip_port_connections": {k: dict(v.most_common(20)) for k, v in ip_port_connections.items()},
        "ip_port_usage": {k: dict(v.most_common(20)) for k, v in ip_port_usage.items()},
        "services": services,
        "geoip_data": dict(list(geoip_data.items())[:30]),
        "dns_queries": dict(dns_queries.most_common(30)),
        "flow_stats": flow_stats,
    }


def _format_analytics(analytics: dict) -> str:
    """Format comprehensive analytics into readable text for LLM."""
    lines = []
    
    # Flow statistics
    stats = analytics.get("flow_stats", {})
    lines.append("═ FLOW STATISTICS ═")
    lines.append(f"  Total flows: {stats.get('total_flows', 0)}")
    lines.append(f"  Total bytes: {stats.get('total_bytes', 0):,}")
    lines.append(f"  Total packets: {stats.get('total_packets', 0):,}")
    lines.append(f"  Avg bytes/flow: {stats.get('avg_bytes_per_flow', 0):.1f}")
    lines.append(f"  Avg duration: {stats.get('avg_duration_us', 0):.0f} µs")
    lines.append("")

    # Protocols
    protocols = analytics.get("protocols", {})
    if protocols:
        lines.append("═ PROTOCOLS ═")
        for proto, count in list(protocols.items())[:10]:
            pct = (count / stats.get("total_flows", 1)) * 100
            lines.append(f"  {proto}: {count} flows ({pct:.1f}%)")
        lines.append("")

    # Directions
    directions = analytics.get("directions", {})
    if directions:
        lines.append("═ TRAFFIC DIRECTION ═")
        for direction, count in directions.items():
            pct = (count / stats.get("total_flows", 1)) * 100
            lines.append(f"  {direction}: {count} flows ({pct:.1f}%)")
        lines.append("")

    # Destination ports
    dest_ports = analytics.get("dest_ports", {})
    services = analytics.get("services", {})
    if dest_ports:
        lines.append("═ TOP DESTINATION PORTS ═")
        for port, count in list(dest_ports.items())[:15]:
            service = services.get(port, "unknown")
            pct = (count / stats.get("total_flows", 1)) * 100
            lines.append(f"  {port}/{service}: {count} flows ({pct:.1f}%)")
        lines.append("")

    # Source ports
    source_ports = analytics.get("source_ports", {})
    if source_ports:
        lines.append("═ TOP SOURCE PORTS ═")
        for port, count in list(source_ports.items())[:10]:
            lines.append(f"  {port}: {count} flows")
        lines.append("")

    # Source and destination IPs
    src_ips = analytics.get("source_ips", {})
    dst_ips = analytics.get("dest_ips", {})
    if src_ips:
        lines.append("═ TOP SOURCE IPs ═")
        for ip, count in list(src_ips.items())[:10]:
            pct = (count / stats.get("total_flows", 1)) * 100
            lines.append(f"  {ip}: {count} flows ({pct:.1f}%)")
        lines.append("")

    if dst_ips:
        lines.append("═ TOP DESTINATION IPs ═")
        for ip, count in list(dst_ips.items())[:10]:
            pct = (count / stats.get("total_flows", 1)) * 100
            lines.append(f"  {ip}: {count} flows ({pct:.1f}%)")
        lines.append("")

    # IP-to-IP relationships
    ip_pairs = analytics.get("ip_pairs", {})
    if ip_pairs:
        lines.append("═ COMMON IP PAIRS (Source → Destination) ═")
        for (src, dst), count in list(ip_pairs.items())[:15]:
            pct = (count / stats.get("total_flows", 1)) * 100
            lines.append(f"  {src} → {dst}: {count} flows ({pct:.1f}%)")
        lines.append("")

    # IP-Port usage (which IPs use which ports)
    ip_port_usage = analytics.get("ip_port_usage", {})
    if ip_port_usage:
        lines.append("═ IP-PORT USAGE (Most Active) ═")
        for ip, ports in list(ip_port_usage.items())[:10]:
            port_list = ", ".join(str(p) for p, _ in list(ports.items())[:5])
            lines.append(f"  {ip}: ports {port_list}")
        lines.append("")

    # GeoIP data
    geoip = analytics.get("geoip_data", {})
    if geoip:
        lines.append("═ GEOLOCATION DATA ═")
        for ip, location in list(geoip.items())[:10]:
            lines.append(f"  {ip}: {location}")
        lines.append("")

    # DNS queries
    dns = analytics.get("dns_queries", {})
    if dns:
        lines.append("═ DNS QUERIES ═")
        for domain, count in list(dns.items())[:15]:
            lines.append(f"  {domain}: {count} queries")
        lines.append("")

    return "\n".join(lines)


def _parse_json_response(text: str) -> dict | None:
    """Extract and parse a JSON block from LLM output."""
    # Try the whole string first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Extract first JSON block from markdown
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # Heuristic: find first { ... } block
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return None
