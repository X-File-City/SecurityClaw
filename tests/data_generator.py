"""
tests/data_generator.py — Realistic synthetic network log and anomaly data.

Generates:
  - Normal network flow records (the baseline corpus)
  - Anomalous flow records (port scans, data exfiltration, lateral movement)
  - Anomaly Detection findings (as OpenSearch AD would return them)
  - Pre-embedded RAG chunks for baseline context
"""
from __future__ import annotations

import hashlib
import math
import random
import string
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional


# ──────────────────────────────────────────────────────────────────────────────
# Constants — realistic baseline parameters
# ──────────────────────────────────────────────────────────────────────────────

INTERNAL_SUBNETS = ["10.0.1.", "10.0.2.", "192.168.1.", "172.16.10."]
EXTERNAL_IPS = [
    "8.8.8.8", "1.1.1.1", "208.67.222.222",
    "13.107.42.14", "52.239.192.0", "151.101.0.0",
]
COMMON_PORTS = [80, 443, 53, 22, 3389, 8080, 8443, 25, 587, 993]
COMMON_PROTOCOLS = ["tcp", "udp", "icmp"]
SERVICES = {
    80: "http", 443: "https", 53: "dns", 22: "ssh",
    3389: "rdp", 8080: "http-proxy", 25: "smtp",
    587: "smtp-ssl", 993: "imap", 8443: "https-alt",
}


# ──────────────────────────────────────────────────────────────────────────────
# IP / address helpers
# ──────────────────────────────────────────────────────────────────────────────

def _rand_internal_ip() -> str:
    subnet = random.choice(INTERNAL_SUBNETS)
    return subnet + str(random.randint(1, 254))


def _rand_external_ip() -> str:
    return random.choice(EXTERNAL_IPS)


def _rand_mac() -> str:
    return ":".join(f"{random.randint(0,255):02x}" for _ in range(6))


def _epoch_ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


# ──────────────────────────────────────────────────────────────────────────────
# Normal network log record
# ──────────────────────────────────────────────────────────────────────────────

def generate_normal_log(
    base_time: Optional[datetime] = None,
    jitter_minutes: int = 360,
) -> dict:
    """Generate one realistic 'normal' network flow record."""
    if base_time is None:
        base_time = datetime.now(timezone.utc) - timedelta(hours=6)
    timestamp = base_time + timedelta(minutes=random.randint(0, jitter_minutes))

    src_ip = _rand_internal_ip()
    dest_port = random.choice(COMMON_PORTS)
    protocol = "udp" if dest_port == 53 else "tcp"
    service = SERVICES.get(dest_port, "unknown")
    bytes_sent = random.randint(64, 15_000)
    bytes_recv = random.randint(128, 50_000)
    packets = random.randint(1, 200)

    return {
        "@timestamp": _iso(timestamp),
        "event": {
            "kind": "event",
            "category": "network",
            "type": "connection",
            "outcome": "success",
            "duration": random.randint(1_000_000, 5_000_000_000),
        },
        "source": {
            "ip": src_ip,
            "port": random.randint(1024, 65535),
            "mac": _rand_mac(),
            "bytes": bytes_sent,
            "packets": packets,
        },
        "destination": {
            "ip": _rand_external_ip() if dest_port in (80, 443, 53) else _rand_internal_ip(),
            "port": dest_port,
            "bytes": bytes_recv,
        },
        "network": {
            "transport": protocol,
            "protocol": service,
            "bytes": bytes_sent + bytes_recv,
            "packets": packets,
            "direction": "outbound" if dest_port in (80, 443, 53) else "internal",
        },
        "host": {
            "hostname": f"ws-{src_ip.replace('.', '-')}",
            "ip": [src_ip],
        },
        "_id": str(uuid.uuid4()),
    }


def generate_normal_logs(n: int = 500, **kwargs) -> list[dict]:
    return [generate_normal_log(**kwargs) for _ in range(n)]


# ──────────────────────────────────────────────────────────────────────────────
# Anomalous records
# ──────────────────────────────────────────────────────────────────────────────

def generate_port_scan(attacker_ip: Optional[str] = None) -> list[dict]:
    """Simulate a port scan: rapid connections to many ports."""
    attacker = attacker_ip or _rand_external_ip()
    target = _rand_internal_ip()
    base_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    records = []
    for port in random.sample(range(1, 65535), 150):
        ts = base_time + timedelta(seconds=random.randint(0, 30))
        records.append({
            "@timestamp": _iso(ts),
            "event": {"kind": "alert", "category": "network", "type": "connection", "outcome": "failure"},
            "source": {"ip": attacker, "port": random.randint(1024, 65535)},
            "destination": {"ip": target, "port": port},
            "network": {"transport": "tcp", "protocol": "unknown", "bytes": 60, "packets": 1},
            "host": {"hostname": f"ws-{target.replace('.', '-')}"},
            "_id": str(uuid.uuid4()),
            "_anomaly_type": "port_scan",
        })
    return records


def generate_data_exfiltration(source_ip: Optional[str] = None) -> list[dict]:
    """Simulate large outbound data transfer (exfiltration)."""
    src = source_ip or _rand_internal_ip()
    dest = _rand_external_ip()
    base_time = datetime.now(timezone.utc) - timedelta(minutes=10)
    records = []
    for i in range(20):
        ts = base_time + timedelta(seconds=i * 30)
        records.append({
            "@timestamp": _iso(ts),
            "event": {"kind": "event", "category": "network", "type": "connection", "outcome": "success"},
            "source": {"ip": src, "port": 49152 + i, "bytes": random.randint(5_000_000, 50_000_000)},
            "destination": {"ip": dest, "port": 443, "bytes": random.randint(500, 5_000)},
            "network": {"transport": "tcp", "protocol": "https",
                        "bytes": random.randint(5_000_000, 50_000_000), "packets": random.randint(3000, 30000)},
            "host": {"hostname": f"ws-{src.replace('.', '-')}"},
            "_id": str(uuid.uuid4()),
            "_anomaly_type": "data_exfiltration",
        })
    return records


def generate_lateral_movement(pivot_ip: Optional[str] = None) -> list[dict]:
    """Simulate lateral movement via RDP/SSH across hosts."""
    pivot = pivot_ip or _rand_internal_ip()
    base_time = datetime.now(timezone.utc) - timedelta(minutes=15)
    records = []
    for i in range(10):
        target = _rand_internal_ip()
        port = random.choice([3389, 22, 445])
        ts = base_time + timedelta(minutes=i)
        records.append({
            "@timestamp": _iso(ts),
            "event": {"kind": "event", "category": "network", "type": "connection", "outcome": "success"},
            "source": {"ip": pivot, "port": random.randint(49152, 65535)},
            "destination": {"ip": target, "port": port},
            "network": {"transport": "tcp", "protocol": SERVICES.get(port, "unknown"),
                        "bytes": random.randint(50_000, 500_000), "packets": random.randint(100, 1000)},
            "host": {"hostname": f"ws-{pivot.replace('.', '-')}"},
            "_id": str(uuid.uuid4()),
            "_anomaly_type": "lateral_movement",
        })
    return records


# ──────────────────────────────────────────────────────────────────────────────
# Anomaly Detection findings
# ──────────────────────────────────────────────────────────────────────────────

def generate_anomaly_findings(
    detector_id: str = "default-detector",
    n_normal: int = 10,
    n_high: int = 3,
    n_critical: int = 2,
) -> list[dict]:
    """
    Generate a mix of low-score (normal) and high-score (alert) AD findings.
    """
    findings = []
    base_time = datetime.now(timezone.utc) - timedelta(hours=1)

    # Normal / low-score findings
    for i in range(n_normal):
        ts = base_time + timedelta(minutes=i * 5)
        findings.append(
            _make_finding(
                detector_id=detector_id,
                entity_ip=_rand_internal_ip(),
                score=round(random.uniform(0.1, 0.65), 4),
                timestamp=ts,
            )
        )

    # High-score findings
    for i in range(n_high):
        ts = base_time + timedelta(minutes=30 + i * 5)
        findings.append(
            _make_finding(
                detector_id=detector_id,
                entity_ip=_rand_internal_ip(),
                score=round(random.uniform(0.78, 0.89), 4),
                timestamp=ts,
            )
        )

    # Critical findings
    for i in range(n_critical):
        ts = base_time + timedelta(minutes=50 + i * 3)
        findings.append(
            _make_finding(
                detector_id=detector_id,
                entity_ip=_rand_external_ip(),
                score=round(random.uniform(0.92, 0.99), 4),
                timestamp=ts,
                feature_overrides={
                    "network.bytes": random.randint(40_000_000, 200_000_000),
                    "unique_dest_ports": random.randint(100, 500),
                },
            )
        )

    random.shuffle(findings)
    return findings


def _make_finding(
    detector_id: str,
    entity_ip: str,
    score: float,
    timestamp: datetime,
    feature_overrides: Optional[dict] = None,
) -> dict:
    end_time = timestamp
    start_time = end_time - timedelta(minutes=10)
    features = {
        "network.bytes": random.randint(1000, 500_000),
        "unique_dest_ports": random.randint(1, 20),
        "connection_count": random.randint(5, 200),
    }
    if feature_overrides:
        features.update(feature_overrides)

    return {
        "_id": str(uuid.uuid4()),
        "detector_id": detector_id,
        "anomaly_score": score,
        "entity": {"name": "source.ip", "value": entity_ip},
        "anomaly_grade": score,
        "confidence": round(random.uniform(0.7, 1.0), 3),
        "data_start_time": _epoch_ms(start_time),
        "data_end_time": _epoch_ms(end_time),
        "feature_data": [
            {"feature_id": fk, "feature_name": fk, "data": fv}
            for fk, fv in features.items()
        ],
        "relevant_attribution": [
            {"feature_name": fk, "attribution": round(random.uniform(0, 1), 3)}
            for fk in features
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────
# Pre-built RAG baseline chunks
# ──────────────────────────────────────────────────────────────────────────────

BASELINE_TEXTS = [
    (
        "Normal outbound traffic predominantly uses TCP port 443 (HTTPS) and port 80 (HTTP). "
        "Average bytes per connection is approximately 10,000 bytes. DNS traffic is high-frequency "
        "but low-volume (< 200 bytes), using UDP port 53."
    ),
    (
        "Internal hosts connect to external IPs 8.8.8.8 and 1.1.1.1 for DNS resolution. "
        "SSH connections on port 22 are expected from the 10.0.1.x management subnet only."
    ),
    (
        "Data transfer volumes are typically under 5 MB per session during business hours. "
        "Large transfers (>10 MB) are only expected from the backup server at 192.168.1.50 "
        "between 02:00 and 04:00 UTC."
    ),
    (
        "RDP (port 3389) is used exclusively by the IT admin team from 10.0.2.x/24 subnet. "
        "No RDP connections should originate from external IPs or the user subnet 10.0.1.x."
    ),
    (
        "Port scanning activity is never observed from internal hosts. Any host connecting "
        "to more than 20 unique destination ports within a 10-minute window should be considered "
        "anomalous."
    ),
    (
        "SMTP traffic (ports 25 and 587) is only generated by the mail relay server at 10.0.2.10. "
        "Other hosts sending SMTP traffic indicate potential spam or exfiltration."
    ),
    (
        "WebSocket upgrades and long-lived connections on port 8080 are expected from the "
        "application tier (10.0.2.x) to load balancers. These can produce large byte counts "
        "but at low packet rates."
    ),
]


def generate_baseline_chunks() -> list[dict]:
    """
    Return pre-built text chunks suitable for seeding the RAG vector store.
    Each chunk gets a deterministic SHA256 ID.
    """
    chunks = []
    for text in BASELINE_TEXTS:
        doc_id = hashlib.sha256(text.encode()).hexdigest()[:32]
        chunks.append({
            "_id": doc_id,
            "text": text,
            "category": "network_baseline",
            "source": "data_generator",
            "@timestamp": _iso(datetime.now(timezone.utc)),
        })
    return chunks


# ──────────────────────────────────────────────────────────────────────────────
# Deterministic mini-embeddings (for tests without a live LLM)
# ──────────────────────────────────────────────────────────────────────────────

def deterministic_embed(text: str, dims: int = 64) -> list[float]:
    """
    Produce a stable, normalized embedding from text without an LLM.
    Uses a character-hash approach — good enough for unit tests.
    """
    import hashlib

    h = hashlib.sha256(text.encode()).digest()
    # Build a longer seed by repeating the digest
    seed = (h * (dims // len(h) + 1))[:dims]
    raw = [((b / 255.0) * 2.0 - 1.0) for b in seed]
    # Normalize
    norm = math.sqrt(sum(x * x for x in raw)) or 1.0
    return [x / norm for x in raw]
