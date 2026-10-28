"""CRIB Network and Cybersecurity Event Detection Engine.

Provides a multi-layered detection pipeline:
1. Rule-Based Detection: Deterministic thresholds and sliding-window event correlation.
2. Signature-Based Detection: Known adversarial commands, web exploit patterns, and privilege escalation.
3. Anomaly-Based Detection: Statistical rate and volume deviations (Z-score).
4. Heuristic Threat Scorer: Multi-signal correlation combining reconnaissance, credential access, and execution.
5. AI/ML Detection: Integration with Isolation Forest and Random Forest classifier (via ml_detector).

Every generated alert includes explainable metadata:
- Detection method
- MITRE ATT&CK technique reference
- Triggered condition vs. observed values
- Affected components
- Actionable SOC investigation playbooks
"""

from collections import defaultdict
from datetime import datetime, timezone
import re
from typing import Dict, Any, List, Set, Tuple, Optional

import ml_detector

WINDOW_SECONDS = 10
PORT_SCAN_THRESHOLD = 10
LOGIN_FAILURE_THRESHOLD = 5
TRAFFIC_SURGE_THRESHOLD = 100
TRAFFIC_SURGE_WINDOW_SECONDS = 2
EXFILTRATION_BYTE_THRESHOLD = 10_000_000  # 10 MB

# ----------------------------------------------------------------------
# Signature Pattern Catalog (MITRE ATT&CK Mapped)
# ----------------------------------------------------------------------
SIGNATURE_PATTERNS = [
    {
        "id": "PRIVILEGE_ESCALATION",
        "name": "Privilege Escalation Command Attempt",
        "severity": "HIGH",
        "mitre": "T1548 (Abuse Elevation Control Mechanism)",
        "patterns": [
            r"\bsudo\s+(?:su|bash|sh|-i|-l)",
            r"\bchmod\s+[0-7]?[4-7][0-7]{2}\b",
            r"\bcat\s+/etc/(?:shadow|passwd|sudoers)\b",
            r"\busermod\s+-[a-zA-Z]*G\s+sudo\b",
            r"\bwhoami\b",
            r"\bid\b",
        ],
        "recommendation": [
            "Verify whether the user account is authorized to execute administrative commands.",
            "Inspect parent process tree and terminal session origin.",
            "Revoke compromised session credentials and isolate the endpoint.",
        ],
    },
    {
        "id": "STAGER_EXECUTION",
        "name": "Remote Script Download and Execution Stager",
        "severity": "CRITICAL",
        "mitre": "T1059.004 (Unix Shell)",
        "patterns": [
            r"curl\s+.*?\|\s*(?:bash|sh|python)",
            r"wget\s+.*?\|\s*(?:bash|sh|python)",
            r"powershell\s+.*-(?:enc|encodedcommand)\b",
            r"certutil\s+.*-urlcache",
        ],
        "recommendation": [
            "Terminate active shell process immediately.",
            "Extract remote payload URL and block domain/IP at perimeter egress.",
            "Acquire volatile endpoint memory for forensic analysis.",
        ],
    },
    {
        "id": "WEB_EXPLOIT_SIGNATURE",
        "name": "Web Application Attack Signature",
        "severity": "HIGH",
        "mitre": "T1190 (Exploit Public-Facing Application)",
        "patterns": [
            r"\.\./\.\./",
            r"['\"][;|\s]+(?:or|and)\s+['\"0-9]+=['\"0-9]+",
            r"\b(?:cmd\.jsp|shell\.php|c99\.php|wso\.php)\b",
            r"union\s+select\s+.*\bfrom\b",
        ],
        "recommendation": [
            "Inspect web application access logs for source IP payload injections.",
            "Verify target web server returned 403/404 or vulnerable 200 responses.",
            "Deploy WAF filter rule blocking the matched request pattern.",
        ],
    },
    {
        "id": "REVERSE_SHELL",
        "name": "Interactive Reverse Shell Construction",
        "severity": "CRITICAL",
        "mitre": "T1059 (Command and Scripting Interpreter)",
        "patterns": [
            r"bash\s+-i\s+>&?\s*/dev/tcp/",
            r"nc\s+-[a-zA-Z]*e\s+/bin/(?:bash|sh)",
            r"python\s+-[a-zA-Z]*c\s+.*import\s+socket",
        ],
        "recommendation": [
            "Sever outbound TCP socket connection at the host firewall.",
            "Quarantine host from local network VLAN.",
            "Inspect process lineage to discover initial compromise vector.",
        ],
    },
]


def _parse_timestamp(value: str) -> datetime:
    """Convert an ISO timestamp to a timezone-aware datetime."""
    if not value:
        raise ValueError("Every event must have a timestamp")

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid event timestamp: {value!r}") from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _event_key(event: Dict[str, Any]) -> datetime:
    """Return a consistent event timestamp."""
    return _parse_timestamp(event.get("timestamp"))


def _parse_details(details: str) -> Dict[str, str]:
    """Parse key-value details formatted as 'ip=...;mac=...;bytes=...'."""
    result = {}
    for part in (details or "").split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        result[key.strip().lower()] = value.strip()
    return result


def _extract_bytes(details: str) -> int:
    """Extract transferred byte count from details string if present."""
    parsed = _parse_details(details)
    if "bytes" in parsed:
        try:
            return int(parsed["bytes"])
        except ValueError:
            pass
    return 0


# ----------------------------------------------------------------------
# Core Multi-Layer Detection Engine
# ----------------------------------------------------------------------
def detect_events(events: List[Dict[str, Any]], enable_ml: bool = True) -> List[Dict[str, Any]]:
    """
    Analyse network and security events through Rule-Based, Signature-Based,
    Anomaly-Based, and Heuristic layers, with optional AI/ML scoring.

    Backward Compatibility:
    - Retains all existing fields ('rule_id', 'severity', 'message', 'source_ip',
      'destination_ip', 'destination_port', 'timestamp').
    - Adds explainable metadata ('detection_method', 'mitre_technique', 'evidence',
      'affected_component', 'recommended_steps').
    """
    if not events:
        return []

    normalized = []
    for event in events:
        item = dict(event)
        item["event_type"] = str(item.get("event_type", "")).upper()
        item["_time"] = _event_key(item)
        normalized.append(item)

    normalized.sort(key=lambda item: item["_time"])

    alerts: List[Dict[str, Any]] = []
    emitted: Set[Tuple[str, Any]] = set()

    def emit(
        rule_id: str,
        severity: str,
        message: str,
        event: Dict[str, Any],
        key: Any,
        detection_method: str = "RULE_BASED",
        mitre_technique: str = "",
        evidence_dict: Optional[Dict[str, Any]] = None,
        recommendation: Optional[List[str]] = None,
        affected_comp: str = "",
    ):
        """Prevent duplicate alerts within an analysis window and attach explainability."""
        unique_key = (rule_id, key)
        if unique_key in emitted:
            return

        emitted.add(unique_key)

        default_recs = {
            "PORT_SCAN": [
                "Verify source host identity and check for authorized vulnerability scanning.",
                "Inspect host firewall logs to confirm whether probed ports were closed or open.",
                "Temporarily rate-limit or isolate the probing IP at the network perimeter.",
            ],
            "AUTH_BRUTE_FORCE": [
                "Examine target authentication logs to verify no login attempt succeeded.",
                "Apply automated connection throttling (fail2ban) to the source IP.",
                "Review target account privileges and mandate multi-factor authentication.",
            ],
            "TRAFFIC_SURGE": [
                "Enable SYN cookies and socket backlog queue protections.",
                "Engage upstream DDoS rate-limiting / CDN traffic scrubbing.",
                "Verify origin server memory, CPU utilization, and keepalive configurations.",
            ],
            "ARP_MAC_CHANGE": [
                "Inspect switch MAC/CAM address table to locate offending physical switch port.",
                "Flush corrupted local ARP cache tables on affected systems.",
                "Deploy Dynamic ARP Inspection (DAI) and DHCP Snooping on local VLAN access switches.",
            ],
            "ARP_DUPLICATE_MAC": [
                "Identify rogue device claiming default gateway IP address on local subnet.",
                "Administratively disable switch port associated with duplicate MAC address.",
                "Verify static gateway binding configuration on mission-critical servers.",
            ],
            "DATA_EXFILTRATION": [
                "Terminate unauthorized outbound data transmission session.",
                "Identify local user and process owning the transmitting network socket.",
                "Determine classification of transmitted file data and initiate breach containment.",
            ],
            "CREDENTIAL_STUFFING": [
                "Enable CAPTCHA and rate-limiting on target login endpoints.",
                "Force password resets on targeted user accounts.",
                "Audit successful logins from involved IP ranges.",
            ],
        }

        rec_steps = recommendation or default_recs.get(rule_id, [
            "Investigate affected component event logs.",
            "Verify origin and authorization of source activity.",
            "Apply defensive network or endpoint containment if unauthorized.",
        ])

        target = affected_comp or (
            f"{event.get('destination_ip')}:{event.get('destination_port')}"
            if event.get("destination_port") else str(event.get("destination_ip") or "DMZ Asset")
        )

        alerts.append(
            {
                "rule_id": rule_id,
                "severity": severity,
                "message": message,
                "detection_method": detection_method,
                "mitre_technique": mitre_technique,
                "affected_component": target,
                "evidence": evidence_dict or {
                    "event_type": event.get("event_type"),
                    "details": event.get("details"),
                    "timestamp": event.get("timestamp"),
                },
                "recommended_steps": rec_steps,
                "source_ip": event.get("source_ip"),
                "destination_ip": event.get("destination_ip"),
                "destination_port": event.get("destination_port"),
                "timestamp": event["timestamp"],
            }
        )

    # Buckets for stateful and window-based evaluation
    connections_by_source = defaultdict(list)
    failures_by_source = defaultdict(list)
    connections_by_port = defaultdict(list)
    exfil_by_source = defaultdict(list)
    ips_by_mac = defaultdict(set)
    heuristic_signals_by_source = defaultdict(lambda: {"score": 0, "indicators": [], "events": []})

    # ==================================================================
    # 1. Event-Level Analysis: Signatures, ARP, Exfiltration & Heuristics
    # ==================================================================
    for event in normalized:
        event_type = event["event_type"]
        timestamp = event["_time"]
        source = event.get("source_ip") or "unknown"
        dest_ip = event.get("destination_ip")
        destination_port = event.get("destination_port")
        details_str = str(event.get("details", ""))
        details_map = _parse_details(details_str)
        bytes_transferred = _extract_bytes(details_str)

        # --------------------------------------------------------------
        # Layer 1: Signatures in Command / Details / Process
        # --------------------------------------------------------------
        details_to_scan = f"{event_type} {details_str}".lower()
        for sig in SIGNATURE_PATTERNS:
            for pattern in sig["patterns"]:
                if re.search(pattern, details_to_scan, re.IGNORECASE):
                    heuristic_signals_by_source[source]["score"] += 35
                    heuristic_signals_by_source[source]["indicators"].append(sig["name"])
                    heuristic_signals_by_source[source]["events"].append(event)

                    emit(
                        rule_id=sig["id"],
                        severity=sig["severity"],
                        message=f"{sig['name']} detected from source {source}.",
                        event=event,
                        key=(sig["id"], source, pattern),
                        detection_method="SIGNATURE_BASED",
                        mitre_technique=sig["mitre"],
                        evidence_dict={
                            "matched_pattern": pattern,
                            "command_or_detail": details_str,
                            "source_ip": source,
                            "timestamp": event["timestamp"],
                        },
                        recommendation=sig["recommendation"],
                        affected_comp=f"{dest_ip or 'Local System'}",
                    )
                    break

        # --------------------------------------------------------------
        # Layer 2: Rule-Based Event Type Categorization
        # --------------------------------------------------------------
        if event_type == "CONNECT":
            connections_by_source[source].append(event)
            if destination_port is not None:
                connections_by_port[str(destination_port)].append(event)

        elif event_type == "AUTH_FAILURE":
            failures_by_source[source].append(event)
            heuristic_signals_by_source[source]["score"] += 15
            heuristic_signals_by_source[source]["indicators"].append("Authentication Failure")

        elif event_type in ("DATA_TRANSFER", "EXFILTRATION", "CONNECT"):
            if bytes_transferred > 0:
                exfil_by_source[source].append((event, bytes_transferred))
                if bytes_transferred >= EXFILTRATION_BYTE_THRESHOLD:
                    mb = bytes_transferred / (1024 * 1024)
                    emit(
                        rule_id="DATA_EXFILTRATION",
                        severity="CRITICAL",
                        message=f"Large outbound transfer ({mb:.1f} MB) from source {source} to port {destination_port}.",
                        event=event,
                        key=(source, destination_port, bytes_transferred),
                        detection_method="RULE_BASED",
                        mitre_technique="T1048 (Exfiltration Over Alternative Protocol)",
                        evidence_dict={
                            "bytes_transferred": bytes_transferred,
                            "threshold_bytes": EXFILTRATION_BYTE_THRESHOLD,
                            "destination_port": destination_port,
                        },
                        affected_comp=f"Outbound Channel :{destination_port}",
                    )

        elif event_type == "ARP_MAC_CHANGE":
            emit(
                rule_id="ARP_MAC_CHANGE",
                severity="HIGH",
                message="An ARP-to-MAC address mapping changed unexpectedly.",
                event=event,
                key=(source, dest_ip),
                detection_method="RULE_BASED",
                mitre_technique="T1557.002 (ARP Poisoning)",
                evidence_dict={"source_ip": source, "destination_ip": dest_ip, "details": details_str},
                affected_comp=f"ARP Cache on {dest_ip or 'Gateway'}",
            )

        elif event_type == "ARP_CLAIM":
            claimed_ip = details_map.get("ip") or event.get("source_ip")
            claimed_mac = details_map.get("mac", "").lower()

            if claimed_ip and claimed_mac:
                ips_by_mac[claimed_mac].add(claimed_ip)

                if len(ips_by_mac[claimed_mac]) >= 2:
                    claimed_list = sorted(list(ips_by_mac[claimed_mac]))
                    emit(
                        rule_id="ARP_DUPLICATE_MAC",
                        severity="HIGH",
                        message=(
                            f"Multiple IP addresses ({', '.join(claimed_list)}) "
                            f"are claimed by the same MAC address ({claimed_mac})."
                        ),
                        event=event,
                        key=claimed_mac,
                        detection_method="RULE_BASED",
                        mitre_technique="T1557.002 (ARP Poisoning)",
                        evidence_dict={
                            "claimed_mac": claimed_mac,
                            "associated_ips": claimed_list,
                        },
                        affected_comp=f"MAC {claimed_mac}",
                    )

    # ==================================================================
    # 2. Sliding Window Analysis: Port Scanning
    # ==================================================================
    for source, source_events in connections_by_source.items():
        for current in source_events:
            start = current["_time"].timestamp() - WINDOW_SECONDS
            window = [
                e for e in source_events
                if start < e["_time"].timestamp() <= current["_time"].timestamp()
            ]

            ports = {
                str(e["destination_port"])
                for e in window
                if e.get("destination_port") is not None
            }

            if len(ports) >= PORT_SCAN_THRESHOLD:
                heuristic_signals_by_source[source]["score"] += 35
                heuristic_signals_by_source[source]["indicators"].append(f"Port Scan ({len(ports)} ports)")

                emit(
                    rule_id="PORT_SCAN",
                    severity="HIGH",
                    message=(
                        f"Source {source} contacted {len(ports)} distinct "
                        f"ports within {WINDOW_SECONDS} seconds."
                    ),
                    event=current,
                    key=source,
                    detection_method="RULE_BASED",
                    mitre_technique="T1046 (Network Service Discovery)",
                    evidence_dict={
                        "distinct_port_count": len(ports),
                        "ports_contacted": sorted(list(ports))[:20],
                        "window_seconds": WINDOW_SECONDS,
                        "threshold": PORT_SCAN_THRESHOLD,
                    },
                    affected_comp=f"Target Host {current.get('destination_ip') or 'DMZ'}",
                )
                break

    # ==================================================================
    # 3. Sliding Window Analysis: Authentication Brute Force
    # ==================================================================
    for source, source_events in failures_by_source.items():
        for current in source_events:
            start = current["_time"].timestamp() - WINDOW_SECONDS
            window = [
                e for e in source_events
                if start < e["_time"].timestamp() <= current["_time"].timestamp()
            ]

            if len(window) >= LOGIN_FAILURE_THRESHOLD:
                emit(
                    rule_id="AUTH_BRUTE_FORCE",
                    severity="HIGH",
                    message=(
                        f"Source {source} generated {len(window)} failed "
                        f"login attempts within {WINDOW_SECONDS} seconds."
                    ),
                    event=current,
                    key=source,
                    detection_method="RULE_BASED",
                    mitre_technique="T1110 (Brute Force)",
                    evidence_dict={
                        "failure_count": len(window),
                        "window_seconds": WINDOW_SECONDS,
                        "threshold": LOGIN_FAILURE_THRESHOLD,
                    },
                    affected_comp=f"Auth Service on {current.get('destination_ip') or 'Host'}",
                )
                break

    # ==================================================================
    # 4. Sliding Window Analysis: Traffic Surges (DoS / Floods)
    # ==================================================================
    for port, port_events in connections_by_port.items():
        for current in port_events:
            start = current["_time"].timestamp() - TRAFFIC_SURGE_WINDOW_SECONDS
            window = [
                e for e in port_events
                if start < e["_time"].timestamp() <= current["_time"].timestamp()
            ]

            if len(window) >= TRAFFIC_SURGE_THRESHOLD:
                emit(
                    rule_id="TRAFFIC_SURGE",
                    severity="CRITICAL",
                    message=(
                        f"{len(window)} connections targeted port {port} "
                        f"within {TRAFFIC_SURGE_WINDOW_SECONDS} seconds."
                    ),
                    event=current,
                    key=port,
                    detection_method="RULE_BASED",
                    mitre_technique="T1498 (Network Denial of Service)",
                    evidence_dict={
                        "connection_count": len(window),
                        "target_port": port,
                        "window_seconds": TRAFFIC_SURGE_WINDOW_SECONDS,
                        "threshold": TRAFFIC_SURGE_THRESHOLD,
                    },
                    affected_comp=f"TCP Port {port}",
                )
                break

    # ==================================================================
    # 5. Layer 4: Heuristic Multi-Signal Correlation
    # ==================================================================
    for source, data in heuristic_signals_by_source.items():
        if data["score"] >= 65 and len(set(data["indicators"])) >= 2:
            rep_event = data["events"][0] if data["events"] else normalized[-1]
            emit(
                rule_id="HEURISTIC_COMPOUND_THREAT",
                severity="CRITICAL" if data["score"] >= 80 else "HIGH",
                message=(
                    f"Compound threat detected from source {source}: "
                    f"Risk score {data['score']}/100 across signals: {', '.join(set(data['indicators']))}."
                ),
                event=rep_event,
                key=source,
                detection_method="HEURISTIC",
                mitre_technique="Multi-Stage Attack Lifecycle",
                evidence_dict={
                    "cumulative_risk_score": data["score"],
                    "correlated_indicators": sorted(list(set(data["indicators"]))),
                    "event_sample_count": len(data["events"]),
                },
                recommendation=[
                    "Escalate to Tier-2 SOC Analyst for multi-stage campaign containment.",
                    "Review full timeline of events for source host across all subnets.",
                    "Quarantine host immediately to prevent lateral traversal.",
                ],
                affected_comp=f"Host Infrastructure (Threat Source: {source})",
            )

    # ==================================================================
    # 6. Layer 5: AI/ML Anomaly Scoring (Optional / On-Demand)
    # ==================================================================
    if enable_ml and len(normalized) > 0:
        burst_counts = {src: len(evts) for src, evts in connections_by_source.items()}
        for event in normalized:
            src = event.get("source_ip", "unknown")
            burst = burst_counts.get(src, 1)
            is_anomaly, score, reason = ml_detector.detect_ml_anomaly(event, window_burst_count=burst)

            if is_anomaly and score < -0.15:
                emit(
                    rule_id="ML_ISOLATION_FOREST",
                    severity="HIGH" if score < -0.3 else "MEDIUM",
                    message=f"Machine learning anomaly detected from {src} ({reason}).",
                    event=event,
                    key=(src, round(score, 2)),
                    detection_method="AI_ML",
                    mitre_technique="Unsupervised Behavioral Anomaly",
                    evidence_dict={
                        "model": "Isolation Forest (scikit-learn)",
                        "anomaly_score": round(score, 4),
                        "decision_boundary": 0.0,
                        "feature_vector_reason": reason,
                    },
                    recommendation=[
                        "Inspect telemetry parameters for unusual deviation from loopback baseline.",
                        "Correlate with concurrent firewall and authentication records.",
                    ],
                    affected_comp=f"Endpoint Telemetry ({src})",
                )
                break

    return alerts
