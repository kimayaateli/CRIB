"""CRIB Controlled Local Network Lab.

Provides a safe, isolated, and repeatable networking environment for hands-on
exercises using loopback networking (127.0.0.1).

Key Safety & Architectural Guarantees:
1. Target restriction: ONLY loopback (127.0.0.1 / localhost) is permitted.
2. Port restriction: Only user-space unprivileged ports (1024 - 65535) or designated lab ports.
3. Strict socket timeouts (maximum 2.0s) to prevent hanging processes.
4. No arbitrary shell or subprocess execution.
5. All genuine local network events are explicitly recorded with evidence origin 'GENUINE_LOCAL_OBSERVATION'.
"""

import socket
import threading
import time
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

import database
import detect

LAB_HOST = "127.0.0.1"
DEFAULT_LAB_PORTS = [9100, 9101, 9102, 9103]
ALLOWED_PORT_MIN = 1024
ALLOWED_PORT_MAX = 65535
SOCKET_TIMEOUT = 1.5

_active_servers: Dict[int, Any] = {}
_lock = threading.Lock()


def validate_lab_target(host: str, port: int) -> None:
    """Validate that host is strictly loopback and port is within safe range."""
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError("Lab exercises are strictly restricted to local loopback (127.0.0.1).")

    if not isinstance(port, int) or port < ALLOWED_PORT_MIN or port > ALLOWED_PORT_MAX:
        raise ValueError(
            f"Port must be an integer between {ALLOWED_PORT_MIN} and {ALLOWED_PORT_MAX}."
        )


def start_lab_echo_service(port: int = 9100) -> Dict[str, Any]:
    """
    Start a local TCP echo server on loopback for controlled testing.
    Idempotent: if already running on that port, returns status without error.
    """
    validate_lab_target(LAB_HOST, port)

    with _lock:
        if port in _active_servers:
            return {
                "status": "already_running",
                "host": LAB_HOST,
                "port": port,
                "message": f"Lab TCP service already running on {LAB_HOST}:{port}",
            }

        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.settimeout(1.0)
        server_sock.bind((LAB_HOST, port))
        server_sock.listen(5)

        stop_event = threading.Event()

        def _serve():
            while not stop_event.is_set():
                try:
                    client_conn, client_addr = server_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                try:
                    client_conn.settimeout(1.0)
                    data = client_conn.recv(1024)
                    if data:
                        client_conn.sendall(b"CRIB_ECHO: " + data)
                except Exception:
                    pass
                finally:
                    client_conn.close()

            server_sock.close()

        thread = threading.Thread(target=_serve, daemon=True, name=f"CRIB-Echo-{port}")
        thread.start()

        _active_servers[port] = {
            "server_sock": server_sock,
            "thread": thread,
            "stop_event": stop_event,
            "started_at": datetime.now(timezone.utc).isoformat(),
        }

        database.add_event(
            event_type="LAB_SERVICE_START",
            source_ip=LAB_HOST,
            destination_ip=LAB_HOST,
            destination_port=port,
            details=f"Local TCP Echo service listener activated on port {port} (GENUINE_LOCAL_OBSERVATION)",
        )

        return {
            "status": "started",
            "host": LAB_HOST,
            "port": port,
            "message": f"Lab TCP service successfully started on {LAB_HOST}:{port}",
        }


def stop_lab_echo_service(port: int = 9100) -> Dict[str, Any]:
    """Stop the local TCP echo server on loopback."""
    validate_lab_target(LAB_HOST, port)

    with _lock:
        server_info = _active_servers.pop(port, None)
        if not server_info:
            return {
                "status": "not_running",
                "host": LAB_HOST,
                "port": port,
                "message": f"No active lab service was running on port {port}.",
            }

        server_info["stop_event"].set()

        database.add_event(
            event_type="LAB_SERVICE_STOP",
            source_ip=LAB_HOST,
            destination_ip=LAB_HOST,
            destination_port=port,
            details=f"Local TCP Echo service on port {port} stopped (GENUINE_LOCAL_OBSERVATION)",
        )

        return {
            "status": "stopped",
            "host": LAB_HOST,
            "port": port,
            "message": f"Lab TCP service on port {port} has been terminated.",
        }


def run_tcp_probe(
    host: str = LAB_HOST,
    port: int = 9100,
    payload: str = "PING"
) -> Dict[str, Any]:
    """
    Perform a genuine, controlled local TCP probe against loopback.
    Measures latency and returns the received response.
    """
    validate_lab_target(host, port)
    safe_payload = (payload or "PING")[:128].encode("utf-8")

    start_time = time.perf_counter()
    response_text = ""
    is_success = False

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(SOCKET_TIMEOUT)
            sock.connect((host, port))
            sock.sendall(safe_payload)
            reply = sock.recv(1024)
            response_text = reply.decode("utf-8", errors="replace")
            is_success = True
    except ConnectionRefusedError:
        response_text = "Connection Refused (Port is closed / no listener)"
    except socket.timeout:
        response_text = f"Connection Timed Out after {SOCKET_TIMEOUT}s"
    except Exception as exc:
        response_text = f"Socket error: {str(exc)}"

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

    database.add_event(
        event_type="LAB_TCP_PROBE",
        source_ip=LAB_HOST,
        destination_ip=host,
        destination_port=port,
        details=(
            f"Genuine local TCP probe; latency={elapsed_ms}ms; "
            f"success={is_success}; response={response_text[:60]}; origin=GENUINE_LOCAL_OBSERVATION"
        ),
    )

    return {
        "host": host,
        "port": port,
        "success": is_success,
        "elapsed_ms": elapsed_ms,
        "response": response_text,
        "origin": "GENUINE_LOCAL_OBSERVATION",
    }


def run_controlled_scan(ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
    """
    Safely probe a list of predefined local ports on 127.0.0.1.
    Demonstrates how connection events correlate to port status.
    """
    target_ports = ports or DEFAULT_LAB_PORTS
    results = []

    for port in target_ports:
        validate_lab_target(LAB_HOST, port)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.3)
                res = sock.connect_ex((LAB_HOST, port))
                is_open = (res == 0)
        except Exception:
            is_open = False

        status_str = "OPEN" if is_open else "CLOSED"
        database.add_event(
            event_type="CONNECT",
            source_ip=LAB_HOST,
            destination_ip=LAB_HOST,
            destination_port=port,
            details=f"Local lab port verification: port {port} is {status_str} (GENUINE_LOCAL_OBSERVATION)",
        )

        results.append({
            "port": port,
            "state": status_str,
            "host": LAB_HOST,
        })

    return results


def run_detection_demo(burst_size: int = 12) -> Dict[str, Any]:
    """
    Demonstrate real-time detection by generating a safe sequence of local events
    and piping them immediately into the detection engine.
    """
    burst_size = max(5, min(30, burst_size))
    generated_events = []
    now = datetime.now(timezone.utc)

    # Generate sequential connections to trigger PORT_SCAN rule
    for i in range(burst_size):
        event = {
            "event_type": "CONNECT",
            "source_ip": "127.0.0.1",
            "destination_ip": "127.0.0.1",
            "destination_port": 9100 + i,
            "timestamp": now.isoformat().replace("+00:00", "Z"),
            "details": f"Controlled detection test connection to port {9100 + i}",
        }
        generated_events.append(event)
        database.add_event(
            event_type=event["event_type"],
            source_ip=event["source_ip"],
            destination_ip=event["destination_ip"],
            destination_port=event["destination_port"],
            details=event["details"] + " (CONTROLLED_DETECTION_DEMO)",
        )

    # Run detection engine
    alerts = detect.detect_events(generated_events)

    # Store any resulting alerts
    saved_alerts = []
    for alert in alerts:
        recs = "; ".join(alert.get("recommended_steps", []))
        alert_id = database.add_alert(
            incident_id=None,
            rule_id=alert["rule_id"],
            severity=alert["severity"],
            message=alert["message"],
            detection_method=alert.get("detection_method", "RULE_BASED"),
            mitre_technique=alert.get("mitre_technique", ""),
            affected_component=alert.get("affected_component", ""),
            recommendation=recs,
        )
        saved_alerts.append({
            "id": alert_id,
            "rule_id": alert["rule_id"],
            "severity": alert["severity"],
            "message": alert["message"],
            "detection_method": alert.get("detection_method", "RULE_BASED"),
            "mitre_technique": alert.get("mitre_technique", ""),
            "affected_component": alert.get("affected_component", ""),
        })

    return {
        "generated_events_count": len(generated_events),
        "triggered_alerts": saved_alerts,
        "message": f"Generated {burst_size} local events. Detection engine fired {len(saved_alerts)} alert(s).",
    }


def get_lab_status() -> Dict[str, Any]:
    """Return status of all active lab services."""
    with _lock:
        services = [
            {"port": port, "started_at": info["started_at"]}
            for port, info in _active_servers.items()
        ]

    return {
        "active_services_count": len(services),
        "services": services,
        "default_ports": DEFAULT_LAB_PORTS,
    }
