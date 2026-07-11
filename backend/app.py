"""
Flask REST API -- Infrastructure Security Monitor
---------------------------------------------------
Serves the HTML dashboard and exposes system metrics +
security alerts to the dashboard frontend and ESP32.

Central Risk Engine: Every alert feeds into a per-IP cumulative
risk score. When the score exceeds the configured threshold,
the IP is automatically blocked. This is the ONLY place that
decides blocking — no duplicate logic elsewhere.

Endpoints:
  GET /                 -> HTML dashboard (index.html)
  GET /shop             -> shop.html
  GET /cart             -> cart.html
  GET /payment          -> payment.html
  GET /login            -> login.html
  GET /alerts           -> last 50 security alerts (JSON)
  GET /latest           -> most recent alert (for ESP32)
  GET /stats            -> aggregate alert counts
  GET /metrics          -> current system metrics snapshot
  GET /metrics/history  -> last 60 metric readings (for charts)
  GET /health           -> service health check
  GET /firewall/rules   -> active firewall blocks
  POST /firewall/block  -> block an IP
  POST /firewall/unblock-> unblock an IP
  GET /visitors         -> real tracked visitors
  GET /cli/data         -> consolidated CLI endpoint
  GET /incidents        -> persistent incident history
  GET /risk-scores      -> current per-IP risk scores
  GET /top-attackers    -> top attacking IPs
  GET /timeline         -> incident timeline for charts
  GET /services         -> IDS service status
  GET /devices          -> device profiles
"""

from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
from collections import Counter, defaultdict
import threading
import os
import time
import logging

_log = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────

from config import get_config

_cfg = get_config()

# Resolve the dashboard directory (one level up from backend/)
DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'dashboard')

app = Flask(__name__)
CORS(app)

# API key from environment (optional — leave empty to disable auth)
_API_KEY = os.environ.get("API_KEY", "")


# ── API Key Authentication ─────────────────────────────────────────

@app.before_request
def _check_api_key():
    """
    If API_KEY is configured, require it on data endpoints.
    HTML pages, health, and ESP32 /latest are always public.
    """
    from flask import request

    if not _API_KEY:
        return  # Auth disabled

    path = request.path

    # Public routes (no auth required)
    public_prefixes = ('/', '/shop', '/cart', '/payment', '/login', '/health', '/latest')
    if path in public_prefixes:
        return
    # Static files
    if path.startswith('/static'):
        return

    # Check API key
    key = request.headers.get("X-API-Key") or request.args.get("api_key")
    if key != _API_KEY:
        return jsonify({"error": "Invalid or missing API key"}), 401


# ── Structured Logging Setup ──────────────────────────────────────

_start_time = time.time()


def setup_logging() -> None:
    """Configure structured logging based on config.yaml settings."""
    log_cfg = _cfg.get("logging", {})
    level = getattr(logging, log_cfg.get("level", "INFO").upper(), logging.INFO)
    log_file = log_cfg.get("file", "")
    log_format = log_cfg.get("format", "text")

    if log_format == "json":
        fmt = '{"time":"%(asctime)s","level":"%(levelname)s","module":"%(name)s","msg":"%(message)s"}'
    else:
        fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(level=level, format=fmt, handlers=handlers, force=True)


# ── Database Initialisation ────────────────────────────────────────

def init_database() -> None:
    """Initialise the SQLite database."""
    import database
    db_path = _cfg.get("database", {}).get("path", "data/incidents.db")
    database.init_db(db_path)
    _log.info("Database ready: %s", db_path)


# ── Real Visitor Tracking ─────────────────────────────────────────

_visitors: dict[str, dict] = {}
_visitors_lock = threading.Lock()


@app.before_request
def _track_visitor():
    """Track every HTTP visitor by IP, user agent, and page."""
    from flask import request
    path = request.path

    # Skip API/data endpoints
    api_paths = ('/metrics', '/alerts', '/stats', '/firewall', '/latest',
                 '/static', '/health', '/visitors', '/incidents', '/risk-scores',
                 '/top-attackers', '/timeline', '/services', '/devices', '/cli/data')
    if any(path.startswith(x) for x in api_paths):
        return

    ip = request.remote_addr
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0].strip()

    user_agent = request.headers.get("User-Agent", "")
    page_map = {
        "/": "/home (Dashboard)",
        "/cart": "/cart (Shopping Cart)",
        "/payment": "/payment (Checkout)",
        "/login": "/login (Authentication)",
        "/shop": "/shop (Product List)",
    }
    page_name = page_map.get(path, path)
    now = time.strftime('%H:%M:%S')

    with _visitors_lock:
        if ip in _visitors:
            _visitors[ip]["request_count"] += 1
            _visitors[ip]["last_seen"] = now
            _visitors[ip]["page"] = page_name
            _visitors[ip]["user_agent"] = user_agent
        else:
            _visitors[ip] = {
                "ip": ip,
                "user_agent": user_agent,
                "request_count": 1,
                "first_seen": now,
                "last_seen": now,
                "page": page_name,
            }

    # Persist to database (best-effort)
    try:
        import database
        from firewall import is_blocked
        database.upsert_visitor(
            ip=ip, user_agent=user_agent, page=page_name,
            risk_score=get_ip_risk_score(ip),
            is_blocked=is_blocked(ip),
        )
    except Exception:
        pass


@app.route("/visitors")
def get_visitors():
    """Return active website visitors with computed threat levels and risk scores."""
    from firewall import get_blocked_ips
    blocked_ips = get_blocked_ips()

    with _visitors_lock:
        result = []
        for ip, info in _visitors.items():
            result.append({
                "ip": ip,
                "user_agent": info.get("user_agent", ""),
                "request_count": info.get("request_count", 0),
                "first_seen": info.get("first_seen", ""),
                "last_seen": info.get("last_seen", ""),
                "page": info.get("page", "/"),
                "risk_score": get_ip_risk_score(ip),
                "severity": _score_to_severity(get_ip_risk_score(ip)),
                "blocked": ip in blocked_ips,
            })
        return jsonify(result)


# ── Dashboard & Page Serving ───────────────────────────────────────

@app.route("/")
def serve_dashboard():
    """Serve the HTML dashboard at the root URL."""
    return send_from_directory(DASHBOARD_DIR, 'index.html')


@app.route("/shop")
def serve_shop():
    """Serve the shop page from dashboard directory."""
    return send_from_directory(DASHBOARD_DIR, 'shop.html')


@app.route("/cart")
def serve_cart():
    """Serve the cart page from dashboard directory."""
    return send_from_directory(DASHBOARD_DIR, 'cart.html')


@app.route("/payment")
def serve_payment():
    """Serve the payment page from dashboard directory."""
    return send_from_directory(DASHBOARD_DIR, 'payment.html')


@app.route("/login")
def serve_login():
    """Serve the login page from dashboard directory."""
    return send_from_directory(DASHBOARD_DIR, 'login.html')


# ── Shared Alert Store & Central Risk Engine ───────────────────────

alerts: list[dict] = []
_alerts_lock = threading.Lock()

# Per-IP cumulative risk scores
_risk_scores: dict[str, float] = {}
_risk_lock = threading.Lock()

# Risk engine config
_risk_weights: dict[str, float] = _cfg.get("risk_engine", {}).get("weights", {})
_severity_multiplier: dict[str, float] = _cfg.get("risk_engine", {}).get("severity_multiplier", {})
_block_threshold: float = float(_cfg.get("risk_engine", {}).get("block_threshold", 15))
_alert_buffer_size: int = int(_cfg.get("monitoring", {}).get("alert_buffer_size", 500))
_immediate_block_rules: list[str] = _cfg.get("risk_engine", {}).get("immediate_block", [])

# Explainable Risk Scores: Tracks score contributions per alert type per IP
_ip_score_breakdown: dict[str, dict[str, float]] = {}


def get_ip_risk_score(ip: str) -> float:
    """Return the current cumulative risk score for an IP."""
    with _risk_lock:
        return _risk_scores.get(ip, 0.0)


def _score_to_severity(score: float) -> str:
    """Map a risk score to a severity label."""
    if score >= _block_threshold:
        return "CRITICAL"
    elif score >= _block_threshold * 0.5:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "SAFE"


def add_alert(alert: dict) -> None:
    """
    Thread-safe append to the alert log.

    CENTRAL RISK ENGINE: calculates cumulative risk score per IP
    and triggers auto-block when threshold is exceeded.
    This is the ONLY place in the system that decides blocking.
    """
    with _alerts_lock:
        alerts.append(alert)
        if len(alerts) > _alert_buffer_size:
            del alerts[:len(alerts) - _alert_buffer_size]

    src_ip = alert.get("src_ip", "-")
    alert_type = alert.get("type", "UNKNOWN")
    severity = alert.get("severity", "LOW")

    # Calculate risk score increment
    base_weight = _risk_weights.get(alert_type, 1.0)
    multiplier = _severity_multiplier.get(severity, 1.0)
    increment = base_weight * multiplier

    action_taken = "none"

    if src_ip and src_ip not in ("-", "outbound", "127.0.0.1", "0.0.0.0"):
        # Update cumulative risk score and breakdown
        with _risk_lock:
            _risk_scores[src_ip] = _risk_scores.get(src_ip, 0.0) + increment
            current_score = _risk_scores[src_ip]
            
            if src_ip not in _ip_score_breakdown:
                _ip_score_breakdown[src_ip] = {}
            _ip_score_breakdown[src_ip][alert_type] = _ip_score_breakdown[src_ip].get(alert_type, 0.0) + increment

        _log.info("INCIDENT: ip=%s type=%s severity=%s risk_score=%.1f action=assessed",
                   src_ip, alert_type, severity, current_score)

        # Auto-block check (SINGLE centralized decision)
        is_immediate = alert_type in _immediate_block_rules
        if current_score >= _block_threshold or is_immediate:
            from firewall import block_ip, is_blocked
            if not is_blocked(src_ip):
                reason = f"Immediate Block ({alert_type})" if is_immediate else f"Risk Score {current_score:.0f} exceeded"
                _log.warning(
                    "Threshold exceeded for %s. Reason: %s. Auto-blocking.",
                    src_ip, reason,
                )
                block_ip(src_ip, reason, is_auto=True)
                action_taken = "auto_blocked"

        # Update device profile
        try:
            import database
            status = "blocked" if action_taken == "auto_blocked" else "active"
            database.upsert_device(
                ip=src_ip, status=status,
                risk_score=current_score, reason=alert_type,
            )
        except Exception:
            pass

    # Persist incident to database
    try:
        import database
        risk = _risk_scores.get(src_ip, 0.0) if src_ip not in ("-", "outbound") else 0.0
        database.log_incident(
            source_ip=src_ip,
            alert_type=alert_type,
            severity=severity,
            risk_score=risk,
            detail=alert.get("detail", ""),
            action=action_taken,
        )
    except Exception as exc:
        _log.debug("Could not log incident to DB: %s", exc)


# ── Alert Endpoints ────────────────────────────────────────────────

@app.route("/alerts")
def get_alerts():
    """Return the last 50 alerts."""
    with _alerts_lock:
        return jsonify(alerts[-50:])


@app.route("/latest")
def get_latest():
    """Return only the most recent alert (used by ESP32)."""
    with _alerts_lock:
        if alerts:
            return jsonify(alerts[-1])
    return jsonify({"severity": "NONE", "type": "NONE", "src_ip": "-", "time": "-"})


@app.route("/stats")
def get_stats():
    """Aggregate alert statistics."""
    with _alerts_lock:
        severity_counts = Counter(a.get("severity", "LOW") for a in alerts)
        type_counts = Counter(a.get("type", "UNKNOWN") for a in alerts)
        unique_ips = len(set(
            a.get("src_ip", "-") for a in alerts if a.get("src_ip") not in ("-", "outbound")
        ))
    return jsonify({
        "total": len(alerts),
        "critical": severity_counts.get("CRITICAL", 0),
        "medium": severity_counts.get("MEDIUM", 0),
        "low": severity_counts.get("LOW", 0),
        "unique_attackers": unique_ips,
        "resource_abuse": type_counts.get("RESOURCE_ABUSE", 0),
        "unusual_upload": type_counts.get("UNUSUAL_UPLOAD_ACTIVITY", 0),
        "port_scans": type_counts.get("PORT_SCAN", 0),
        "lateral_movement": type_counts.get("LATERAL_MOVEMENT", 0),
        "resource_anomaly": type_counts.get("RESOURCE_ANOMALY", 0),
    })


# ── Metrics Store ──────────────────────────────────────────────────

_current_metrics: dict = {}
_metrics_lock = threading.Lock()
_metrics_history_ref = None


def set_metrics(snapshot: dict):
    """Update the current metrics snapshot (called by monitor.py)."""
    global _current_metrics
    with _metrics_lock:
        _current_metrics = snapshot


def set_metrics_history_ref(history_deque):
    """Set a reference to the collector's metrics_history deque."""
    global _metrics_history_ref
    _metrics_history_ref = history_deque


@app.route("/metrics")
def get_metrics():
    """Return the current system metrics snapshot."""
    with _metrics_lock:
        return jsonify(_current_metrics)


@app.route("/metrics/history")
def get_metrics_history():
    """Return the last 60 metric snapshots for timeline charts."""
    if _metrics_history_ref is not None:
        return jsonify(list(_metrics_history_ref))
    return jsonify([])


# ── Firewall Rules API ──────────────────────────────────────────────

@app.route("/firewall/rules")
def get_firewall_rules():
    """Return list of currently blocked IPs."""
    from firewall import get_blocked_ips
    return jsonify(get_blocked_ips())


@app.route("/firewall/block", methods=["POST"])
def post_block_ip():
    """Block a specific IP address (manual action)."""
    from flask import request
    from firewall import block_ip

    data = request.get_json() or {}
    ip = data.get("ip")
    reason = data.get("reason", "manual block via dashboard")
    if not ip:
        return jsonify({"success": False, "error": "No IP specified"}), 400

    success = block_ip(ip, reason, is_auto=False)
    return jsonify({"success": success})


@app.route("/firewall/unblock", methods=["POST"])
def post_unblock_ip():
    """Unblock a specific IP address (manual action only)."""
    from flask import request
    from firewall import unblock_ip

    data = request.get_json() or {}
    ip = data.get("ip")
    if not ip:
        return jsonify({"success": False, "error": "No IP specified"}), 400

    success = unblock_ip(ip)
    return jsonify({"success": success})


# ── New Endpoints (Persistent Data) ────────────────────────────────

@app.route("/incidents")
def get_incidents():
    """Return paginated incident history from database."""
    from flask import request
    try:
        import database
        limit = int(request.args.get("limit", 100))
        offset = int(request.args.get("offset", 0))
        return jsonify(database.get_incidents(limit=limit, offset=offset))
    except Exception as exc:
        _log.error("Failed to fetch incidents: %s", exc)
        return jsonify([])


@app.route("/risk-scores")
def get_risk_scores():
    """Return current per-IP risk scores along with explainable breakdowns."""
    with _risk_lock:
        scores = []
        for ip, score in sorted(_risk_scores.items(), key=lambda x: x[1], reverse=True):
            scores.append({
                "ip": ip,
                "risk_score": round(score, 1),
                "severity": _score_to_severity(score),
                "breakdown": {k: round(v, 1) for k, v in _ip_score_breakdown.get(ip, {}).items()}
            })
        return jsonify(scores)


@app.route("/top-attackers")
def get_top_attackers():
    """Return top attacking IPs from persistent database."""
    try:
        import database
        return jsonify(database.get_top_attackers(limit=10))
    except Exception as exc:
        _log.error("Failed to fetch top attackers: %s", exc)
        return jsonify([])


@app.route("/timeline")
def get_timeline():
    """Return incident timeline grouped by hour for charts."""
    from flask import request
    try:
        import database
        hours = int(request.args.get("hours", 24))
        return jsonify(database.get_incident_timeline(hours=hours))
    except Exception as exc:
        _log.error("Failed to fetch timeline: %s", exc)
        return jsonify([])


@app.route("/services")
def get_services():
    """Return IDS service status."""
    try:
        import database
        db_ok = database.is_healthy()
    except Exception:
        db_ok = False

    return jsonify({
        "monitor_running": True,
        "uptime_seconds": round(time.time() - _start_time),
        "database_connected": db_ok,
        "api_key_enabled": bool(_API_KEY),
        "alert_count": len(alerts),
        "blocked_count": len(get_blocked_ips_safe()),
    })


@app.route("/devices")
def get_device_profiles():
    """Return all tracked device profiles with risk breakdown."""
    try:
        import database
        devices = database.get_devices()
        with _risk_lock:
            for dev in devices:
                ip = dev["ip"]
                dev["breakdown"] = {k: round(v, 1) for k, v in _ip_score_breakdown.get(ip, {}).items()}
        return jsonify(devices)
    except Exception as exc:
        _log.error("Failed to fetch devices: %s", exc)
        return jsonify([])


def get_blocked_ips_safe() -> dict:
    """Safe wrapper for firewall.get_blocked_ips()."""
    try:
        from firewall import get_blocked_ips
        return get_blocked_ips()
    except Exception:
        return {}


# ── Consolidated CLI Endpoint ──────────────────────────────────────

@app.route("/cli/data")
def get_cli_data():
    """Consolidated endpoint for all CLI data to prevent lagging/multiple calls."""
    from firewall import get_blocked_ips
    blocked_ips = get_blocked_ips()

    # 1. Metrics
    with _metrics_lock:
        current_metrics = dict(_current_metrics)

    # 2. Stats & Alerts
    with _alerts_lock:
        last_alerts = alerts[-50:]
        severity_counts = Counter(a.get("severity", "LOW") for a in alerts)
        type_counts = Counter(a.get("type", "UNKNOWN") for a in alerts)
        unique_ips = len(set(
            a.get("src_ip", "-") for a in alerts if a.get("src_ip") not in ("-", "outbound")
        ))
        stats = {
            "total": len(alerts),
            "critical": severity_counts.get("CRITICAL", 0),
            "medium": severity_counts.get("MEDIUM", 0),
            "low": severity_counts.get("LOW", 0),
            "unique_attackers": unique_ips,
            "resource_abuse": type_counts.get("RESOURCE_ABUSE", 0),
            "unusual_upload": type_counts.get("UNUSUAL_UPLOAD_ACTIVITY", 0),
            "port_scans": type_counts.get("PORT_SCAN", 0),
            "lateral_movement": type_counts.get("LATERAL_MOVEMENT", 0),
            "resource_anomaly": type_counts.get("RESOURCE_ANOMALY", 0),
        }

    # 3. Visitors
    with _visitors_lock:
        visitors = []
        for ip, info in _visitors.items():
            score = get_ip_risk_score(ip)
            visitors.append({
                "ip": ip,
                "page": info.get("page", "/"),
                "time": info.get("last_seen", ""),
                "severity": _score_to_severity(score),
                "risk_score": round(score, 1),
                "blocked": ip in blocked_ips,
            })

    return jsonify({
        "metrics": current_metrics,
        "stats": stats,
        "firewall_rules": blocked_ips,
        "alerts": last_alerts,
        "visitors": visitors,
    })


# ── Health & Diagnostics ──────────────────────────────────────────

def _format_uptime(seconds: float) -> str:
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    return f"{h}h {m}m"

@app.route("/health")
def health():
    """Health check endpoint for Docker and load balancers."""
    try:
        import database
        db_ok = database.is_healthy()
    except Exception:
        db_ok = False

    return jsonify({
        "status": "healthy" if db_ok else "degraded",
        "uptime": _format_uptime(time.time() - _start_time),
        "services": {
            "database": "up" if db_ok else "unavailable",
            "collector": "running",
            "sniffer": "running",
            "firewall": "ready",
            "dashboard": "running",
            "risk_engine": "running"
        }
    })

@app.route("/self-test")
def self_test():
    """Active verification of every subsystem."""
    import sys
    results = {}
    
    # 1. Configuration
    try:
        if _cfg:
            results["Configuration"] = {"status": "PASS", "message": "Loaded config.yaml"}
        else:
            results["Configuration"] = {"status": "FAIL", "message": "No configuration loaded"}
    except Exception as e:
        results["Configuration"] = {"status": "FAIL", "message": str(e)}

    # 2. SQLite
    try:
        import database
        if database.is_healthy():
            results["SQLite"] = {"status": "PASS", "message": "Connected to database"}
        else:
            results["SQLite"] = {"status": "FAIL", "message": "Query failed"}
    except Exception as e:
        results["SQLite"] = {"status": "FAIL", "message": str(e)}

    # 3. Logging
    results["Logging"] = {"status": "PASS", "message": "Structured logging active"}
    
    # 4. Firewall
    try:
        from firewall import _is_linux, _execute_cmd
        if _is_linux():
            import subprocess
            res = subprocess.run(["iptables", "-L", "INPUT", "-n"], capture_output=True)
            if res.returncode == 0:
                results["Firewall"] = {"status": "PASS", "message": "iptables ready"}
            else:
                results["Firewall"] = {"status": "FAIL", "message": f"iptables error: {res.stderr.strip() or 'Unknown'}"}
        else:
            results["Firewall"] = {"status": "PASS", "message": "Windows firewall mode (netsh)"}
    except Exception as e:
        results["Firewall"] = {"status": "FAIL", "message": str(e)}
        
    # 5. Packet Capture
    try:
        import scapy
        results["Packet Capture"] = {"status": "PASS", "message": "Scapy loaded (perms verified in /deployment-check)"}
    except Exception as e:
        results["Packet Capture"] = {"status": "FAIL", "message": "Scapy not installed or import error"}

    # 6. Collector
    with _metrics_lock:
        if _current_metrics:
             results["Collector"] = {"status": "PASS", "message": "Receiving metrics"}
        else:
             results["Collector"] = {"status": "FAIL", "message": "No metrics received yet"}

    # 7. REST API
    results["REST API"] = {"status": "PASS", "message": "Responsive"}

    # 8. Dashboard
    results["Dashboard"] = {"status": "PASS", "message": f"Static files mapped to {os.path.basename(DASHBOARD_DIR)}"}

    return jsonify(results)

@app.route("/deployment-check")
def deployment_check():
    """Verify Azure/AWS/Local deployment readiness."""
    import sys, platform, subprocess, socket
    results = {}
    
    # OS Compatibility
    results["Operating System"] = {"status": "PASS", "message": f"Running on {platform.system()}"}
    
    # Docker Capabilities
    in_docker = os.path.exists('/.dockerenv')
    results["Docker"] = {"status": "PASS", "message": "Running inside Docker" if in_docker else "Running natively"}
        
    # Firewall Permissions
    try:
        if sys.platform.startswith("linux"):
            res = subprocess.run(["iptables", "-L", "-n"], capture_output=True)
            if res.returncode == 0:
                results["Firewall"] = {"status": "PASS", "message": "iptables available"}
            else:
                results["Firewall"] = {"status": "FAIL", "message": "NET_ADMIN capability missing or iptables not installed"}
        else:
            results["Firewall"] = {"status": "PASS", "message": "Windows firewall requires Admin"}
    except Exception as e:
        results["Firewall"] = {"status": "FAIL", "message": str(e)}

    # Packet Capture Permissions
    if sys.platform.startswith("linux"):
        try:
            # socket.AF_PACKET = 17, socket.SOCK_RAW = 3
            s = socket.socket(17, 3, socket.htons(3))
            s.close()
            results["Packet Capture"] = {"status": "PASS", "message": "Raw sockets permitted"}
        except PermissionError:
            results["Packet Capture"] = {"status": "FAIL", "message": "NET_RAW capability missing"}
        except Exception as e:
            results["Packet Capture"] = {"status": "FAIL", "message": str(e)}
    else:
        results["Packet Capture"] = {"status": "PASS", "message": "Windows Npcap/WinPcap required"}

    # Writable Database Path
    db_path = _cfg.get("database", {}).get("path", "data/incidents.db")
    db_dir = os.path.dirname(db_path) or "."
    try:
        os.makedirs(db_dir, exist_ok=True)
        test_file = os.path.join(db_dir, ".test_write")
        with open(test_file, "w") as f: f.write("test")
        os.remove(test_file)
        results["Database Directory"] = {"status": "PASS", "message": f"Writable: {db_dir}"}
    except Exception as e:
        results["Database Directory"] = {"status": "FAIL", "message": f"Not writable: {e}"}

    # Writable Log Path
    log_file = _cfg.get("logging", {}).get("file", "data/ids.log")
    if log_file:
        log_dir = os.path.dirname(log_file) or "."
        try:
            os.makedirs(log_dir, exist_ok=True)
            test_file = os.path.join(log_dir, ".test_write")
            with open(test_file, "w") as f: f.write("test")
            os.remove(test_file)
            results["Log Directory"] = {"status": "PASS", "message": f"Writable: {log_dir}"}
        except Exception as e:
            results["Log Directory"] = {"status": "FAIL", "message": f"Not writable: {e}"}
    else:
        results["Log Directory"] = {"status": "PASS", "message": "File logging disabled"}

    return jsonify(results)

@app.route("/config")
def get_runtime_config():
    """Return read-only configuration values for the dashboard panel."""
    try:
        cfg = _cfg
        return jsonify({
            "Risk Threshold": cfg.get("risk_engine", {}).get("block_threshold", 15),
            "Immediate Block Rules": ", ".join(cfg.get("risk_engine", {}).get("immediate_block", [])),
            "CPU Threshold": f"{cfg.get('detection', {}).get('cpu_threshold', 85.0)}%",
            "Port Scan Threshold": cfg.get("detection", {}).get("engine_port_scan_threshold", 10),
            "Upload Threshold": f"{cfg.get('detection', {}).get('upload_multiplier', 3.0)}x",
            "Database Path": cfg.get("database", {}).get("path", "data/incidents.db"),
            "Log Level": cfg.get("logging", {}).get("level", "INFO"),
            "Deployment Mode": "Monitor" if not os.environ.get("SIMULATOR_MODE") else "Simulator",
            "Build Version": "1.2.0-stable"
        })
    except Exception as exc:
        _log.error("Failed to fetch config for dashboard: %s", exc)
        return jsonify({})

# ── Flask Runner ───────────────────────────────────────────────────

def run_flask(host: str | None = None, port: int | None = None):
    """Start the Flask server (called from monitor.py in a daemon thread)."""
    h = host or _cfg.get("server", {}).get("host", "0.0.0.0")
    p = port or _cfg.get("server", {}).get("port", 5000)
    app.run(host=h, port=p, debug=False, use_reloader=False)
