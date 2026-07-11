"""
Infrastructure Security Monitor -- Main Entry Point
-----------------------------------------------------
Collects system metrics every 2 seconds, runs anomaly
detection, and pushes alerts to the Flask API.

This is the REAL monitor that uses live system data.
For testing without live data, use simulator.py instead.

Usage:
    python backend/monitor.py
"""

import signal
import sys
import threading
import time
import logging

import psutil

from collector import collect_and_store, metrics_history
from anomaly import AnomalyEngine
from app import add_alert, set_metrics, set_metrics_history_ref, run_flask, setup_logging, init_database

_log = logging.getLogger(__name__)
_shutdown = threading.Event()


def _handle_signal(signum, frame):
    """Handle SIGINT / SIGTERM for graceful shutdown."""
    _log.info("Received signal %s — shutting down gracefully...", signum)
    _shutdown.set()


def _run_self_diagnostics():
    """Perform a system self-test on startup."""
    _log.info("--- Running Startup Self-Diagnostics ---")
    
    # Config
    try:
        from config import get_config
        if get_config(): _log.info(" [PASS] Configuration")
        else: _log.error(" [FAIL] Configuration (no config returned)")
    except Exception as e: _log.error(" [FAIL] Configuration: %s", e)
        
    # SQLite
    try:
        import database
        if database.is_healthy(): _log.info(" [PASS] SQLite")
        else: _log.error(" [FAIL] SQLite (unhealthy)")
    except Exception as e: _log.error(" [FAIL] SQLite: %s", e)
        
    # Firewall
    try:
        from firewall import _is_linux
        if _is_linux():
            import subprocess
            res = subprocess.run(["iptables", "-L", "-n"], capture_output=True)
            if res.returncode == 0: _log.info(" [PASS] Firewall (iptables)")
            else: _log.error(" [FAIL] Firewall (iptables error/perms)")
        else:
            _log.info(" [PASS] Firewall (Windows)")
    except Exception as e: _log.error(" [FAIL] Firewall: %s", e)
    
    # Scapy
    try:
        import scapy
        _log.info(" [PASS] Packet Capture (Scapy imported)")
    except Exception as e: _log.error(" [FAIL] Packet Capture: %s", e)
    
    _log.info("--- Diagnostics complete ---")


def main():
    # ── Logging & Database ─────────────────────────────────────
    setup_logging()
    init_database()
    _run_self_diagnostics()

    # ── Signal Handlers ────────────────────────────────────────
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    # Initialize CPU measurement (first call always returns 0)
    psutil.cpu_percent(interval=None)

    # Start Flask API in background
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

    # Give Flask a moment to start
    time.sleep(0.5)

    # Link the metrics history buffer to Flask
    set_metrics_history_ref(metrics_history)

    # Initialize the anomaly engine
    engine = AnomalyEngine()

    _log.info("=" * 58)
    _log.info("  Infrastructure Security Monitor Active")
    _log.info("  Flask API + Dashboard on http://localhost:5000")
    _log.info("  Anomaly detection engine running")
    _log.info("  Collecting CPU / Memory / Network / Processes")
    _log.info("=" * 58)

    while not _shutdown.is_set():
        try:
            # Collect system metrics
            snapshot = collect_and_store()
            set_metrics(snapshot)

            # Run anomaly detection
            new_alerts = engine.analyze(snapshot)

            for alert in new_alerts:
                # Central risk engine in add_alert() handles blocking
                add_alert(alert)
                _log.info(
                    "[%s] %s — %s",
                    alert['severity'], alert['type'], alert.get('detail', ''),
                )

            # Brief status line
            cpu = snapshot['cpu_percent']
            mem = snapshot['memory_percent']
            conns = snapshot['active_connections']
            _log.debug(
                "CPU: %.1f%% | MEM: %.1f%% | CONN: %d | Alerts: %d",
                cpu, mem, conns, len(new_alerts),
            )

        except Exception as exc:
            _log.error("Monitor loop error: %s", exc, exc_info=True)

        _shutdown.wait(timeout=2)

    _log.info("Monitor stopped.")


if __name__ == "__main__":
    main()
