"""
Infrastructure Security Monitor -- Attack Simulator
-----------------------------------------------------
Simulates system metric snapshots (CPU, Memory, Network, Processes, Connections)
and feeds them to the actual AnomalyEngine. This validates the Z-score and
rule-based detection logic, exposing them via the Flask API and the HTML
dashboard without needing actual raw sockets or system stress.

Usage:
    python backend/simulator.py
"""

import signal
import sys
import threading
import time
import random
import logging

from app import add_alert, set_metrics, set_metrics_history_ref, run_flask, setup_logging, init_database
from collector import metrics_history
from anomaly import AnomalyEngine

_log = logging.getLogger(__name__)
_shutdown = threading.Event()

# ── Mock Data Templates ───────────────────────────────────────────

NORMAL_PROCESSES = [
    {"pid": 4120, "name": "chrome.exe", "cpu": 2.4, "memory_mb": 412.5, "connections": 12},
    {"pid": 8940, "name": "slack.exe", "cpu": 0.8, "memory_mb": 284.1, "connections": 6},
    {"pid": 1124, "name": "code.exe", "cpu": 1.5, "memory_mb": 512.9, "connections": 3},
    {"pid": 6012, "name": "python.exe", "cpu": 0.5, "memory_mb": 84.2, "connections": 2},
    {"pid": 884, "name": "explorer.exe", "cpu": 0.2, "memory_mb": 118.0, "connections": 0},
    {"pid": 4, "name": "System", "cpu": 0.1, "memory_mb": 24.0, "connections": 15},
]

NORMAL_CONNECTIONS = [
    {"pid": 4120, "process": "chrome.exe", "local_port": 50123, "remote_ip": "172.217.16.142", "remote_port": 443, "status": "ESTABLISHED"},
    {"pid": 4120, "process": "chrome.exe", "local_port": 50124, "remote_ip": "142.250.190.46", "remote_port": 443, "status": "ESTABLISHED"},
    {"pid": 8940, "process": "slack.exe", "local_port": 51332, "remote_ip": "52.84.120.33", "remote_port": 443, "status": "ESTABLISHED"},
    {"pid": 6012, "process": "python.exe", "local_port": 5000, "remote_ip": "0.0.0.0", "remote_port": 0, "status": "LISTEN"},
]

# ── Simulation State ──────────────────────────────────────────────

current_scenario = "NORMAL"
scenario_time_left = 0

scenario_data = {
    "cpu_base": 15.0,
    "mem_base": 42.0,
    "net_sent_base": 25 * 1024,
    "net_recv_base": 180 * 1024,
    "extra_processes": [],
    "extra_connections": [],
}


def set_scenario(name: str, duration: int):
    """Transition to a new simulation scenario."""
    global current_scenario, scenario_time_left, scenario_data
    current_scenario = name
    scenario_time_left = duration

    scenario_data = {
        "cpu_base": 15.0,
        "mem_base": 42.0,
        "net_sent_base": 25 * 1024,
        "net_recv_base": 180 * 1024,
        "extra_processes": [],
        "extra_connections": [],
    }

    if name == "RESOURCE_ABUSE":
        scenario_data["cpu_base"] = 96.5
        scenario_data["extra_processes"] = [
            {"pid": 9821, "name": "xmrig.exe", "cpu": 88.4, "memory_mb": 142.0, "connections": 2}
        ]
        scenario_data["extra_connections"] = [
            {"pid": 9821, "process": "xmrig.exe", "local_port": 53211, "remote_ip": "162.213.199.25", "remote_port": 3333, "status": "ESTABLISHED"}
        ]
    elif name == "UNUSUAL_UPLOAD_ACTIVITY":
        scenario_data["net_sent_base"] = 8.5 * 1024 * 1024
        scenario_data["extra_processes"] = [
            {"pid": 7412, "name": "scp.exe", "cpu": 12.3, "memory_mb": 48.5, "connections": 1}
        ]
        scenario_data["extra_connections"] = [
            {"pid": 7412, "process": "scp.exe", "local_port": 49201, "remote_ip": "45.79.112.203", "remote_port": 22, "status": "ESTABLISHED"}
        ]
    elif name == "PORT_SCAN":
        scan_ip = "192.168.1.105"
        ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3389, 8080]
        for i, port in enumerate(ports):
            scenario_data["extra_connections"].append({
                "pid": 0, "process": "-", "local_port": port,
                "remote_ip": scan_ip, "remote_port": 61000 + i, "status": "SYN_RECV"
            })
    elif name == "LATERAL_MOVEMENT":
        target_ip = "10.0.0.42"
        scenario_data["extra_processes"] = [
            {"pid": 11200, "name": "powershell.exe", "cpu": 4.2, "memory_mb": 85.0, "connections": 1}
        ]
        scenario_data["extra_connections"] = [
            {"pid": 11200, "process": "powershell.exe", "local_port": 49832, "remote_ip": target_ip, "remote_port": 5985, "status": "ESTABLISHED"}
        ]


def generate_mock_snapshot() -> dict:
    """Generate realistic metrics snapshot based on current scenario."""
    global scenario_time_left, current_scenario

    if scenario_time_left <= 0 and current_scenario != "NORMAL":
        _log.info("Scenario %s finished. Returning to NORMAL.", current_scenario)
        set_scenario("NORMAL", 0)

    cpu_noise = random.uniform(-2.5, 2.5)
    mem_noise = random.uniform(-0.5, 0.5)
    net_noise = random.uniform(0.8, 1.2)

    cpu = max(1.0, min(100.0, scenario_data["cpu_base"] + cpu_noise))
    mem = max(5.0, min(100.0, scenario_data["mem_base"] + mem_noise))
    net_sent = scenario_data["net_sent_base"] * net_noise
    net_recv = scenario_data["net_recv_base"] * net_noise

    procs = [dict(p) for p in NORMAL_PROCESSES]
    if scenario_data["extra_processes"]:
        procs.extend(scenario_data["extra_processes"])

    total_proc_cpu = sum(p["cpu"] for p in procs)
    diff = cpu - total_proc_cpu
    if diff > 0 and procs:
        procs[0]["cpu"] = round(procs[0]["cpu"] + diff, 1)

    conns = list(NORMAL_CONNECTIONS)
    if scenario_data["extra_connections"]:
        conns.extend(scenario_data["extra_connections"])

    unique_ips = len(set(c["remote_ip"] for c in conns if c["remote_ip"] != "0.0.0.0"))

    if scenario_time_left > 0:
        scenario_time_left -= 2

    return {
        'cpu_percent': round(cpu, 1),
        'memory_percent': round(mem, 1),
        'memory_used_mb': round(8192 * (mem / 100)),
        'memory_total_mb': 8192,
        'disk_usage_percent': 48.2,
        'net_bytes_sent_rate': round(net_sent),
        'net_bytes_recv_rate': round(net_recv),
        'active_connections': len(conns),
        'unique_remote_ips': unique_ips,
        'top_processes': sorted(procs, key=lambda x: x["cpu"], reverse=True),
        'connections': conns,
        'time': time.strftime('%H:%M:%S'),
    }


def _handle_signal(signum, frame):
    _log.info("Received signal %s — shutting down...", signum)
    _shutdown.set()


def scenario_scheduler_loop():
    """Periodically triggers threat scenarios to test the dashboard."""
    time.sleep(10)
    scenarios = ["RESOURCE_ABUSE", "UNUSUAL_UPLOAD_ACTIVITY", "PORT_SCAN", "LATERAL_MOVEMENT"]

    while not _shutdown.is_set():
        next_scenario = random.choice(scenarios)
        duration = random.randint(12, 24)
        _log.info("Triggering scenario: %s for %ds", next_scenario, duration)
        set_scenario(next_scenario, duration)
        _shutdown.wait(timeout=duration + random.randint(15, 30))


def main():
    setup_logging()
    init_database()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

    set_metrics_history_ref(metrics_history)
    engine = AnomalyEngine()

    scheduler_thread = threading.Thread(target=scenario_scheduler_loop, daemon=True)
    scheduler_thread.start()

    _log.info("=" * 60)
    _log.info("  Infrastructure Security Monitor -- Simulator Mode")
    _log.info("  Flask API + Dashboard running at http://localhost:5000")
    _log.info("  Statistical anomaly engine active")
    _log.info("  Generating system metrics + periodic attacks")
    _log.info("=" * 60)

    while not _shutdown.is_set():
        try:
            snapshot = generate_mock_snapshot()
            set_metrics(snapshot)

            metrics_history.append({
                'time': snapshot['time'],
                'cpu_percent': snapshot['cpu_percent'],
                'memory_percent': snapshot['memory_percent'],
                'net_sent_rate': snapshot['net_bytes_sent_rate'],
                'net_recv_rate': snapshot['net_bytes_recv_rate'],
                'connections': snapshot['active_connections'],
            })

            new_alerts = engine.analyze(snapshot)

            # Central risk engine in add_alert() handles all blocking
            for alert in new_alerts:
                add_alert(alert)
                _log.info(
                    "[%s] %s — Process: %s — %s",
                    alert['severity'], alert['type'],
                    alert.get('process', '-'), alert.get('detail', ''),
                )

            _log.debug(
                "[%s] CPU: %.1f%% | MEM: %.1f%% | CONN: %d | Alerts: %d",
                current_scenario, snapshot['cpu_percent'],
                snapshot['memory_percent'], snapshot['active_connections'],
                len(new_alerts),
            )

        except Exception as exc:
            _log.error("Simulator loop error: %s", exc, exc_info=True)

        _shutdown.wait(timeout=2)

    _log.info("Simulator stopped.")


if __name__ == "__main__":
    main()
