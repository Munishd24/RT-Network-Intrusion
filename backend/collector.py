"""
System Metrics Collector
------------------------
Collects real-time system metrics using psutil:
  - CPU usage (system-wide + per-process)
  - Memory usage
  - Disk usage
  - Network I/O rates (bytes sent/received per second)
  - Active network connections (netstat-like)
  - Top processes by resource usage

All functions work without admin privileges on Windows.
"""

import psutil
import time
import threading
from collections import deque

# ── State ──────────────────────────────────────────────────────────
_prev_net_io = None
_prev_net_time = None
_lock = threading.Lock()


def get_network_rates():
    """
    Calculate network bytes sent/received per second
    by comparing two snapshots.
    """
    global _prev_net_io, _prev_net_time

    net_io = psutil.net_io_counters()
    now = time.time()

    with _lock:
        if _prev_net_io is None:
            _prev_net_io = net_io
            _prev_net_time = now
            return 0.0, 0.0

        elapsed = now - _prev_net_time
        if elapsed <= 0:
            return 0.0, 0.0

        sent_rate = (net_io.bytes_sent - _prev_net_io.bytes_sent) / elapsed
        recv_rate = (net_io.bytes_recv - _prev_net_io.bytes_recv) / elapsed

        _prev_net_io = net_io
        _prev_net_time = now

    return sent_rate, recv_rate


def get_top_processes(limit: int = 10) -> list[dict]:
    """
    Return top processes sorted by CPU usage.
    Includes per-process connection count.
    """
    procs = []

    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
        try:
            info = proc.info
            cpu = info.get('cpu_percent', 0.0) or 0.0
            mem_info = info.get('memory_info')
            mem_mb = mem_info.rss / (1024 * 1024) if mem_info else 0.0

            # Count connections for this process
            try:
                conn_count = len(proc.net_connections(kind='inet'))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                conn_count = 0

            procs.append({
                'pid': info['pid'],
                'name': info['name'] or 'unknown',
                'cpu': round(cpu, 1),
                'memory_mb': round(mem_mb, 1),
                'connections': conn_count,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Sort by CPU descending, take top N
    procs.sort(key=lambda p: p['cpu'], reverse=True)
    return procs[:limit]


def get_active_connections(limit: int = 30) -> list[dict]:
    """
    Return active network connections (like netstat).
    Works without admin on Windows for the current user's connections.
    """
    connections = []

    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr:  # only connections with a remote address
                # Try to get process name
                proc_name = '-'
                if conn.pid:
                    try:
                        proc_name = psutil.Process(conn.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        proc_name = f'pid:{conn.pid}'

                connections.append({
                    'pid': conn.pid or 0,
                    'process': proc_name,
                    'local_port': conn.laddr.port if conn.laddr else 0,
                    'remote_ip': conn.raddr.ip,
                    'remote_port': conn.raddr.port,
                    'status': conn.status,
                })
    except psutil.AccessDenied:
        # On Windows without admin, we get limited results
        pass

    return connections[:limit]


def collect_metrics() -> dict:
    """
    Collect a full snapshot of system metrics.
    Returns a dict ready to be serialized as JSON.
    """
    # CPU (non-blocking — uses value from previous interval)
    cpu_percent = psutil.cpu_percent(interval=None)

    # Memory
    mem = psutil.virtual_memory()

    # Disk
    try:
        disk = psutil.disk_usage('/')
    except OSError:
        disk = psutil.disk_usage('C:\\')

    # Network rates
    sent_rate, recv_rate = get_network_rates()

    # Connections
    connections = get_active_connections()
    unique_ips = len(set(c['remote_ip'] for c in connections))

    # Top processes
    top_procs = get_top_processes(limit=10)

    return {
        'cpu_percent': round(cpu_percent, 1),
        'memory_percent': round(mem.percent, 1),
        'memory_used_mb': round(mem.used / (1024 * 1024)),
        'memory_total_mb': round(mem.total / (1024 * 1024)),
        'disk_usage_percent': round(disk.percent, 1),
        'net_bytes_sent_rate': round(sent_rate),
        'net_bytes_recv_rate': round(recv_rate),
        'active_connections': len(connections),
        'unique_remote_ips': unique_ips,
        'top_processes': top_procs,
        'connections': connections,
        'time': time.strftime('%H:%M:%S'),
    }


# ── Metrics History Ring Buffer ────────────────────────────────────
metrics_history: deque = deque(maxlen=60)


def collect_and_store() -> dict:
    """Collect metrics and append a summary to history."""
    snapshot = collect_metrics()

    # Store a lightweight summary for the timeline chart
    metrics_history.append({
        'time': snapshot['time'],
        'cpu_percent': snapshot['cpu_percent'],
        'memory_percent': snapshot['memory_percent'],
        'net_sent_rate': snapshot['net_bytes_sent_rate'],
        'net_recv_rate': snapshot['net_bytes_recv_rate'],
        'connections': snapshot['active_connections'],
    })

    return snapshot


def get_metrics_history() -> list[dict]:
    """Return the last 60 metric snapshots."""
    return list(metrics_history)
