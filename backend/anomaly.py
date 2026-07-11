"""
Anomaly Detection Engine
-------------------------
Two detection layers:

Layer 1 — Rule-Based Detection:
  Threshold rules for known threat patterns:
    - Resource Abuse (high CPU, mining ports)
    - Unusual Upload Activity (outbound traffic spikes)
    - Port Scan (many ports from one IP)
    - Lateral Movement (new internal connections on admin ports)

Layer 2 — Statistical Anomaly Detection:
  Rolling Z-score analysis on system metrics.
  Z-score > 3.0 = statistically anomalous.

All detectors work on metric snapshots produced by collector.py.
All thresholds are loaded from config.yaml.
"""

import time
import ipaddress
import logging
import numpy as np
from collections import defaultdict, deque

_log = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════
#  CONFIGURATION HELPERS
# ══════════════════════════════════════════════════════════════════

_cfg_cache: dict | None = None


def _get_detection_cfg() -> dict:
    """Return the detection section of config, loaded once."""
    global _cfg_cache
    if _cfg_cache is not None:
        return _cfg_cache
    try:
        from config import get_config
        _cfg_cache = get_config().get("detection", {})
    except Exception as exc:
        _log.warning("anomaly: could not load config, using defaults: %s", exc)
        _cfg_cache = {}
    return _cfg_cache


# ══════════════════════════════════════════════════════════════════
#  Z-SCORE ANOMALY DETECTOR
# ══════════════════════════════════════════════════════════════════

class ZScoreDetector:
    """
    Rolling window Z-score anomaly detector.

    Maintains a history of metric values and flags new values
    whose Z-score exceeds the threshold (default 3.0).
    A Z-score of 3.0 means the value is 3 standard deviations
    from the mean — expected in only ~0.3% of normal readings.
    """

    def __init__(self, window_size: int = 60, threshold: float = 3.0):
        self.window_size = window_size
        self.threshold = threshold
        self.history: deque = deque(maxlen=window_size)

    def update(self, value: float) -> dict:
        """
        Add a new value and return analysis result.
        Returns dict with z_score, is_anomaly, mean, std.
        """
        if len(self.history) < 10:
            # Need minimum samples for meaningful stats
            self.history.append(value)
            return {
                'z_score': 0.0,
                'is_anomaly': False,
                'mean': 0.0,
                'std': 0.0,
            }

        data = np.array(self.history)
        mean = float(np.mean(data))
        std = float(np.std(data))

        z_score = abs(value - mean) / std if std > 0 else 0.0
        is_anomaly = z_score > self.threshold

        self.history.append(value)
        return {
            'z_score': round(z_score, 2),
            'is_anomaly': is_anomaly,
            'mean': round(mean, 2),
            'std': round(std, 2),
        }


# ══════════════════════════════════════════════════════════════════
#  RULE-BASED THREAT DETECTORS
# ══════════════════════════════════════════════════════════════════

# ── Resource Abuse Detector ────────────────────────────────────────
# (Previously "CryptoMiningDetector" — renamed to behavioural label)

# Known crypto mining pool ports (used as a signal, not proof)
MINING_PORTS = {3333, 4444, 5555, 8333, 14433, 14444, 45560}

class ResourceAbuseDetector:
    """
    Detects resource abuse by monitoring:
      1. Sustained high CPU (>threshold for N+ seconds)
      2. Connections to known mining pool ports
    Reports behavioural observation, NOT a definitive malware label.
    """

    def __init__(self) -> None:
        cfg = _get_detection_cfg()
        self.cpu_threshold: float = float(cfg.get("cpu_threshold", 85.0))
        self.sustained_seconds: float = float(cfg.get("cpu_sustained_seconds", 30.0))
        self.high_cpu_since: float | None = None

    def check(self, metrics: dict) -> dict | None:
        """Returns an alert dict if resource abuse is suspected, else None."""
        cpu = metrics.get('cpu_percent', 0)
        now = time.time()

        # Track sustained high CPU
        if cpu > self.cpu_threshold:
            if self.high_cpu_since is None:
                self.high_cpu_since = now
            sustained = now - self.high_cpu_since
        else:
            self.high_cpu_since = None
            sustained = 0

        # Check for mining port connections
        mining_conns = []
        for conn in metrics.get('connections', []):
            if conn.get('remote_port') in MINING_PORTS:
                mining_conns.append(conn)

        # Alert conditions
        if sustained >= self.sustained_seconds:
            # Find the top CPU process
            top_proc = '-'
            top_cpu = 0
            for p in metrics.get('top_processes', []):
                if p['cpu'] > top_cpu:
                    top_cpu = p['cpu']
                    top_proc = p['name']

            detail = f"CPU {cpu}% for {int(sustained)}s"
            if mining_conns:
                detail += f" + {len(mining_conns)} mining pool connections"

            return {
                'type': 'RESOURCE_ABUSE',
                'severity': 'CRITICAL',
                'src_ip': '-',
                'process': top_proc,
                'detail': detail,
                'time': time.strftime('%H:%M:%S'),
            }

        if mining_conns:
            return {
                'type': 'RESOURCE_ABUSE',
                'severity': 'MEDIUM',
                'src_ip': mining_conns[0].get('remote_ip', '-'),
                'process': mining_conns[0].get('process', '-'),
                'detail': f"Connection to mining port {mining_conns[0].get('remote_port')}",
                'time': time.strftime('%H:%M:%S'),
            }

        return None


# ── Unusual Upload Activity Detector ───────────────────────────────
# (Previously "DataExfiltrationDetector" — renamed to behavioural label)

class UnusualUploadDetector:
    """
    Detects unusual upload activity by monitoring outbound traffic rate.
    Alerts when outbound rate exceeds a multiplier of the baseline.
    Reports a behavioural observation, NOT a definitive exfiltration label.
    """

    def __init__(self) -> None:
        cfg = _get_detection_cfg()
        self.multiplier: float = float(cfg.get("upload_multiplier", 3.0))
        baseline_samples: int = int(cfg.get("upload_baseline_samples", 15))
        self.min_samples = baseline_samples
        self.history: deque = deque(maxlen=60)

    def check(self, metrics: dict) -> dict | None:
        sent_rate = metrics.get('net_bytes_sent_rate', 0)

        if len(self.history) < self.min_samples:
            self.history.append(sent_rate)
            return None

        baseline = float(np.mean(self.history))
        self.history.append(sent_rate)

        if baseline > 0 and sent_rate > baseline * self.multiplier:
            ratio = sent_rate / baseline
            return {
                'type': 'UNUSUAL_UPLOAD_ACTIVITY',
                'severity': 'CRITICAL' if ratio > 5 else 'MEDIUM',
                'src_ip': 'outbound',
                'process': '-',
                'detail': f"Outbound {ratio:.1f}x baseline ({_format_bytes(sent_rate)}/s vs {_format_bytes(baseline)}/s avg)",
                'time': time.strftime('%H:%M:%S'),
            }

        return None


# ── Port Scan Detector ─────────────────────────────────────────────

class PortScanDetector:
    """
    Detects inbound port scanning by tracking connection patterns.
    Multiple connections from one IP to different local ports
    within a time window = port scan.
    Counts UNIQUE ports, not total connections.
    """

    def __init__(self) -> None:
        cfg = _get_detection_cfg()
        self.window_seconds: float = float(cfg.get("engine_port_scan_window", 5.0))
        self.threshold: int = int(cfg.get("engine_port_scan_threshold", 10))
        # ip -> list of (timestamp, local_port)
        self.tracker: dict[str, list] = defaultdict(list)

    def check(self, metrics: dict) -> dict | None:
        now = time.time()

        # Build set of current remote IPs and their target ports
        for conn in metrics.get('connections', []):
            remote_ip = conn.get('remote_ip', '')
            local_port = conn.get('local_port', 0)
            if remote_ip and _is_private_ip(remote_ip):
                self.tracker[remote_ip].append((now, local_port))

        # Prune old entries and check thresholds
        for ip in list(self.tracker.keys()):
            self.tracker[ip] = [
                (t, p) for t, p in self.tracker[ip]
                if now - t < self.window_seconds
            ]
            unique_ports = len(set(p for _, p in self.tracker[ip]))

            if unique_ports >= self.threshold:
                severity = 'CRITICAL' if unique_ports > 30 else 'MEDIUM'
                return {
                    'type': 'PORT_SCAN',
                    'severity': severity,
                    'src_ip': ip,
                    'process': '-',
                    'detail': f"{unique_ports} unique ports/{self.window_seconds:.0f}s",
                    'time': time.strftime('%H:%M:%S'),
                }

        return None


# ── Lateral Movement Detector ──────────────────────────────────────

LATERAL_PORTS = {22, 135, 139, 445, 3389, 5985, 5986}

class LateralMovementDetector:
    """
    Detects lateral movement by watching for new connections
    to internal IPs on suspicious ports (SMB, RDP, SSH, WinRM).
    """

    def __init__(self):
        self.known_internal_targets: set[str] = set()

    def check(self, metrics: dict) -> dict | None:
        for conn in metrics.get('connections', []):
            remote_ip = conn.get('remote_ip', '')
            remote_port = conn.get('remote_port', 0)

            if (
                remote_ip
                and _is_private_ip(remote_ip)
                and remote_port in LATERAL_PORTS
                and remote_ip not in self.known_internal_targets
            ):
                self.known_internal_targets.add(remote_ip)
                port_name = _port_to_service(remote_port)
                return {
                    'type': 'LATERAL_MOVEMENT',
                    'severity': 'MEDIUM',
                    'src_ip': remote_ip,
                    'process': conn.get('process', '-'),
                    'detail': f"{port_name} to new internal IP {remote_ip}",
                    'time': time.strftime('%H:%M:%S'),
                }

        return None


# ══════════════════════════════════════════════════════════════════
#  COMBINED ANOMALY ENGINE
# ══════════════════════════════════════════════════════════════════

class AnomalyEngine:
    """
    Runs all detectors on each metrics snapshot.
    Returns a list of new alerts (may be empty).
    """

    def __init__(self):
        cfg = _get_detection_cfg()

        # Rule-based detectors
        self.resource_abuse = ResourceAbuseDetector()
        self.unusual_upload = UnusualUploadDetector()
        self.portscan = PortScanDetector()
        self.lateral = LateralMovementDetector()

        # Z-score detectors for each metric
        zw = int(cfg.get("zscore_window", 60))
        zt = float(cfg.get("zscore_threshold", 3.0))
        self.z_cpu = ZScoreDetector(window_size=zw, threshold=zt)
        self.z_memory = ZScoreDetector(window_size=zw, threshold=zt)
        self.z_net_sent = ZScoreDetector(window_size=zw, threshold=zt)
        self.z_connections = ZScoreDetector(window_size=zw, threshold=zt)

        # Cooldown: prevent alert spam (type -> last_alert_time)
        self._cooldowns: dict[str, float] = {}
        self.cooldown_seconds: float = float(cfg.get("cooldown_seconds", 10.0))

    def analyze(self, metrics: dict) -> list[dict]:
        """Run all detectors and return new alerts."""
        alerts = []

        # ── Rule-based checks ──────────────────────────────────
        for detector in [self.resource_abuse, self.unusual_upload, self.portscan, self.lateral]:
            alert = detector.check(metrics)
            if alert and self._check_cooldown(alert['type']):
                alerts.append(alert)

        # ── Z-score statistical checks ─────────────────────────
        z_checks = [
            ('cpu_percent', self.z_cpu, 'CPU'),
            ('memory_percent', self.z_memory, 'Memory'),
            ('net_bytes_sent_rate', self.z_net_sent, 'Network Out'),
            ('active_connections', self.z_connections, 'Connections'),
        ]

        for metric_key, detector, label in z_checks:
            value = metrics.get(metric_key, 0)
            result = detector.update(float(value))

            if result['is_anomaly'] and self._check_cooldown(f'z_{metric_key}'):
                alerts.append({
                    'type': 'RESOURCE_ANOMALY',
                    'severity': 'LOW' if result['z_score'] < 4 else 'MEDIUM',
                    'src_ip': '-',
                    'process': '-',
                    'detail': f"{label} Z-score {result['z_score']} (value={value}, mean={result['mean']})",
                    'time': time.strftime('%H:%M:%S'),
                })

        return alerts

    def _check_cooldown(self, alert_type: str) -> bool:
        """Return True if enough time has passed since the last alert of this type."""
        now = time.time()
        last = self._cooldowns.get(alert_type, 0)
        if now - last >= self.cooldown_seconds:
            self._cooldowns[alert_type] = now
            return True
        return False


# ══════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════

def _is_private_ip(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def _format_bytes(b: float) -> str:
    if b >= 1024 * 1024:
        return f"{b / (1024*1024):.1f} MB"
    if b >= 1024:
        return f"{b / 1024:.1f} KB"
    return f"{b:.0f} B"


def _port_to_service(port: int) -> str:
    services = {
        22: 'SSH', 135: 'RPC', 139: 'NetBIOS',
        445: 'SMB', 3389: 'RDP', 5985: 'WinRM', 5986: 'WinRM-S',
    }
    return services.get(port, f'port-{port}')
