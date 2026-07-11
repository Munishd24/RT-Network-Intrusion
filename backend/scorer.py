"""
Threat Severity Scoring Engine
-------------------------------
Tracks port scan frequency and ARP anomalies per source IP,
then assigns severity levels: CRITICAL / MEDIUM / LOW / NONE.

Scoring Logic — Port Scans (within a configurable sliding window):
  Counts UNIQUE destination ports per source IP.
  Repeated connections to the same port do NOT increase the count.
    > critical threshold unique ports  → CRITICAL
    > medium threshold unique ports    → MEDIUM
    > low threshold unique ports       → LOW

ARP Spoofing:
  Multiple MACs claiming the same IP → CRITICAL
"""

from collections import defaultdict
import logging
import time

_log = logging.getLogger(__name__)


# ── Configuration (loaded once at first use) ──────────────────────

_config_loaded = False
_window_seconds: float = 5.0
_thresholds: dict = {"critical": 50, "medium": 20, "low": 5}


def _ensure_config() -> None:
    """Load thresholds from config.yaml on first call."""
    global _config_loaded, _window_seconds, _thresholds
    if _config_loaded:
        return
    try:
        from config import get_config
        cfg = get_config().get("detection", {})
        _window_seconds = float(cfg.get("port_scan_window_seconds", 5))
        ps = cfg.get("port_scan_unique_ports", {})
        _thresholds = {
            "critical": int(ps.get("critical", 50)),
            "medium": int(ps.get("medium", 20)),
            "low": int(ps.get("low", 5)),
        }
    except Exception as exc:
        _log.warning("scorer: could not load config, using defaults: %s", exc)
    _config_loaded = True


# ── Port Scan Tracking ─────────────────────────────────────────────
# Maps src_ip → list of (timestamp, dst_port) tuples
port_scan_tracker: dict[str, list[tuple[float, int]]] = defaultdict(list)

# ── ARP Spoof Tracking ─────────────────────────────────────────────
# Maps src_ip → set of MACs that have claimed that IP
arp_tracker: dict[str, set[str]] = defaultdict(set)


def score_port_scan(src_ip: str, dst_port: int) -> tuple[str | None, int]:
    """
    Record a SYN probe from `src_ip` to `dst_port` and return
    (severity, unique_port_count_in_window).

    Counts UNIQUE destination ports within the sliding window,
    not total SYN packets.  Repeated probes to the same port
    are stored but only counted once toward the threshold.

    Returns (None, count) when the activity is below threshold.
    """
    _ensure_config()
    now = time.time()
    port_scan_tracker[src_ip].append((now, dst_port))

    # Prune entries older than the sliding window
    port_scan_tracker[src_ip] = [
        (t, p) for t, p in port_scan_tracker[src_ip]
        if now - t < _window_seconds
    ]

    # Count UNIQUE ports (not total entries)
    unique_ports = len(set(p for _, p in port_scan_tracker[src_ip]))

    if unique_ports > _thresholds["critical"]:
        return "CRITICAL", unique_ports
    elif unique_ports > _thresholds["medium"]:
        return "MEDIUM", unique_ports
    elif unique_ports > _thresholds["low"]:
        return "LOW", unique_ports
    return None, unique_ports


def score_arp_spoof(src_mac: str, src_ip: str) -> str | None:
    """
    Track MAC → IP bindings.  If more than one MAC claims the same
    IP address, that's a strong indicator of ARP cache poisoning.
    """
    arp_tracker[src_ip].add(src_mac)

    if len(arp_tracker[src_ip]) > 1:
        return "CRITICAL"
    return None
