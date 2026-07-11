"""
Firewall Manager -- Intrusion Prevention System (IPS)
------------------------------------------------------
Supports dynamic IP blocking and unblocking on:
  - Windows: netsh advfirewall
  - Linux: iptables

Improvements over original:
  - Whitelist loaded from config.yaml
  - Cooldown: prevents re-blocking the same IP too quickly
  - Persistent audit log via SQLite
  - Maximum blocked entries limit
  - No automatic unblock (admin must manually unblock)
  - Duplicate rule prevention (already-blocked check)
  - SSH connection whitelisting preserved
"""

import os
import sys
import subprocess
import threading
import time
import logging

_log = logging.getLogger(__name__)

# ── State ──────────────────────────────────────────────────────────

_lock = threading.Lock()

# Dictionary of active blocks: {ip: {"reason": str, "time": str, "is_auto": bool}}
_active_blocks: dict[str, dict] = {}

# Cooldown tracker: {ip: last_block_timestamp}
_last_block_time: dict[str, float] = {}

# ── Configuration (loaded once) ────────────────────────────────────

_config_loaded = False
_whitelist: set[str] = {"127.0.0.1", "0.0.0.0"}
_cooldown_seconds: float = 30.0
_max_blocked: int = 500


def _ensure_config() -> None:
    """Load firewall settings from config.yaml on first call."""
    global _config_loaded, _whitelist, _cooldown_seconds, _max_blocked
    if _config_loaded:
        return
    try:
        from config import get_config
        fw = get_config().get("firewall", {})
        wl = fw.get("whitelist", ["127.0.0.1", "0.0.0.0"])
        _whitelist = set(wl)
        _cooldown_seconds = float(fw.get("cooldown_seconds", 30))
        _max_blocked = int(fw.get("max_blocked", 500))
    except Exception as exc:
        _log.warning("firewall: could not load config, using defaults: %s", exc)
    _config_loaded = True


def _detect_ssh_ip() -> str | None:
    """
    Detect the administrator's SSH connection IP address
    on Linux to prevent self-blocking.
    """
    ssh_client = os.environ.get("SSH_CLIENT")
    ssh_conn = os.environ.get("SSH_CONNECTION")

    for var in [ssh_client, ssh_conn]:
        if var:
            parts = var.strip().split()
            if parts:
                ip = parts[0]
                _log.info("Detected SSH session from: %s (added to whitelist)", ip)
                _whitelist.add(ip)
                return ip
    return None


# Initialise SSH whitelist at import time
_detect_ssh_ip()


# ── OS Command Wrappers ───────────────────────────────────────────

def _is_linux() -> bool:
    return sys.platform.startswith("linux")


def _execute_cmd(cmd: list) -> bool:
    """Run a system command and return True if successful."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            return True
        else:
            _log.error("Firewall command failed: %s — %s", " ".join(cmd), res.stderr.strip())
            return False
    except Exception as exc:
        _log.error("Error running firewall command %s: %s", " ".join(cmd), exc)
        return False


# ── Core IPS Functions ────────────────────────────────────────────

def block_ip(ip: str, reason: str = "suspicious activity", is_auto: bool = False) -> bool:
    """
    Block an IP address in the OS firewall.
    Returns True if the IP was newly blocked, False otherwise.

    Checks:
      - Not in whitelist
      - Not already blocked (duplicate prevention)
      - Not in cooldown period
      - Max blocked limit not reached
    """
    _ensure_config()

    if not ip or ip in _whitelist:
        return False

    with _lock:
        # Duplicate prevention
        if ip in _active_blocks:
            return False

        # Cooldown check
        now = time.time()
        last = _last_block_time.get(ip, 0)
        if now - last < _cooldown_seconds:
            _log.debug("Cooldown active for %s (%.0fs remaining)", ip, _cooldown_seconds - (now - last))
            return False

        # Max blocked limit
        if len(_active_blocks) >= _max_blocked:
            _log.warning("Max blocked IPs reached (%d). Cannot block %s", _max_blocked, ip)
            return False

        _log.warning("BLOCKING IP: %s — Reason: %s (auto=%s)", ip, reason, is_auto)

        success = False
        if _is_linux():
            cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            success = _execute_cmd(cmd)
        else:
            rule_name = f"IDS_BLOCK_{ip.replace('.', '_')}"
            cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
                   f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"]
            success = _execute_cmd(cmd)

        if not success:
            _log.warning("OS firewall rule failed for %s (insufficient privileges). Recording in-memory block.", ip)

        _active_blocks[ip] = {
            "reason": reason,
            "time": time.strftime("%H:%M:%S"),
            "is_auto": is_auto,
        }
        _last_block_time[ip] = now

    # Persistent audit log
    try:
        import database
        database.log_firewall_action("BLOCK", ip, reason, is_auto=is_auto)
    except Exception as exc:
        _log.debug("Could not write firewall log to DB: %s", exc)

    return True


def unblock_ip(ip: str) -> bool:
    """
    Remove the firewall block rule for an IP address.
    This is always a manual action (no automatic unblock).
    """
    with _lock:
        if ip not in _active_blocks:
            return False

        _log.info("UNBLOCKING IP: %s", ip)

        success = False
        if _is_linux():
            cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
            success = _execute_cmd(cmd)
        else:
            rule_name = f"IDS_BLOCK_{ip.replace('.', '_')}"
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
            success = _execute_cmd(cmd)

        if not success:
            _log.warning("OS firewall remove failed for %s. Removing from memory blocklist.", ip)

        _active_blocks.pop(ip, None)

    # Persistent audit log
    try:
        import database
        database.log_firewall_action("UNBLOCK", ip, "manual unblock", is_auto=False)
    except Exception as exc:
        _log.debug("Could not write firewall log to DB: %s", exc)

    return True


def is_blocked(ip: str) -> bool:
    """Check if an IP is currently blocked."""
    with _lock:
        return ip in _active_blocks


def get_blocked_ips() -> dict:
    """Return dictionary of currently blocked IPs."""
    with _lock:
        return dict(_active_blocks)
