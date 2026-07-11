"""
Configuration Loader
---------------------
Loads settings from config.yaml with environment variable overrides.
Provides a module-level get_config() function that returns the full
configuration dict. Config is loaded once and cached.

Environment variable overrides:
  IDS_CONFIG_PATH   — path to config.yaml (default: config.yaml in project root)
  IDS_LOG_LEVEL     — override logging.level
  IDS_DB_PATH       — override database.path
  IDS_HOST          — override server.host
  IDS_PORT          — override server.port
  API_KEY           — API key for endpoint authentication
"""

import os
import sys
import logging

_log = logging.getLogger(__name__)

# Resolve project root (one level up from backend/)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_config_cache: dict | None = None

# Default configuration (used when config.yaml is missing)
_DEFAULTS: dict = {
    "risk_engine": {
        "weights": {
            "PORT_SCAN": 5,
            "UNUSUAL_UPLOAD_ACTIVITY": 3,
            "RESOURCE_ABUSE": 2,
            "ARP_SPOOFING": 5,
            "LATERAL_MOVEMENT": 4,
            "RESOURCE_ANOMALY": 1,
        },
        "immediate_block": [
            "ARP_SPOOFING"
        ],
        "severity_multiplier": {
            "CRITICAL": 2.0,
            "MEDIUM": 1.0,
            "LOW": 0.5,
            "SAFE": 0.0,
        },
        "block_threshold": 15,
    },
    "detection": {
        "port_scan_window_seconds": 5,
        "port_scan_unique_ports": {"critical": 50, "medium": 20, "low": 5},
        "cpu_threshold": 85.0,
        "cpu_sustained_seconds": 30.0,
        "upload_multiplier": 3.0,
        "upload_baseline_samples": 15,
        "engine_port_scan_threshold": 10,
        "engine_port_scan_window": 5.0,
        "cooldown_seconds": 10.0,
        "zscore_window": 60,
        "zscore_threshold": 3.0,
    },
    "firewall": {
        "whitelist": ["127.0.0.1", "0.0.0.0"],
        "cooldown_seconds": 30,
        "max_blocked": 500,
    },
    "monitoring": {
        "poll_interval_seconds": 2,
        "metrics_history_size": 60,
        "alert_buffer_size": 500,
    },
    "server": {"host": "0.0.0.0", "port": 5000},
    "logging": {"level": "INFO", "format": "json", "file": "data/ids.log"},
    "database": {"path": "data/incidents.db"},
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into a copy of *base*."""
    merged = dict(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_yaml(path: str) -> dict:
    """Load a YAML file. Returns empty dict on failure."""
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
            return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        _log.warning("Config file not found: %s — using defaults", path)
        return {}
    except Exception as exc:
        _log.error("Failed to load config %s: %s — using defaults", path, exc)
        return {}


def _apply_env_overrides(cfg: dict) -> None:
    """Apply environment variable overrides in-place."""
    if os.environ.get("IDS_LOG_LEVEL"):
        cfg["logging"]["level"] = os.environ["IDS_LOG_LEVEL"]
    if os.environ.get("IDS_DB_PATH"):
        cfg["database"]["path"] = os.environ["IDS_DB_PATH"]
    if os.environ.get("IDS_HOST"):
        cfg["server"]["host"] = os.environ["IDS_HOST"]
    if os.environ.get("IDS_PORT"):
        cfg["server"]["port"] = int(os.environ["IDS_PORT"])


def _resolve_path(cfg: dict) -> None:
    """Resolve relative paths in config against the project root."""
    for section in ("logging", "database"):
        key = "file" if section == "logging" else "path"
        raw = cfg[section].get(key, "")
        if raw and not os.path.isabs(raw):
            cfg[section][key] = os.path.join(_PROJECT_ROOT, raw)


def get_config() -> dict:
    """Return the full configuration dict (loaded once, cached)."""
    global _config_cache
    if _config_cache is not None:
        return _config_cache

    config_path = os.environ.get(
        "IDS_CONFIG_PATH",
        os.path.join(_PROJECT_ROOT, "config.yaml"),
    )
    yaml_data = _load_yaml(config_path)
    cfg = _deep_merge(_DEFAULTS, yaml_data)
    _apply_env_overrides(cfg)
    _resolve_path(cfg)

    # Ensure data directory exists
    data_dir = os.path.dirname(cfg["database"]["path"])
    if data_dir:
        os.makedirs(data_dir, exist_ok=True)

    _config_cache = cfg
    return cfg
