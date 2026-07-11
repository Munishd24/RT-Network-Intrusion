"""
IPS Terminal CLI Tool
----------------------
Terminal-friendly text interface for monitoring system stats,
alerts, and managing active firewall rules. Thread-isolated
non-blocking input and fetching for zero lag.

Usage:
    python backend/cli.py
"""

import os
import sys
import time
import requests
import threading

# Cross-platform non-blocking key reader imports
if not sys.platform.startswith("win"):
    import termios
    import tty
    import select
else:
    import msvcrt

API_BASE = os.environ.get("IDS_API_URL", "http://localhost:5000")
_API_KEY = os.environ.get("IDS_API_KEY", "")

# ANSI Colors
CLR_RESET = "\033[0m"
CLR_RED = "\033[91m"
CLR_GREEN = "\033[92m"
CLR_YELLOW = "\033[93m"
CLR_BLUE = "\033[94m"
CLR_CYAN = "\033[96m"
CLR_BOLD = "\033[1m"

# Thread-Safe Global State
data_lock = threading.Lock()
cli_data = {}
is_api_connected = False
api_error_message = "Initializing..."
last_seen_visitors = []

# Non-blocking input states
prompt_action = None  # "BLOCK", "UNBLOCK", or None
input_buffer = ""
status_message = ""
status_message_expiry = 0.0


def set_status(msg: str, duration: float = 3.0):
    global status_message, status_message_expiry
    status_message = msg
    status_message_expiry = time.time() + duration


class NonBlockingConsole:
    """Context manager for terminal non-blocking keyboard input."""
    def __enter__(self):
        if not sys.platform.startswith("win"):
            self.old_settings = termios.tcgetattr(sys.stdin)
            tty.setcbreak(sys.stdin.fileno())
        return self

    def __exit__(self, type, value, traceback):
        if not sys.platform.startswith("win"):
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.old_settings)

    def get_char(self):
        if sys.platform.startswith("win"):
            if msvcrt.kbhit():
                try:
                    ch = msvcrt.getch()
                    # Map backspace, enter, and escape
                    if ch == b'\x08':  # Backspace
                        return 'BACKSPACE'
                    elif ch in (b'\r', b'\n'):
                        return 'ENTER'
                    elif ch == b'\x1b':  # Escape
                        return 'ESCAPE'
                    return ch.decode("utf-8")
                except Exception:
                    return None
            return None
        else:
            # Linux single key non-blocking read
            rlist, _, _ = select.select([sys.stdin], [], [], 0.02)
            if rlist:
                ch = sys.stdin.read(1)
                if ch in ('\x7f', '\x08'):  # Backspace
                    return 'BACKSPACE'
                elif ch in ('\n', '\r'):
                    return 'ENTER'
                elif ch == '\x1b':  # Escape
                    return 'ESCAPE'
                return ch
            return None


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def format_rate(bytes_sec: float) -> str:
    if bytes_sec >= 1024 * 1024:
        return f"{bytes_sec / (1024*1024):.1f} MB/s"
    return f"{bytes_sec / 1024:.1f} KB/s"


def fetch_data_once():
    """Performs a single background request to populate state."""
    global cli_data, is_api_connected, api_error_message, last_seen_visitors
    try:
        headers = {"X-API-Key": _API_KEY} if _API_KEY else {}
        res = requests.get(f"{API_BASE}/cli/data", timeout=1.5, headers=headers)
        if res.status_code == 200:
            data = res.json()
            with data_lock:
                cli_data = data
                is_api_connected = True
                api_error_message = ""
                last_seen_visitors = data.get("visitors", [])
            return True
        else:
            with data_lock:
                is_api_connected = False
                api_error_message = f"HTTP Error {res.status_code}"
            return False
    except Exception as e:
        with data_lock:
            is_api_connected = False
            api_error_message = str(e)
        return False


def background_data_fetcher():
    """Thread function that polls the server for state updates."""
    while True:
        fetch_data_once()
        draw_stats()
        time.sleep(2.0)


def draw_stats():
    global prompt_action, input_buffer, status_message, status_message_expiry
    
    with data_lock:
        connected = is_api_connected
        err_msg = api_error_message
        data = dict(cli_data) if cli_data else {}

    if not connected:
        clear_screen()
        print(f"{CLR_RED}{CLR_BOLD}Error connecting to local API: {err_msg}{CLR_RESET}")
        print("Make sure backend/monitor.py or backend/simulator.py is running.")
        print("-" * 65)
        print(f"{CLR_BOLD}Menu Options:{CLR_RESET}  [r] Retry Connection  |  [q] Exit")
        return False

    clear_screen()
    print(f"{CLR_CYAN}{CLR_BOLD}================================================================={CLR_RESET}")
    print(f"{CLR_CYAN}{CLR_BOLD}             🛡️  INFRASTRUCTURE SECURITY MONITOR CLI              {CLR_RESET}")
    print(f"{CLR_CYAN}{CLR_BOLD}================================================================={CLR_RESET}")

    metrics = data.get("metrics", {})
    stats = data.get("stats", {})
    visitors = data.get("visitors", [])
    rules = data.get("firewall_rules", {})
    alerts = data.get("alerts", [])

    # Row 1: Health
    cpu = metrics.get("cpu_percent", 0.0)
    mem = metrics.get("memory_percent", 0.0)
    cpu_color = CLR_RED if cpu > 90 else (CLR_YELLOW if cpu > 70 else CLR_GREEN)
    mem_color = CLR_RED if mem > 90 else (CLR_YELLOW if mem > 70 else CLR_GREEN)

    print(f"{CLR_BOLD}System Resources:{CLR_RESET}")
    print(f"  CPU: {cpu_color}{cpu}%{CLR_RESET}  |  Memory: {mem_color}{mem}%{CLR_RESET} ({metrics.get('memory_used_mb', 0)}/{metrics.get('memory_total_mb', 0)} MB)")
    print(f"  Net Sent: {CLR_BLUE}{format_rate(metrics.get('net_bytes_sent_rate', 0))}{CLR_RESET}  |  Net Recv: {CLR_BLUE}{format_rate(metrics.get('net_bytes_recv_rate', 0))}{CLR_RESET}")
    print(f"  Connections: {CLR_BOLD}{metrics.get('active_connections', 0)}{CLR_RESET} ({metrics.get('unique_remote_ips', 0)} unique remote IPs)")
    print("-" * 65)

    # Row 2: Threat Summary
    print(f"{CLR_BOLD}Threat Alert Statistics:{CLR_RESET}")
    print(f"  Critical: {CLR_RED}{stats.get('critical', 0)}{CLR_RESET}  |  Medium: {CLR_YELLOW}{stats.get('medium', 0)}{CLR_RESET}  |  Low: {CLR_BLUE}{stats.get('low', 0)}{CLR_RESET}")
    print(f"  Types: Res.Abuse: {stats.get('resource_abuse', 0)} | Upl.Anomaly: {stats.get('unusual_upload', 0)} | Scans: {stats.get('port_scans', 0)} | Lateral: {stats.get('lateral_movement', 0)}")
    print("-" * 65)

    # Row 2.5: Active Website Connections / Visitors
    print(f"{CLR_CYAN}{CLR_BOLD}Active Website Connections / Visitors:{CLR_RESET}")
    if not visitors:
        print("  No active website connections tracked.")
    else:
        print(f"  {CLR_BOLD}{'No.':4} | {'Remote IP':16} | {'Website Page/Section':26} | {'Threat Level':12} | {'Status':10}{CLR_RESET}")
        for idx, v in enumerate(visitors, 1):
            ip = v["ip"]
            page = v["page"]
            sev = v["severity"]
            is_blocked = v["blocked"]
            
            # Color code based on severity
            if sev == "CRITICAL":
                sev_color = CLR_RED
            elif sev == "MEDIUM":
                sev_color = CLR_YELLOW
            elif sev == "LOW":
                sev_color = CLR_BLUE
            else:
                sev_color = CLR_GREEN
                
            sev_str = f"{sev_color}{sev:12}{CLR_RESET}"
            status_str = f"{CLR_RED}[BLOCKED]{CLR_RESET}" if is_blocked else f"{CLR_GREEN}[ACTIVE]{CLR_RESET}"
            print(f"  [{idx}]  | {ip:16} | {page[:26]:26} | {sev_str} | {status_str}")
    print("-" * 65)

    # Row 3: Active Firewall Blocks
    print(f"{CLR_RED}{CLR_BOLD}Active Firewall Blocks:{CLR_RESET}")
    if not rules:
        print("  No active firewall blocks. System secure.")
    else:
        print(f"  {CLR_BOLD}{'Blocked IP':18} | {'Trigger Attack':18} | {'Time Blocked':12}{CLR_RESET}")
        for ip, detail in rules.items():
            print(f"  {ip:18} | {detail['reason']:18} | {detail['time']:12}")
    print("-" * 65)

    # Row 4: Recent Alerts Feed
    print(f"{CLR_BOLD}Recent Security Alerts (Last 5):{CLR_RESET}")
    if not alerts:
        print("  No alerts detected.")
    else:
        for a in reversed(alerts[-5:]):
            sev = a.get("severity", "LOW")
            color = CLR_RED if sev == "CRITICAL" else (CLR_YELLOW if sev == "MEDIUM" else CLR_BLUE)
            print(f"  [{color}{sev:8}{CLR_RESET}] {a.get('time')} -- {a.get('type'):18} -- {a.get('detail')}")

    print("-" * 65)

    # Row 5: Async Status Message
    if status_message and time.time() < status_message_expiry:
        print(f"{CLR_YELLOW}{CLR_BOLD}System Status: {status_message}{CLR_RESET}")
    else:
        print("")  # Blank line to maintain height

    # Row 6: Interactive Prompt
    if prompt_action == "BLOCK":
        print(f"{CLR_YELLOW}{CLR_BOLD}Command Mode [BLOCK IP]:{CLR_RESET} Enter index (1-4) or IP to block: {CLR_BOLD}{input_buffer}█{CLR_RESET}")
        print("Press [Enter] to confirm | [Esc] to cancel")
    elif prompt_action == "UNBLOCK":
        print(f"{CLR_YELLOW}{CLR_BOLD}Command Mode [UNBLOCK IP]:{CLR_RESET} Enter IP to unblock: {CLR_BOLD}{input_buffer}█{CLR_RESET}")
        print("Press [Enter] to confirm | [Esc] to cancel")
    else:
        print(f"{CLR_BOLD}Menu Options:{CLR_RESET}  [b/t] Block IP/No.  |  [u] Unblock IP  |  [r] Refresh  |  [q] Exit")
    return True


def execute_command_async(action: str, val: str):
    global last_seen_visitors
    if action == "BLOCK":
        ip = None
        if val.isdigit():
            idx = int(val) - 1
            if 0 <= idx < len(last_seen_visitors):
                ip = last_seen_visitors[idx]["ip"]
                set_status(f"Resolved index {val} to IP: {ip}")
            else:
                set_status(f"Error: Invalid index number {val}")
                return
        else:
            ip = val

        set_status(f"Requesting block for {ip}...")
        try:
            headers = {"X-API-Key": _API_KEY} if _API_KEY else {}
            res = requests.post(f"{API_BASE}/firewall/block", json={"ip": ip, "reason": "manual CLI block"}, timeout=3, headers=headers).json()
            if res.get("success"):
                set_status(f"Successfully blocked {ip}")
            else:
                set_status(f"Failed to block {ip}: {res.get('error', 'unknown error')}")
        except Exception as e:
            set_status(f"Error communicating with API: {e}")

    elif action == "UNBLOCK":
        ip = val
        set_status(f"Requesting unblock for {ip}...")
        try:
            headers = {"X-API-Key": _API_KEY} if _API_KEY else {}
            res = requests.post(f"{API_BASE}/firewall/unblock", json={"ip": ip}, timeout=3, headers=headers).json()
            if res.get("success"):
                set_status(f"Successfully unblocked {ip}")
            else:
                set_status(f"Failed to unblock {ip}: {res.get('error', 'unknown error')}")
        except Exception as e:
            set_status(f"Error communicating with API: {e}")

    # Instantly trigger background fetch so changes show up in CLI immediately
    fetch_data_once()
    draw_stats()


def main():
    global prompt_action, input_buffer

    # Start data fetcher daemon thread
    fetcher_thread = threading.Thread(target=background_data_fetcher, daemon=True)
    fetcher_thread.start()

    # Wait briefly for first fetch
    time.sleep(0.2)
    draw_stats()

    with NonBlockingConsole() as console:
        while True:
            ch = console.get_char()
            if ch:
                if prompt_action is None:
                    # Navigation Mode
                    ch_lower = ch.lower()
                    if ch_lower in ('b', 't'):
                        prompt_action = "BLOCK"
                        input_buffer = ""
                        draw_stats()
                    elif ch_lower == 'u':
                        prompt_action = "UNBLOCK"
                        input_buffer = ""
                        draw_stats()
                    elif ch_lower == 'r':
                        # Manual reload
                        threading.Thread(target=fetch_data_once, daemon=True).start()
                    elif ch_lower == 'q':
                        print("\nExiting CLI.")
                        break
                else:
                    # Typing Mode
                    if ch == 'ENTER':
                        action = prompt_action
                        val = input_buffer.strip()
                        prompt_action = None
                        input_buffer = ""
                        
                        if val:
                            threading.Thread(target=execute_command_async, args=(action, val), daemon=True).start()
                        draw_stats()
                    elif ch == 'ESCAPE':
                        prompt_action = None
                        input_buffer = ""
                        draw_stats()
                    elif ch == 'BACKSPACE':
                        input_buffer = input_buffer[:-1]
                        draw_stats()
                    elif len(ch) == 1 and ch.isprintable():
                        input_buffer += ch
                        draw_stats()

            time.sleep(0.02)


if __name__ == "__main__":
    main()
