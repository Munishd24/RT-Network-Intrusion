# 🛡️ Real-Time Infrastructure Security Monitor & Intrusion Prevention System (IPS)

An enterprise-grade, real-time security monitor and active mitigation system built for CCNS. It combines deep infrastructure resource collection (CPU, Memory, Disk, Network I/O, Connections) with an Intrusion Detection/Prevention System (IPS) that leverages Z-score statistical anomaly detection (AI) and signature rules to automatically block malicious IP addresses.

Features a **premium dark-themed glassmorphism HTML dashboard**, an **interactive SSH-friendly non-blocking terminal CLI**, a **mock e-commerce visitor simulator**, **ESP32 hardware integration**, and **Docker Compose cloud-readiness** (Isolated & Host Infrastructure modes).

---

## System Architecture

```
                                  ┌───────────────────────────┐
                                  │   Target Cloud Server     │
                                  │ (Shared Host Namespaces)  │
                                  └─────────────┬─────────────┘
                                                │
                                                ▼
  ┌─────────────────┐             ┌───────────────────────────┐
  │  Attack Laptop  │             │   Docker Container Agent  │
  │ (nmap/arpspoof) ├─scans/spoof─▶   [python backend/monitor.py] │
  └─────────────────┘             └─────────────┬─────────────┘
                                                │
                                                ▼
  ┌─────────────────┐             ┌─────────────┴─────────────┐
  │   Live Admin    │◀─SSH CLI ───│  Consolidated API / Web   │
  │  Terminal Shell │ (cli.py)    │  Dashboard (localhost:5000)│
  └─────────────────┘             └─────────────┬─────────────┘
                                                │
                                                ▼
                                  ┌───────────────────────────┐
                                  │       ESP32 Hardware      │
                                  │  (OLED + LED + Buzzer)    │
                                  └───────────────────────────┘
```

---

## Key Features

1. **Rule-Based & Z-Score Anomaly Engine (`anomaly.py`, `collector.py`)**
   - Signature rules for sustained high CPU (`CRYPTO_MINING`), massive upload rate spikes (`DATA_EXFILTRATION`), high-frequency socket probes (`PORT_SCAN`), and connections to private IP ranges on admin ports (`LATERAL_MOVEMENT`).
   - Rolling Z-score statistics (AI) detects metrics exceeding 3.0 standard deviations from the historical average.
2. **Cumulative Threat Score Auto-Blocking (`app.py`, `firewall.py`)**
   - Centralized IPS system maps alerts to threat weights: `CRITICAL` = 10, `MEDIUM` = 5, `LOW` = 2, `SAFE` = 0.
   - If an IP accumulates $\ge 10$ points, the IPS triggers an **automatic firewall block** on the host.
   - Handles Windows (`netsh`) and Linux (`iptables`) firewalls, whitelists active SSH sessions automatically to prevent lockout, and falls back to mock-blocking if run without administrator privileges.
3. **Consolidated REST API (`app.py`)**
   - Returns telemetry and firewall states under `/metrics`, `/alerts`, `/stats`, `/visitors`, and a single consolidated `/cli/data` endpoint to eliminate network round-trip overhead.
4. **Premium Web Dashboard (`index.html`)**
   - Styled in a responsive dark glassmorphism theme using Inter and JetBrains Mono fonts.
   - Houses circular resource meters, historical timeline charts (Chart.js), alert feeds, active web visitors, and a firewall rules manager with interactive **Unblock** buttons.
5. **Interactive Non-Blocking Terminal CLI (`cli.py`)**
   - Thread-isolated asynchronous architecture reads remote stats in a background thread.
   - Command inputs (`b`/`t` to block, `u` to unblock) are non-blocking, keeping resource meters and visitor status updating live at 60 FPS while you type. Supports index-number selection (e.g. type `1` to block).
6. **E-Commerce Mock Website (`shop.html`, `cart.html`, `payment.html`, `login.html`)**
   - Mock store templates that log visitor IP addresses and sections in real-time. Visiting `/shop` or checking out maps client sessions to the Dashboard and CLI.

---

## CCNS Course Topics Covered

| CCNS Topic | Implementation Detail |
|------------|-----------------------|
| **TCP/IP & Ports** | Handshake SYN flag analysis for Port Scan detection. |
| **ARP Protocol** | Opcode/MAC bindings tracking to prevent ARP cache poisoning. |
| **Network Security** | Intrusion Prevention Systems (IPS), signature rules, and mitigation. |
| **IoT Networking** | Wi-Fi socket polling, JSON parsing, and hardware alerts over HTTP. |
| **Infrastructure & Virtualization** | Namespace isolation, shared networking, and Docker deployment. |

---

## Project Structure

```
ids-project/
├── backend/
│   ├── app.py            # Flask REST API, web visitor tracker & IPS block engine
│   ├── cli.py            # Asynchronous, non-blocking SSH Terminal CLI
│   ├── monitor.py        # Host system monitoring entry point
│   ├── simulator.py      # Telemetry & attack scenario simulation entry point
│   ├── collector.py      # psutil-based host metrics gatherer
│   ├── anomaly.py        # Signature rules & Z-score anomaly detector
│   ├── firewall.py       # iptables / netsh wrapper with SSH whitelisting
│   ├── sniffer.py        # Scapy raw packet listener
│   └── scorer.py         # Packet-level TCP/ARP scoring engine
├── dashboard/
│   ├── index.html        # Premium dark glassmorphism Web Dashboard
│   ├── shop.html         # Mock store index
│   ├── cart.html         # Mock store shopping cart
│   ├── payment.html      # Mock store checkout page
│   └── login.html        # Mock store sign-in page
├── esp32/
│   └── firmware.ino      # ESP32 OLED, LED, and Buzzer alert client
├── Dockerfile            # Container build recipe
├── docker-compose.yml    # Bridge and Host deployment orchestration
└── requirements.txt      # Python dependencies
```

---

## How to Test and Run

### Option A: Local Traditional Execution

#### 1. Install Dependencies
```bash
cd ids-project
pip install -r requirements.txt
```

#### 2. Start the Backend Monitor or Simulator
- **Simulator Mode (No privileges needed)**:
  ```bash
  python backend/simulator.py
  ```
- **Real Monitor Mode (Requires admin/sudo to block host IPs)**:
  ```bash
  python backend/monitor.py
  ```

---

### Option B: Docker Container Deployment (Recommended for Cloud Servers)

#### 1. Isolated Mode (For Local Testing & Simulator Runs)
Starts Flask and the web assets inside a virtual bridge network:
```bash
docker compose up ids-monitor-bridge --build
```
*Access the Web GUI Dashboard at `http://localhost:5000` and the E-Commerce Store at `http://localhost:5000/shop`.*

#### 2. Host Infrastructure Mode (For Server Protection)
Runs the container sharing the host's namespaces. Allows the container to monitor real processes/sockets on the cloud server and execute real `iptables` drop rules on the host network:
```bash
docker compose up ids-monitor-host --build
```

---

### Step 3: Launch the Terminal CLI

In a separate terminal window (local or remote SSH):
```bash
python backend/cli.py
```
- Press `b` or `t` to block. Type the index number of the visitor (e.g. `1`) or an IP address, then press `Enter`.
- Press `u` to unblock, or `q` to exit.

---

## ESP32 Wiring Diagram

```
ESP32 DevKit V1
┌──────────────┐
│              │
│  GPIO 25 ───┼──► 220Ω ──► Red LED    ──► GND
│  GPIO 26 ───┼──► 220Ω ──► Green LED  ──► GND
│  GPIO 27 ───┼──► 220Ω ──► Blue LED   ──► GND
│              │
│  GPIO 14 ───┼──► Buzzer (+) ──► GND
│              │
│  GPIO 21 ───┼──► OLED SDA
│  GPIO 22 ───┼──► OLED SCL
│  3.3V    ───┼──► OLED VCC
│  GND     ───┼──► OLED GND
│              │
└──────────────┘
```

---

## Submission Day Demo Script (60 Seconds)

1. **Access the Store**: Open `http://localhost:5000/shop` on your phone or laptop.
2. **Show the CLI**: Run `python backend/cli.py`. Point to the visitor table showing your device's IP address with a green `SAFE` label.
3. **Start an Attack**: Trigger the simulator or scan using `nmap -sS`.
4. **Demonstrate Mitigation**: Watch the threat level shift to `CRITICAL`. In the CLI, press `b`, type `1` (your visitor index), and press `Enter`.
5. **Show Proof**: The IP instantly moves to the **Active Firewall Blocks** list in both the CLI and Web Dashboard, proving a complete end-to-end detection, scoring, and IPS mitigation loop.

---

## License

MIT — Created for CCNS coursework presentation and cloud infrastructure testing.
