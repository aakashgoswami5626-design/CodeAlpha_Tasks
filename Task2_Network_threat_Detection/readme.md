# 🌐 Network Intrusion Monitoring Dashboard

This project is a Python-based passive network monitoring tool built with Scapy. It captures live traffic on a selected interface, detects suspicious network patterns, and shows the results in a local browser dashboard.

It is designed for learning, lab testing, and authorized local-network observation. The system does not block traffic or change the network state—it only monitors and alerts.

## ✨ Features

- 🧠 Real-time packet capture from a live network interface
- 🔍 Passive intrusion detection for:
  - TCP port scans
  - UDP port scans
  - SYN floods
  - ICMP floods
  - ARP address changes
- 📊 Live dashboard at `http://127.0.0.1:8765`
- 📈 Traffic statistics such as packets/sec, active hosts, and top ports
- 📝 Alert logging to `ids_alerts.jsonl` in JSON Lines format
- 🛡️ Safe-by-design behavior: monitoring only, no blocking or injection

## 🧩 Project Files

- `network_dashboard.py` — main packet sniffer and browser dashboard
- `network_ids.py` — intrusion detection logic and thresholds
- `runtime_environment.py` — environment setup for Scapy
- `requirements.txt` — Python dependencies
- `ids_alerts.jsonl` — generated alert log file
- `run_dashboard.bat` / `build.bat` — Windows launch helpers

## ⚙️ Requirements

Before running the project, install the dependencies:

```bash
python -m pip install -r requirements.txt
```

You may also need:

- Windows: Npcap or WinPcap installed
- Administrator/root privileges for packet capture
- A network interface that supports promiscuous or passive sniffing

## 🚀 Quick Start

List available interfaces:

```bash
python network_dashboard.py --list-interfaces
```

Start the dashboard on a selected interface:

```bash
python network_dashboard.py --interface "Ethernet"
```

The dashboard should open automatically in your browser. If it does not, visit:

```text
http://127.0.0.1:8765/
```

### Optional arguments

```bash
python network_dashboard.py \
  --interface "Ethernet" \
  --port 8765 \
  --window-seconds 10 \
  --port-scan-threshold 15 \
  --syn-flood-threshold 100 \
  --icmp-flood-threshold 30 \
  --alert-log ids_alerts.jsonl
```

## 📌 What the tool detects

This project uses heuristic detection rules instead of full production IDS logic. It watches for noisy or suspicious traffic patterns such as:

- 🔴 Large numbers of distinct destination ports from one source
- 🔴 Burst of TCP SYN packets aimed at one host
- 🔴 High ICMP traffic from one source
- 🔴 ARP source IP mapping to a different MAC address

These alerts help identify possible scanning or flooding activity, but they are not guaranteed proof of an attack.

## 🧾 Alert Logging

Detected alerts are appended to `ids_alerts.jsonl` as structured JSON records. This makes it easy to review detections later without changing the live monitoring behavior.

## ✅ Important Notes

- This is a learning/demo security tool, not a full enterprise IDS.
- It only monitors traffic visible on the selected interface.
- It does not block packets or modify the network.
- Only use it on networks you own or are explicitly authorized to inspect.
- On Windows, packet capture often requires Npcap and elevated privileges.

## 🧪 Example Use Case

A developer can run the tool on a local machine to:

- inspect active traffic on the LAN
- observe unusual scan patterns
- learn how network packets behave in real time
- study event patterns before building more advanced monitoring systems

## 📘 Summary

This project combines packet capture, intrusion detection heuristics, and a local dashboard into one simple monitoring tool. It is perfect for understanding how network traffic behaves and how suspicious patterns can be detected in a passive, safe way.

