# 🕵️ Network Packet Sniffer

A simple **Python-based Network Packet Sniffer** built using **Scapy**.
It captures live network traffic and displays readable information about packets, protocols, endpoints, and payloads.

> ⚠️ **For educational and authorized use only.**

---

## 🚀 Features

* 🔍 Network interface discovery
* 📡 Live packet capture
* 🌐 IPv4 & IPv6 support
* 🔗 Ethernet packet analysis
* 🚚 TCP & UDP detection
* 📢 ICMP & ARP detection
* 🌎 DNS detection
* 🔐 Basic TLS detection
* 📡 DHCPv6 detection
* 📢 IGMP detection
* 📍 Source & destination endpoints
* 🔢 Port information
* 📦 Payload preview
* 🔤 ASCII & hexadecimal payload display
* 📝 Clean terminal output
* ⚡ Real-time packet processing

---

## 🛠️ Technologies Used

* 🐍 Python
* 🦂 Scapy
* 🌐 TCP/IP
* 💻 Command Line Interface

---

## 📦 Requirements

* 🐍 Python 3.x
* 🦂 Scapy
* 💻 Windows / Linux / macOS
* 🔐 Administrator/root privileges may be required

### Install Scapy

```bash
pip install scapy
```

> 💡 On Windows, **Npcap** may also be required for packet capture.

---

## ▶️ Usage

### 🔍 List Network Interfaces

```bash
python network_sniffer.py --list-interfaces
```

### 📡 Start Sniffer

```bash
python network_sniffer.py
```

### 🖧 Select Interface

```bash
python network_sniffer.py -i Ethernet
```

### 🔢 Capture Specific Number of Packets

```bash
python network_sniffer.py -c 20
```

### 📦 Set Payload Preview Size

```bash
python network_sniffer.py --payload-bytes 128
```

---

## ⚙️ Command-Line Options

| Option              | Description                  |
| ------------------- | ---------------------------- |
| `-i, --interface`   | Select network interface     |
| `-c, --count`       | Number of packets to capture |
| `--payload-bytes`   | Payload preview size         |
| `--list-interfaces` | List available interfaces    |

---

## 📊 Example Output

```text
[00001] 12:45:30.256
192.168.1.10:54822 → 8.8.8.8:53

Protocol:
Ethernet > IPv4 > UDP > DNS

Frame size:
78 bytes

IPv4:
TTL=64
Packet ID=41212

Ethernet:
00:11:22:33:44:55 → aa:bb:cc:dd:ee:ff

UDP:
Datagram length=46 bytes

DNS:
Query: example.com
Type: A (IPv4)

Payload:
Hex: ...
ASCII: ...
```

---

## 🌐 Supported Protocols

```text
🔗 Ethernet
├── 🌐 IPv4
│   ├── 🚚 TCP
│   ├── 📡 UDP
│   └── 📢 ICMP
│
├── 🌐 IPv6
│   └── 📢 ICMPv6
│
├── 🔄 ARP
│
└── Application Protocols
    ├── 🌎 DNS
    ├── 🔐 TLS
    ├── 📡 DHCPv6
    └── 📢 IGMP
```

---

## 🎯 Use Cases

* 🔍 Monitor local network traffic
* 🌎 Study network protocols
* 🐛 Debug networking applications
* 📚 Learn TCP/IP communication
* 🛡️ Understand basic network security
* 🧪 Practice packet analysis

---

## 📁 Project Structure

```text
Network-Packet-Sniffer/
│
├── 🐍 network_sniffer.py
├── 📄 README.md
└── 📜 requirements.txt
```

### `requirements.txt`

```text
scapy
```

---

## 🔮 Future Improvements

* 🖥️ GUI interface
* 📊 Traffic statistics
* 🔍 Advanced packet filtering
* 💾 PCAP file export
* 📈 Traffic visualization
* 🚨 Basic suspicious-traffic alerts
* 📋 CSV export
* 🌐 Additional protocol support

---

## ⚠️ Ethical & Legal Use

Packet sniffing can expose sensitive information.

Use this project **only on networks and devices that you own or have explicit permission to monitor**.

❌ Do not use it to intercept private communications or unauthorized network traffic.

---

## 🎓 Learning Outcomes

* 🐍 Python programming
* 🦂 Scapy
* 📡 Packet capture
* 🌐 Network protocols
* 🔎 Packet analysis
* 🛡️ Cyber Security fundamentals

---

## 👨‍💻 Author

**Aakash**

🎓 B.Tech — Cyber Security
💻 Networking & Cyber Security Enthusiast

---

⭐ **If you found this project useful, consider giving the repository a star!**

