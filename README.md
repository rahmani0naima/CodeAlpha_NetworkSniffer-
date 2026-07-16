# CodeAlpha_NetworkSniffer

**CodeAlpha Cyber Security Internship — Task 1: Basic Network Sniffer**

A Python-based network packet sniffer built with [Scapy](https://scapy.net/), available as both a command-line tool and a desktop GUI. It captures live traffic, parses each packet's structure (source/destination IP, protocol, ports, payload), and lets you export captures to `.pcap` (Wireshark-compatible) or a readable text log.

## Features

- Live packet capture on any network interface, with optional BPF filters (`tcp`, `udp port 53`, etc.)
- Parses IPv4, IPv6, TCP, UDP, ICMP, and ARP layers
- Displays source/destination IP & port, protocol, packet length, and an ASCII payload preview
- Export to `.pcap` (opens in Wireshark) or a plain-text log
- Two interfaces sharing one capture engine:
  - **CLI** — color-coded live terminal output, ideal for quick captures or scripting
  - **GUI** — CustomTkinter desktop app with a live packet table, protocol color-coding, packet inspector panel, and running stats

## Screenshots

<img width="940" height="681" alt="image" src="https://github.com/user-attachments/assets/379ea6d9-1a5c-4b1d-809c-2c64c7d9159f" />


## Requirements

- Python 3.10+
- [Npcap](https://npcap.com/) (Windows) or `libpcap` (Linux/macOS — usually preinstalled; on Debian/Ubuntu: `sudo apt install libpcap-dev`)
- **Administrator/root privileges** are required to capture raw packets

```bash
pip install -r requirements.txt
```

## Usage

### CLI

```bash
# Sniff all traffic on the default interface (Ctrl+C to stop)
sudo python sniffer_cli.py

# Sniff only TCP traffic on a specific interface
sudo python sniffer_cli.py -i eth0 -f "tcp"

# Capture exactly 50 packets and save as pcap
sudo python sniffer_cli.py -c 50 -o capture.pcap

# List available interfaces
python sniffer_cli.py --list-interfaces
```

| Flag | Description |
|---|---|
| `-i, --iface` | Network interface to sniff on |
| `-f, --filter` | BPF filter expression (e.g. `"tcp"`, `"udp port 53"`) |
| `-c, --count` | Number of packets to capture (0 = unlimited) |
| `-o, --output` | Save captured packets to a `.pcap` file |
| `--log` | Save a text log of captured packets |
| `--list-interfaces` | List available network interfaces and exit |

### GUI

```bash
sudo python sniffer_gui.py
```

Pick an interface and optional filter, hit **Start Capture**, and watch packets stream into the table in real time. Click any row to inspect its full detail (IPs, ports, length, ASCII payload preview) in the side panel. Use **Export** to save the session as `.pcap` or `.log`.

## Project Structure

```
CodeAlpha_NetworkSniffer/
├── sniffer_core.py     # Shared capture engine (threaded Scapy wrapper, packet parsing)
├── sniffer_cli.py       # Command-line interface
├── sniffer_gui.py       # CustomTkinter GUI
├── requirements.txt
└── README.md
```

## How It Works

`sniffer_core.py` wraps `scapy.sniff()` in a background thread so the capture never blocks the CLI or GUI. Each captured packet is parsed into a `PacketInfo` dataclass (timestamp, protocol, IPs, ports, length, ASCII payload preview) and handed to a callback — the CLI prints it immediately in color, the GUI pushes it through a thread-safe queue and renders it in the live table. Both front-ends share the exact same parsing and export logic, so results are always consistent between them.

## Disclaimer

This tool is built for educational purposes as part of the CodeAlpha Cyber Security Internship. Only capture traffic on networks you own or have explicit permission to monitor. Unauthorized packet interception may be illegal in your jurisdiction.

## Author

Naima Rahmani — [GitHub](https://github.com/rahmani0naima)
