"""
sniffer_cli.py
---------------
Command-line front-end for the Network Sniffer.

Examples:
    sudo python sniffer_cli.py                       # sniff all traffic, all interfaces
    sudo python sniffer_cli.py -i eth0 -f "tcp"       # only TCP on eth0
    sudo python sniffer_cli.py -c 50 -o capture.pcap  # capture 50 packets, save as pcap
    python sniffer_cli.py --list-interfaces

Note: Raw packet capture requires administrator/root privileges.

Author: Naima Rahmani
Project: CodeAlpha_NetworkSniffer (CodeAlpha Cyber Security Internship - Task 1)
"""

import argparse
import signal
import sys

from sniffer_core import NetworkSniffer

# ANSI colors for readable terminal output
COLORS = {
    "TCP": "\033[94m",
    "UDP": "\033[92m",
    "ICMP": "\033[93m",
    "ARP": "\033[95m",
    "IPv6": "\033[96m",
    "OTHER": "\033[90m",
    "RESET": "\033[0m",
}


def print_banner():
    print("=" * 70)
    print("  CodeAlpha Cyber Security Internship - Task 1")
    print("  Basic Network Sniffer (Python + Scapy)")
    print("=" * 70)


def print_packet(info, error=None):
    if error:
        print(f"\n[!] {error}\n", file=sys.stderr)
        sys.exit(1)

    color = COLORS.get(info.protocol, COLORS["OTHER"])
    reset = COLORS["RESET"]
    port_info = ""
    if info.src_port and info.dst_port:
        port_info = f":{info.src_port} -> :{info.dst_port}  "

    line = (
        f"{color}[{info.index:>4}] {info.timestamp} | {info.protocol:<6}{reset} "
        f"{info.src_ip:>15} -> {info.dst_ip:<15} {port_info}"
        f"({info.length}B)"
    )
    print(line)
    if info.payload_preview:
        print(f"        payload: {info.payload_preview[:60]}")


def main():
    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer - capture and analyze network packets."
    )
    parser.add_argument("-i", "--iface", default=None, help="Network interface to sniff on")
    parser.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'tcp', 'udp port 53'")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-o", "--output", default=None, help="Save captured packets to .pcap file")
    parser.add_argument("--log", default=None, help="Save a text log of captured packets")
    parser.add_argument("--list-interfaces", action="store_true", help="List available network interfaces and exit")
    args = parser.parse_args()

    if args.list_interfaces:
        ifaces = NetworkSniffer.list_interfaces()
        print("Available interfaces:")
        for name in ifaces:
            print(f"  - {name}")
        return

    print_banner()
    print(f"Interface : {args.iface or 'default (all)'}")
    print(f"Filter    : {args.filter or 'none (all traffic)'}")
    print(f"Count     : {'unlimited (Ctrl+C to stop)' if args.count == 0 else args.count}")
    print("-" * 70)

    sniffer = NetworkSniffer(on_packet=print_packet)

    def handle_sigint(sig, frame):
        print("\n\n[*] Stopping capture...")
        sniffer.stop()

    signal.signal(signal.SIGINT, handle_sigint)

    sniffer.start(iface=args.iface, bpf_filter=args.filter, count=args.count)

    # Block main thread until the sniffing thread finishes (Ctrl+C or count reached).
    # Polling with a short timeout (instead of a plain join) keeps the main thread
    # responsive to the SIGINT handler on all platforms, including Windows.
    try:
        while sniffer.is_running():
            sniffer._thread.join(timeout=0.5)
    except KeyboardInterrupt:
        sniffer.stop()
        sniffer._thread.join(timeout=5)

    # Summary
    stats = sniffer.get_stats()
    print("-" * 70)
    print(f"Capture complete: {stats['total_packets']} packets in {stats['elapsed_seconds']}s")
    for proto, cnt in stats["protocol_breakdown"].items():
        print(f"  {proto:<6}: {cnt}")

    if args.output:
        try:
            sniffer.save_pcap(args.output)
            print(f"[+] Saved pcap file: {args.output}")
        except ValueError as e:
            print(f"[!] {e}")

    if args.log:
        sniffer.save_log(args.log)
        print(f"[+] Saved text log: {args.log}")


if __name__ == "__main__":
    main()
