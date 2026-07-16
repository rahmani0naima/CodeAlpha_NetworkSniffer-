"""
sniffer_core.py
----------------
Core packet-capture engine shared by the CLI and GUI front-ends.

Responsibilities:
    - Wrap Scapy's sniff() in a background thread so callers (CLI/GUI)
      stay responsive.
    - Parse each captured packet into a clean, display-ready dict.
    - Provide start/stop/save controls and simple statistics.

Author: Naima Rahmani
Project: CodeAlpha_NetworkSniffer (CodeAlpha Cyber Security Internship - Task 1)
"""

import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, ARP, Raw, get_if_list


@dataclass
class PacketInfo:
    """Clean, display-ready representation of one captured packet."""
    index: int
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: str = ""
    dst_port: str = ""
    length: int = 0
    payload_preview: str = ""
    summary: str = ""
    raw_packet: object = field(default=None, repr=False)


class NetworkSniffer:
    """
    Threaded packet sniffer built on Scapy.

    Usage:
        sniffer = NetworkSniffer(on_packet=my_callback)
        sniffer.start(iface="eth0", bpf_filter="tcp or udp")
        ...
        sniffer.stop()
        sniffer.save_pcap("capture.pcap")
    """

    PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

    def __init__(self, on_packet=None):
        """
        on_packet: optional callback(PacketInfo) invoked for every
                   captured packet — used by the GUI to update the
                   table live. CLI can leave this None and just poll
                   self.packets after stopping, or pass a print function.
        """
        self.on_packet = on_packet
        self.packets: list[PacketInfo] = []
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._counter = 0
        self.protocol_stats = Counter()
        self.start_time = None

    # ------------------------------------------------------------------ #
    # Capture control
    # ------------------------------------------------------------------ #
    def start(self, iface=None, bpf_filter="", count=0):
        """Start sniffing in a background thread (non-blocking)."""
        if self._thread and self._thread.is_alive():
            raise RuntimeError("Sniffer is already running.")

        self._stop_event.clear()
        self.start_time = time.time()
        self._thread = threading.Thread(
            target=self._sniff_loop,
            kwargs={"iface": iface, "bpf_filter": bpf_filter, "count": count},
            daemon=True,
        )
        self._thread.start()

    def stop(self):
        """Signal the sniff loop to stop. Scapy checks stop_filter each packet."""
        self._stop_event.set()

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def _sniff_loop(self, iface, bpf_filter, count):
        try:
            sniff(
                iface=iface,
                filter=bpf_filter or None,
                prn=self._process_packet,
                stop_filter=lambda pkt: self._stop_event.is_set(),
                store=False,
                count=count if count > 0 else 0,
            )
        except PermissionError:
            self._emit_error(
                "Permission denied. Packet capture requires administrator/root "
                "privileges (run as sudo on Linux/macOS, or 'Run as Administrator' "
                "on Windows with Npcap installed)."
            )
        except OSError as e:
            self._emit_error(f"Interface error: {e}")

    def _emit_error(self, message):
        if self.on_packet:
            self.on_packet(None, error=message)

    # ------------------------------------------------------------------ #
    # Packet parsing
    # ------------------------------------------------------------------ #
    def _process_packet(self, pkt):
        self._counter += 1
        info = self._parse_packet(pkt, self._counter)
        self.packets.append(info)
        self.protocol_stats[info.protocol] += 1
        if self.on_packet:
            self.on_packet(info)

    def _parse_packet(self, pkt, index) -> PacketInfo:
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        src_ip = dst_ip = "N/A"
        proto_name = "OTHER"
        src_port = dst_port = ""
        length = len(pkt)

        if pkt.haslayer(IP):
            layer = pkt[IP]
            src_ip, dst_ip = layer.src, layer.dst
            proto_name = self.PROTO_MAP.get(layer.proto, f"IP-{layer.proto}")
        elif pkt.haslayer(IPv6):
            layer = pkt[IPv6]
            src_ip, dst_ip = layer.src, layer.dst
            proto_name = "IPv6"
        elif pkt.haslayer(ARP):
            src_ip, dst_ip = pkt[ARP].psrc, pkt[ARP].pdst
            proto_name = "ARP"

        if pkt.haslayer(TCP):
            proto_name = "TCP"
            src_port, dst_port = str(pkt[TCP].sport), str(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            proto_name = "UDP"
            src_port, dst_port = str(pkt[UDP].sport), str(pkt[UDP].dport)
        elif pkt.haslayer(ICMP):
            proto_name = "ICMP"

        payload_preview = ""
        if pkt.haslayer(Raw):
            raw_bytes = bytes(pkt[Raw].load)[:64]
            payload_preview = self._safe_preview(raw_bytes)

        return PacketInfo(
            index=index,
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=proto_name,
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            payload_preview=payload_preview,
            summary=pkt.summary(),
            raw_packet=pkt,
        )

    @staticmethod
    def _safe_preview(raw_bytes: bytes) -> str:
        """Render payload bytes as printable ASCII, dots for non-printable."""
        return "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_bytes)

    # ------------------------------------------------------------------ #
    # Utilities
    # ------------------------------------------------------------------ #
    def save_pcap(self, filepath: str):
        """Save all captured packets to a .pcap file (openable in Wireshark)."""
        raw_pkts = [p.raw_packet for p in self.packets if p.raw_packet is not None]
        if not raw_pkts:
            raise ValueError("No packets captured yet.")
        wrpcap(filepath, raw_pkts)

    def save_log(self, filepath: str):
        """Save a human-readable text log of captured packets."""
        with open(filepath, "w", encoding="utf-8") as f:
            for p in self.packets:
                f.write(
                    f"[{p.index}] {p.timestamp} | {p.protocol:6s} | "
                    f"{p.src_ip}:{p.src_port} -> {p.dst_ip}:{p.dst_port} | "
                    f"{p.length} bytes\n"
                )
                if p.payload_preview:
                    f.write(f"      payload: {p.payload_preview}\n")

    def get_stats(self) -> dict:
        elapsed = time.time() - self.start_time if self.start_time else 0
        return {
            "total_packets": len(self.packets),
            "elapsed_seconds": round(elapsed, 1),
            "protocol_breakdown": dict(self.protocol_stats),
        }

    def reset(self):
        self.packets.clear()
        self.protocol_stats.clear()
        self._counter = 0
        self.start_time = None

    @staticmethod
    def list_interfaces():
        try:
            return get_if_list()
        except Exception:
            return []
