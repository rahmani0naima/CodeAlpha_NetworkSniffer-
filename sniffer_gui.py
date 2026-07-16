"""
sniffer_gui.py
----------------
CustomTkinter GUI front-end for the Network Sniffer.

Run with administrator/root privileges to actually capture packets:
    Windows : run terminal "as Administrator", then  python sniffer_gui.py
    Linux   : sudo python sniffer_gui.py
    macOS   : sudo python sniffer_gui.py

Author: Naima Rahmani
Project: CodeAlpha_NetworkSniffer (CodeAlpha Cyber Security Internship - Task 1)
"""

import queue
import threading
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from sniffer_core import NetworkSniffer

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

PROTOCOL_COLORS = {
    "TCP": "#4FA3FF",
    "UDP": "#4CD964",
    "ICMP": "#FFC048",
    "ARP": "#C77DFF",
    "IPv6": "#5CE1E6",
    "OTHER": "#9AA0A6",
}


class NetworkSnifferApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CodeAlpha - Basic Network Sniffer")
        self.geometry("1180x720")
        self.minsize(980, 600)

        self.sniffer = NetworkSniffer(on_packet=self._on_packet_captured)
        self._ui_queue: "queue.Queue" = queue.Queue()
        self._selected_packet = None

        self._build_layout()
        self._poll_queue()
        self._refresh_interfaces()

    # ------------------------------------------------------------------ #
    # Layout
    # ------------------------------------------------------------------ #
    def _build_layout(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self._build_header()
        self._build_controls()
        self._build_body()
        self._build_statusbar()

    def _build_header(self):
        header = ctk.CTkFrame(self, corner_radius=0, fg_color=("#1A1A2E", "#1A1A2E"))
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            header, text="🛰", font=ctk.CTkFont(size=28)
        ).grid(row=0, column=0, padx=(20, 8), pady=14)

        title_box = ctk.CTkFrame(header, fg_color="transparent")
        title_box.grid(row=0, column=1, sticky="w", pady=10)
        ctk.CTkLabel(
            title_box, text="Basic Network Sniffer",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(anchor="w")
        ctk.CTkLabel(
            title_box, text="CodeAlpha Cyber Security Internship — Task 1",
            font=ctk.CTkFont(size=12), text_color="#9AA0A6",
        ).pack(anchor="w")

    def _build_controls(self):
        bar = ctk.CTkFrame(self, corner_radius=10)
        bar.grid(row=1, column=0, sticky="ew", padx=16, pady=(14, 8))
        for c in range(8):
            bar.grid_columnconfigure(c, weight=0)
        bar.grid_columnconfigure(3, weight=1)

        ctk.CTkLabel(bar, text="Interface").grid(row=0, column=0, padx=(14, 6), pady=12, sticky="w")
        self.iface_menu = ctk.CTkOptionMenu(bar, values=["any"], width=140)
        self.iface_menu.grid(row=0, column=1, padx=6, pady=12)

        ctk.CTkLabel(bar, text="Filter").grid(row=0, column=2, padx=(14, 6), pady=12, sticky="w")
        self.filter_entry = ctk.CTkEntry(bar, placeholder_text="e.g. tcp, udp port 53", width=220)
        self.filter_entry.grid(row=0, column=3, padx=6, pady=12, sticky="ew")

        self.start_btn = ctk.CTkButton(
            bar, text="▶  Start Capture", fg_color="#2E7D32", hover_color="#1B5E20",
            command=self.start_capture, width=140,
        )
        self.start_btn.grid(row=0, column=4, padx=6, pady=12)

        self.stop_btn = ctk.CTkButton(
            bar, text="■  Stop", fg_color="#B71C1C", hover_color="#7F0000",
            command=self.stop_capture, width=90, state="disabled",
        )
        self.stop_btn.grid(row=0, column=5, padx=6, pady=12)

        self.clear_btn = ctk.CTkButton(
            bar, text="Clear", fg_color="#424242", hover_color="#2E2E2E",
            command=self.clear_capture, width=80,
        )
        self.clear_btn.grid(row=0, column=6, padx=6, pady=12)

        self.export_btn = ctk.CTkButton(
            bar, text="⭳ Export", command=self.export_capture, width=90,
        )
        self.export_btn.grid(row=0, column=7, padx=(6, 14), pady=12)

    def _build_body(self):
        body = ctk.CTkFrame(self, corner_radius=10)
        body.grid(row=2, column=0, sticky="nsew", padx=16, pady=8)
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        # --- Packet table (ttk.Treeview themed to match dark UI) ---
        table_frame = ctk.CTkFrame(body, corner_radius=8)
        table_frame.grid(row=0, column=0, sticky="nsew", padx=(10, 6), pady=10)
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Sniffer.Treeview",
            background="#1E1E2E", fieldbackground="#1E1E2E", foreground="#E0E0E0",
            rowheight=26, borderwidth=0, font=("Consolas", 10),
        )
        style.configure(
            "Sniffer.Treeview.Heading",
            background="#2A2A3D", foreground="#FFFFFF",
            font=("Segoe UI", 10, "bold"), borderwidth=0,
        )
        style.map("Sniffer.Treeview", background=[("selected", "#3A5A8C")])

        columns = ("no", "time", "proto", "src", "dst", "ports", "len")
        self.tree = ttk.Treeview(
            table_frame, columns=columns, show="headings", style="Sniffer.Treeview"
        )
        headers = {
            "no": ("#", 45), "time": ("Time", 100), "proto": ("Proto", 70),
            "src": ("Source", 170), "dst": ("Destination", 170),
            "ports": ("Ports", 110), "len": ("Len", 60),
        }
        for col, (label, width) in headers.items():
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor="w")

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        self.tree.bind("<<TreeviewSelect>>", self._on_row_selected)

        for proto, color in PROTOCOL_COLORS.items():
            self.tree.tag_configure(proto, foreground=color)

        # --- Detail / stats panel ---
        side = ctk.CTkFrame(body, corner_radius=8)
        side.grid(row=0, column=1, sticky="nsew", padx=(6, 10), pady=10)
        side.grid_rowconfigure(1, weight=1)
        side.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            side, text="Packet Detail", font=ctk.CTkFont(size=14, weight="bold")
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(12, 4))

        self.detail_box = ctk.CTkTextbox(side, font=ctk.CTkFont(family="Consolas", size=11))
        self.detail_box.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 8))
        self.detail_box.insert("1.0", "Select a packet to inspect it.")
        self.detail_box.configure(state="disabled")

        stats_frame = ctk.CTkFrame(side, fg_color="transparent")
        stats_frame.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 12))
        stats_frame.grid_columnconfigure((0, 1), weight=1)

        self.stat_total = self._make_stat_tile(stats_frame, "Packets", "0", 0, 0)
        self.stat_time = self._make_stat_tile(stats_frame, "Elapsed", "0s", 0, 1)

    def _make_stat_tile(self, parent, label, value, row, col):
        tile = ctk.CTkFrame(parent, corner_radius=8, fg_color="#23233A")
        tile.grid(row=row, column=col, sticky="ew", padx=4, pady=4)
        ctk.CTkLabel(tile, text=label, font=ctk.CTkFont(size=11), text_color="#9AA0A6").pack(
            anchor="w", padx=10, pady=(8, 0)
        )
        value_label = ctk.CTkLabel(tile, text=value, font=ctk.CTkFont(size=18, weight="bold"))
        value_label.pack(anchor="w", padx=10, pady=(0, 8))
        return value_label

    def _build_statusbar(self):
        bar = ctk.CTkFrame(self, height=28, corner_radius=0, fg_color=("#1A1A2E", "#1A1A2E"))
        bar.grid(row=3, column=0, sticky="ew")
        self.status_label = ctk.CTkLabel(
            bar, text="Idle. Configure an interface/filter and press Start Capture.",
            font=ctk.CTkFont(size=11), text_color="#9AA0A6",
        )
        self.status_label.pack(side="left", padx=14, pady=4)

    # ------------------------------------------------------------------ #
    # Interfaces
    # ------------------------------------------------------------------ #
    def _refresh_interfaces(self):
        ifaces = NetworkSniffer.list_interfaces() or ["any"]
        self.iface_menu.configure(values=["any"] + ifaces)
        self.iface_menu.set("any")

    # ------------------------------------------------------------------ #
    # Capture control (buttons)
    # ------------------------------------------------------------------ #
    def start_capture(self):
        if self.sniffer.is_running():
            return

        iface = self.iface_menu.get()
        iface = None if iface == "any" else iface
        bpf_filter = self.filter_entry.get().strip()

        try:
            self.sniffer.start(iface=iface, bpf_filter=bpf_filter)
        except RuntimeError as e:
            messagebox.showerror("Sniffer", str(e))
            return

        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_label.configure(
            text=f"Capturing on '{iface or 'any'}'"
            + (f" with filter '{bpf_filter}'" if bpf_filter else "") + " ..."
        )
        self._tick_stats()

    def stop_capture(self):
        self.sniffer.stop()
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.status_label.configure(text="Capture stopped.")

    def clear_capture(self):
        if self.sniffer.is_running():
            messagebox.showinfo("Sniffer", "Stop the capture before clearing.")
            return
        self.sniffer.reset()
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.stat_total.configure(text="0")
        self.stat_time.configure(text="0s")
        self.detail_box.configure(state="normal")
        self.detail_box.delete("1.0", "end")
        self.detail_box.insert("1.0", "Select a packet to inspect it.")
        self.detail_box.configure(state="disabled")
        self.status_label.configure(text="Capture cleared.")

    def export_capture(self):
        if not self.sniffer.packets:
            messagebox.showinfo("Export", "No packets captured yet.")
            return

        filetypes = [("PCAP file", "*.pcap"), ("Text log", "*.log"), ("All files", "*.*")]
        path = filedialog.asksaveasfilename(
            defaultextension=".pcap", filetypes=filetypes, initialfile="capture.pcap"
        )
        if not path:
            return
        try:
            if path.endswith(".log") or path.endswith(".txt"):
                self.sniffer.save_log(path)
            else:
                self.sniffer.save_pcap(path)
            messagebox.showinfo("Export", f"Saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    # ------------------------------------------------------------------ #
    # Live updates (thread-safe via queue)
    # ------------------------------------------------------------------ #
    def _on_packet_captured(self, info, error=None):
        # Called from the sniffer's background thread — never touch Tk widgets
        # directly here. Push to a thread-safe queue and let the Tk mainloop
        # drain it on a timer instead.
        self._ui_queue.put((info, error))

    def _poll_queue(self):
        try:
            while True:
                info, error = self._ui_queue.get_nowait()
                if error:
                    self._handle_capture_error(error)
                elif info:
                    self._insert_row(info)
        except queue.Empty:
            pass
        self.after(150, self._poll_queue)

    def _handle_capture_error(self, message):
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.status_label.configure(text="Error — see popup.")
        messagebox.showerror("Capture error", message)

    def _insert_row(self, info):
        tag = info.protocol if info.protocol in PROTOCOL_COLORS else "OTHER"
        ports = f"{info.src_port}→{info.dst_port}" if info.src_port else ""
        self.tree.insert(
            "", "end", iid=str(info.index),
            values=(info.index, info.timestamp, info.protocol, info.src_ip,
                    info.dst_ip, ports, info.length),
            tags=(tag,),
        )
        self.tree.see(str(info.index))
        self._packets_by_index = getattr(self, "_packets_by_index", {})
        self._packets_by_index[info.index] = info
        self.stat_total.configure(text=str(len(self.sniffer.packets)))

    def _tick_stats(self):
        if self.sniffer.is_running():
            stats = self.sniffer.get_stats()
            self.stat_time.configure(text=f"{stats['elapsed_seconds']}s")
            self.after(1000, self._tick_stats)

    def _on_row_selected(self, _event):
        selection = self.tree.selection()
        if not selection:
            return
        idx = int(selection[0])
        info = getattr(self, "_packets_by_index", {}).get(idx)
        if not info:
            return

        detail = (
            f"Packet #{info.index}\n"
            f"Time      : {info.timestamp}\n"
            f"Protocol  : {info.protocol}\n"
            f"Source    : {info.src_ip}{(':' + info.src_port) if info.src_port else ''}\n"
            f"Dest      : {info.dst_ip}{(':' + info.dst_port) if info.dst_port else ''}\n"
            f"Length    : {info.length} bytes\n\n"
            f"Summary   : {info.summary}\n\n"
            f"Payload preview:\n{info.payload_preview or '(none)'}"
        )
        self.detail_box.configure(state="normal")
        self.detail_box.delete("1.0", "end")
        self.detail_box.insert("1.0", detail)
        self.detail_box.configure(state="disabled")

    def on_close(self):
        if self.sniffer.is_running():
            self.sniffer.stop()
        self.destroy()


if __name__ == "__main__":
    app = NetworkSnifferApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
