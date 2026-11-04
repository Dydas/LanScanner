"""LAN Scanner - skanuje adresy IP w sieci lokalnej i wyświetla ich hostname.

Uruchomienie:  python lan_scanner.py   (lub pythonw, bez okna konsoli)
Wymagania:     Python 3.8+, tylko biblioteka standardowa.
"""

import csv
import ipaddress
import json
import os
import platform
import queue
import random
import re
import socket
import struct
import subprocess
import threading
import time
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import filedialog, messagebox, ttk

IS_WINDOWS = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
NO_WINDOW = subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0
MAX_HOSTS = 65536


# --------------------------------------------------------------------------- #
#  Sieć
# --------------------------------------------------------------------------- #
def run(cmd, timeout=10):
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            stdin=subprocess.DEVNULL,
            creationflags=NO_WINDOW, errors="replace",
        ).stdout
    except Exception:
        return ""


def local_networks():
    """Zwraca listę (opis, sieć CIDR, własny IP) dla lokalnych interfejsów IPv4."""
    nets = []
    if IS_WINDOWS:
        out = run([
            "powershell", "-NoProfile", "-Command",
            "$gw = @(Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue"
            " | Select-Object -ExpandProperty InterfaceIndex); "
            "Get-NetIPAddress -AddressFamily IPv4 | "
            "Select-Object IPAddress,PrefixLength,InterfaceAlias,"
            "@{n='Gw';e={$gw -contains $_.InterfaceIndex}} | ConvertTo-Json",
        ], timeout=15)
        try:
            data = json.loads(out) if out.strip() else []
            if isinstance(data, dict):
                data = [data]
            for d in data:
                ip = d["IPAddress"]
                if ip.startswith(("127.", "169.254.")):
                    continue
                net = ipaddress.ip_network(f"{ip}/{d['PrefixLength']}", strict=False)
                nets.append((d["InterfaceAlias"], net, ip, bool(d.get("Gw"))))
        except Exception:
            pass
    else:  # macOS / Linux: parsowanie ifconfig
        gw_if = set()
        if IS_MAC:
            for line in run(["/usr/sbin/netstat", "-rn", "-f", "inet"]).splitlines():
                parts = line.split()
                if parts and parts[0] == "default" and len(parts) >= 4:
                    gw_if.add(parts[3])
        out = run(["/sbin/ifconfig"]) or run(["ifconfig"])
        iface = None
        for line in out.splitlines():
            m = re.match(r"^([\w.\-]+):?\s", line)
            if m and not line[0].isspace():
                iface = m.group(1).rstrip(":")
                continue
            m = re.search(r"inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)\s+.*?(?:netmask|Mask:)\s*(0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)", line)
            if not m or iface is None:
                continue
            ip, mask = m.groups()
            if ip.startswith(("127.", "169.254.")):
                continue
            if mask.startswith("0x"):
                mask = str(ipaddress.IPv4Address(int(mask, 16)))
            try:
                net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
            except ValueError:
                continue
            nets.append((iface, net, ip, iface in gw_if))
    nets = [n for n in nets if n[1].prefixlen < 31]  # pomiń /31, /32 (VPN, p2p)
    if not nets:  # fallback: główny interfejs, zakładamy /24
        ip = primary_ip()
        if ip:
            nets.append(("domyślny", ipaddress.ip_network(f"{ip}/24", strict=False), ip, True))
    return nets


def primary_ip():
    """IP interfejsu z trasą domyślną (bez wysyłania pakietów)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def ping(ip, timeout_ms):
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif IS_MAC:  # na macOS -W jest w milisekundach
        cmd = ["/sbin/ping", "-c", "1", "-n", "-W", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-n", "-W", str(max(1, timeout_ms // 1000)), ip]
    out = run(cmd, timeout=timeout_ms / 1000 + 3)
    # "TTL=" występuje w odpowiedzi niezależnie od języka systemu
    ok = "ttl=" in out.lower()
    # czas: "time=12ms" / "czas<1 ms" / "time=0.45 ms"
    m = re.search(r"[=<]\s*([\d.,]+)\s*ms", out)
    ms = float(m.group(1).replace(",", ".")) if (ok and m) else None
    return ok, ms


def arp_table():
    """IP -> MAC z tablicy ARP systemu."""
    table = {}
    out = run(["arp", "-an"] if not IS_WINDOWS else ["arp", "-a"])
    # macOS wypisuje MAC bez zer wiodących, np. 0:15:5d:1:1e:2
    for m in re.finditer(
        r"(\d+\.\d+\.\d+\.\d+)\D+?([0-9a-fA-F]{1,2}(?:[-:][0-9a-fA-F]{1,2}){5})\b", out
    ):
        mac = ":".join(p.zfill(2) for p in re.split("[-:]", m.group(2).lower()))
        if mac == "ff:ff:ff:ff:ff:ff" or mac.startswith("01:00:5e"):
            continue
        table[m.group(1)] = mac
    return table


def netbios_name(ip, timeout=1.0):
    """Zapytanie NetBIOS Node Status (UDP 137). Zwraca (nazwa, mac) lub (None, None)."""
    tid = random.randint(0, 0xFFFF)
    name = b"*" + b"\x00" * 15
    encoded = b"".join(bytes([0x41 + (c >> 4), 0x41 + (c & 0x0F)]) for c in name)
    packet = (
        struct.pack(">HHHHHH", tid, 0, 1, 0, 0, 0)
        + b"\x20" + encoded + b"\x00"
        + struct.pack(">HH", 0x21, 0x01)
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(packet, (ip, 137))
        data, _ = s.recvfrom(2048)
    except OSError:
        return None, None
    finally:
        s.close()
    try:
        off = 12 + 34 + 2 + 2 + 4 + 2  # nagłówek + nazwa + typ + klasa + TTL + rdlength
        count = data[off]
        off += 1
        result = None
        for i in range(count):
            entry = data[off + i * 18: off + (i + 1) * 18]
            nm = entry[:15].decode("ascii", "replace").strip()
            suffix, flags = entry[15], struct.unpack(">H", entry[16:18])[0]
            if suffix == 0x00 and not flags & 0x8000:  # unikalna nazwa stacji
                result = nm
                break
        mac_bytes = data[off + count * 18: off + count * 18 + 6]
        mac = ":".join(f"{b:02x}" for b in mac_bytes) if len(mac_bytes) == 6 else None
        if mac == "00:00:00:00:00:00":
            mac = None
        return result, mac
    except (IndexError, struct.error):
        return None, None


def resolve(ip, use_netbios):
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name, "DNS", None
    except (OSError, UnicodeError):
        pass
    if use_netbios:
        name, mac = netbios_name(ip)
        if name:
            return name, "NetBIOS", mac
    return "", "", None


# --------------------------------------------------------------------------- #
#  GUI
# --------------------------------------------------------------------------- #
class App(tk.Tk):
    COLS = ("ip", "hostname", "source", "mac", "ping")
    HEAD = {"ip": "Adres IP", "hostname": "Hostname", "source": "Źródło nazwy",
            "mac": "Adres MAC", "ping": "Ping [ms]"}
    WIDTH = {"ip": 120, "hostname": 260, "source": 100, "mac": 140, "ping": 80}

    def __init__(self):
        super().__init__()
        self.title("LAN Scanner")
        self.geometry("820x560")
        self.minsize(640, 400)

        self.q = queue.Queue()
        self.stop_event = threading.Event()
        self.worker = None
        self.rows = {}
        self.sort_state = {}
        self.networks = []

        self._build()
        self.after(100, self._poll)
        threading.Thread(target=self._load_networks, daemon=True).start()

    # ---------- budowa interfejsu ----------
    def _build(self):
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")

        ttk.Label(top, text="Interfejs:").grid(row=0, column=0, sticky="w")
        self.iface_var = tk.StringVar(value="wykrywanie…")
        self.iface_cb = ttk.Combobox(top, textvariable=self.iface_var, state="readonly", width=45)
        self.iface_cb.grid(row=0, column=1, columnspan=3, sticky="we", padx=4)
        self.iface_cb.bind("<<ComboboxSelected>>", self._on_iface)

        ttk.Label(top, text="Zakres (CIDR):").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.cidr_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.cidr_var, width=22).grid(
            row=1, column=1, sticky="w", padx=4, pady=(6, 0))

        ttk.Label(top, text="Timeout ping [ms]:").grid(row=1, column=2, sticky="e", pady=(6, 0))
        self.timeout_var = tk.IntVar(value=600)
        ttk.Spinbox(top, from_=100, to=5000, increment=100, textvariable=self.timeout_var,
                    width=7).grid(row=1, column=3, sticky="w", padx=4, pady=(6, 0))

        self.show_all_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Pokaż też niedostępne", variable=self.show_all_var).grid(
            row=2, column=1, sticky="w", pady=(6, 0))
        self.netbios_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="NetBIOS gdy brak DNS", variable=self.netbios_var).grid(
            row=2, column=2, columnspan=2, sticky="w", pady=(6, 0))

        btns = ttk.Frame(top)
        btns.grid(row=0, column=4, rowspan=3, sticky="ne", padx=(12, 0))
        self.start_btn = ttk.Button(btns, text="▶ Skanuj", command=self.start)
        self.start_btn.pack(fill="x")
        self.stop_btn = ttk.Button(btns, text="■ Stop", command=self.stop, state="disabled")
        self.stop_btn.pack(fill="x", pady=4)
        ttk.Button(btns, text="Eksport CSV", command=self.export).pack(fill="x")
        top.columnconfigure(1, weight=1)

        mid = ttk.Frame(self, padding=(8, 0))
        mid.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(mid, columns=self.COLS, show="headings")
        for c in self.COLS:
            self.tree.heading(c, text=self.HEAD[c], command=lambda c=c: self._sort(c))
            self.tree.column(c, width=self.WIDTH[c],
                             anchor="e" if c == "ping" else "w", stretch=(c == "hostname"))
        vs = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.tree.tag_configure("down", foreground="#999999")
        self.tree.tag_configure("self", foreground="#0a6ebd")
        self.tree.bind("<Control-c>", self._copy)
        self.tree.bind("<Command-c>" if IS_MAC else "<Control-C>", self._copy)

        bottom = ttk.Frame(self, padding=8)
        bottom.pack(fill="x")
        self.progress = ttk.Progressbar(bottom, mode="determinate")
        self.progress.pack(fill="x")
        self.status_var = tk.StringVar(value="Gotowy.")
        ttk.Label(bottom, textvariable=self.status_var).pack(anchor="w", pady=(4, 0))

    # ---------- interfejsy ----------
    def _load_networks(self):
        self.q.put(("networks", (local_networks(), primary_ip())))

    def _on_iface(self, _=None):
        i = self.iface_cb.current()
        if 0 <= i < len(self.networks):
            self.cidr_var.set(str(self.networks[i][1]))

    # ---------- skanowanie ----------
    def start(self):
        try:
            net = ipaddress.ip_network(self.cidr_var.get().strip(), strict=False)
        except ValueError:
            messagebox.showerror("Błąd", "Nieprawidłowy zakres, np. 192.168.1.0/24")
            return
        if net.version != 4:
            messagebox.showerror("Błąd", "Obsługiwane jest tylko IPv4.")
            return
        hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
        if len(hosts) > MAX_HOSTS:
            messagebox.showerror("Błąd", f"Zakres zbyt duży (max {MAX_HOSTS} adresów).")
            return
        if len(hosts) > 4096 and not messagebox.askyesno(
                "Duży zakres", f"Skanować {len(hosts)} adresów? To może potrwać."):
            return

        self.tree.delete(*self.tree.get_children())
        self.rows.clear()
        self.stop_event.clear()
        self.progress.configure(maximum=len(hosts), value=0)
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_var.set(f"Skanowanie {net} ({len(hosts)} adresów)…")
        self.t_start = time.time()

        own_ips = {n[2] for n in self.networks}
        self.worker = threading.Thread(
            target=self._scan,
            args=([str(h) for h in hosts], int(self.timeout_var.get()),
                  self.show_all_var.get(), self.netbios_var.get(), own_ips),
            daemon=True)
        self.worker.start()

    def stop(self):
        self.stop_event.set()
        self.status_var.set("Zatrzymywanie…")

    def _scan(self, ips, timeout_ms, show_all, use_netbios, own_ips):
        alive = {}

        # 1) ping sweep
        def probe(ip):
            if self.stop_event.is_set():
                return ip, False, None
            ok, ms = ping(ip, timeout_ms)
            return ip, ok, ms

        with ThreadPoolExecutor(max_workers=128) as ex:
            futs = [ex.submit(probe, ip) for ip in ips]
            for f in as_completed(futs):
                ip, ok, ms = f.result()
                if ok or ip in own_ips:
                    alive[ip] = ms if ok else None
                self.q.put(("progress", 1))

        # 2) urządzenia, które nie odpowiadają na ping, ale są w tablicy ARP
        ip_set = set(ips)
        arp = arp_table()
        for ip in arp:
            if ip in ip_set and ip not in alive:
                alive[ip] = None

        if self.stop_event.is_set():
            self.q.put(("done", len(alive)))
            return

        # 3) rozwiązywanie nazw
        self.q.put(("status", f"Znaleziono {len(alive)} hostów, pobieranie nazw…"))
        targets = list(alive) if not show_all else ips

        def name_job(ip):
            if self.stop_event.is_set():
                return None
            up = ip in alive
            if not up:
                return ip, "", "", "", "", "down"
            host, src, nb_mac = resolve(ip, use_netbios)
            if ip in own_ips:
                host = host or socket.gethostname()
                src = src or "lokalny"
            mac = arp.get(ip) or nb_mac or ""
            ms = alive[ip]
            ping_txt = f"{ms:.0f}" if ms is not None else "—"
            return ip, host, src, mac, ping_txt, "self" if ip in own_ips else ""

        with ThreadPoolExecutor(max_workers=64) as ex:
            for f in as_completed([ex.submit(name_job, ip) for ip in targets]):
                r = f.result()
                if r:
                    self.q.put(("row", r))
        self.q.put(("done", len(alive)))

    # ---------- komunikacja wątek -> GUI ----------
    def _poll(self):
        try:
            for _ in range(500):
                kind, data = self.q.get_nowait()
                if kind == "progress":
                    self.progress.step(data)
                elif kind == "row":
                    self._add_row(data)
                elif kind == "status":
                    self.status_var.set(data)
                elif kind == "networks":
                    self._set_networks(data)
                elif kind == "done":
                    self.progress.configure(value=self.progress["maximum"])
                    self.start_btn.configure(state="normal")
                    self.stop_btn.configure(state="disabled")
                    named = sum(1 for v in self.rows.values() if v[1])
                    msg = "Przerwano" if self.stop_event.is_set() else "Zakończono"
                    self.status_var.set(
                        f"{msg}: {data} aktywnych hostów, {named} z nazwą "
                        f"({time.time() - self.t_start:.1f} s).")
                    self._sort("ip", keep=True)
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def _set_networks(self, data):
        nets, primary = data
        self.networks = nets
        self.iface_cb["values"] = [f"{n[0]} — {n[2]} ({n[1]})" for n in nets]
        if nets:
            virtual = re.compile(r"vEthernet|VirtualBox|VMware|WSL|Hyper-V|"
                                 r"^(utun|bridge|awdl|llw|vmnet|docker|veth)", re.I)

            def score(n):  # trasa domyślna > brama > niewirtualny > prywatny
                return (n[2] == primary, n[3], not virtual.search(n[0]),
                        n[1].is_private)

            best = max(range(len(nets)), key=lambda i: score(nets[i]))
            self.iface_cb.current(best)
            self._on_iface()
        else:
            self.iface_var.set("nie wykryto — wpisz zakres ręcznie")

    def _add_row(self, r):
        ip, host, src, mac, ping_txt, tag = r
        self.rows[ip] = r
        self.tree.insert("", "end", iid=ip, values=(ip, host, src, mac, ping_txt),
                         tags=(tag,) if tag else ())

    # ---------- sortowanie / kopiowanie / eksport ----------
    def _sort(self, col, keep=False):
        rev = self.sort_state.get(col, False) if keep else not self.sort_state.get(col, True)
        self.sort_state = {col: rev}
        idx = self.COLS.index(col)

        def key(iid):
            v = self.rows[iid][idx]
            if col == "ip":
                return int(ipaddress.ip_address(v))
            if col == "ping":
                try:
                    return float(v)
                except ValueError:
                    return float("inf")
            return (v == "", v.lower())

        for i, iid in enumerate(sorted(self.rows, key=key, reverse=rev)):
            self.tree.move(iid, "", i)

    def _copy(self, _=None):
        sel = self.tree.selection()
        if sel:
            self.clipboard_clear()
            self.clipboard_append("\n".join("\t".join(self.rows[i][:5]) for i in sel))

    def export(self):
        if not self.rows:
            messagebox.showinfo("Eksport", "Brak danych do eksportu.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV", "*.csv")],
            initialfile=f"lan_scan_{time.strftime('%Y%m%d_%H%M%S')}.csv")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow([self.HEAD[c] for c in self.COLS])
            for iid in self.tree.get_children():
                w.writerow(self.rows[iid][:5])
        self.status_var.set(f"Zapisano: {path}")


if __name__ == "__main__":
    if IS_WINDOWS:
        try:  # ostre czcionki na ekranach HiDPI
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    App().mainloop()
