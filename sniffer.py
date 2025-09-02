#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cyber Sniffer (Educational)
Features:
  - Devices scan (ARP) on your local network
  - Live packet sniff (metadata only) + CSV logging
  - Pretty terminal output with Rich
Use ethically on YOUR own network only.
"""

import argparse
import csv
import datetime as dt
import os
import sys
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich import box
except Exception:
    print("Rich not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

try:
    from scapy.all import ARP, Ether, srp, sniff, conf, get_if_list
except Exception:
    print("Scapy not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

console = Console()

BANNER = r"""
   ______          __              _____       _  __  ____  _  __
  / ____/___  ____/ /___  ____ _  / ___/____  | |/ / / __ \| |/ /
 / /   / __ \/ __  / __ \/ __ `/  \__ \/ __ \ |   / / /_/ /|   / 
/ /___/ /_/ / /_/ / /_/ / /_/ /  ___/ / /_/ /|   | / ____/ |   | 
\____/\____/\__,_/\____/\__,_/  /____/\____/ |_|\_/_/      |_|\_|

        Educational Network Devices Scanner + Sniffer
"""

LEGAL = """
[bold yellow]LEGAL / ETHICAL NOTICE[/bold yellow]
Use this tool only on networks you own or have explicit permission to test.
You may need administrator/root privileges for packet capture and ARP scanning.
"""

def ensure_csv(path: Path, headers):
    new = not path.exists()
    f = path.open("a", newline="", encoding="utf-8")
    writer = csv.writer(f)
    if new:
        writer.writerow(headers)
    return f, writer

def list_interfaces():
    return get_if_list()

def cmd_scan(args):
    console.print(BANNER, style="cyan")
    console.print(LEGAL)
    target_cidr = args.target  # e.g., "192.168.1.0/24"
    iface = args.iface

    console.rule("[bold green]ARP Devices Scan")
    console.print(f"[bold]Interface:[/bold] {iface or 'auto'}  |  [bold]Target:[/bold] {target_cidr}")

    # Build ARP request
    arp = ARP(pdst=target_cidr)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Send and receive
    ans, unans = srp(packet, timeout=2, iface=iface, verbose=False)

    table = Table(title="Devices Found", box=box.SIMPLE_HEAVY, show_lines=False)
    table.add_column("#", style="bold")
    table.add_column("IP")
    table.add_column("MAC")
    table.add_column("Vendor (N/A)")

    devices = []
    for i, (sent, recv) in enumerate(ans, start=1):
        devices.append((recv.psrc, recv.hwsrc))
        table.add_row(str(i), recv.psrc, recv.hwsrc, "—")

    if devices:
        console.print(table)
        console.print(f"[green]Total devices:[/green] {len(devices)}")
    else:
        console.print("[yellow]No devices discovered. Try another subnet or run as admin/root.[/yellow]")

    # Optional CSV save
    if args.out:
        out = Path(args.out)
        f, writer = ensure_csv(out, ["timestamp", "ip", "mac"])
        ts = dt.datetime.utcnow().isoformat()
        for ip, mac in devices:
            writer.writerow([ts, ip, mac])
        f.close()
        console.print(f"[blue]Saved results to:[/blue] {out.resolve()}")

def cmd_sniff(args):
    console.print(BANNER, style="cyan")
    console.print(LEGAL)

    iface = args.iface
    bpf_filter = args.filter  # e.g., "tcp or udp"
    limit = args.limit
    timeout = args.timeout
    out = Path(args.out) if args.out else Path(f"packets_{dt.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv")

    console.rule("[bold green]Live Packet Sniff (metadata only)")
    console.print(f"[bold]Interface:[/bold] {iface or 'auto'}")
    console.print(f"[bold]Filter:[/bold] {bpf_filter or 'none'}")
    console.print(f"[bold]Limit:[/bold] {limit or '∞'}   [bold]Timeout:[/bold] {timeout or '∞'} sec")
    console.print(f"[bold]CSV Log:[/bold] {out}")

    # Prepare CSV
    f, writer = ensure_csv(out, ["timestamp", "src_ip", "dst_ip", "proto", "length"])

    table = Table(title="Live Packets (metadata)", box=box.SIMPLE_HEAVY)
    table.add_column("#", style="bold")
    table.add_column("Time (UTC)")
    table.add_column("Src → Dst")
    table.add_column("Proto")
    table.add_column("Len")

    counter = {"n": 0}

    def on_packet(pkt):
        try:
            # Only metadata (no payload dumps)
            ts = dt.datetime.utcnow().strftime("%H:%M:%S")
            length = len(pkt)
            proto = "OTHER"
            src = getattr(pkt, "src", "?")
            dst = getattr(pkt, "dst", "?")

            # Try IP layer fields if present
            if hasattr(pkt, "payload") and hasattr(pkt.payload, "src"):
                src = getattr(pkt.payload, "src", src)
                dst = getattr(pkt.payload, "dst", dst)

            # Guess protocol name
            if hasattr(pkt, "sport") or hasattr(pkt, "dport"):
                # common transport protocols
                if pkt.haslayer("TCP"):
                    proto = "TCP"
                elif pkt.haslayer("UDP"):
                    proto = "UDP"
                else:
                    proto = "TRANS"

            counter["n"] += 1
            row_idx = str(counter["n"])
            table.add_row(row_idx, ts, f"{src} → {dst}", proto, str(length))
            writer.writerow([dt.datetime.utcnow().isoformat(), src, dst, proto, length])
        except Exception:
            # ignore malformed packets safely
            pass

    with Live(table, refresh_per_second=5, console=console):
        try:
            sniff(
                iface=iface,
                filter=bpf_filter,
                prn=on_packet,
                store=False,
                count=limit if limit and limit > 0 else 0,
                timeout=timeout if timeout and timeout > 0 else None,
            )
        except PermissionError:
            console.print("[red]Permission error: run as Administrator/root.[/red]")
        except OSError as e:
            console.print(f"[red]OS error: {e}[/red]")

    f.close()
    console.print(f"[green]Done. Logged to:[/green] {out.resolve()}")

def cmd_ifaces(_):
    console.print(BANNER, style="cyan")
    console.rule("[bold green]Available Interfaces")
    ifaces = list_interfaces()
    t = Table(box=box.SIMPLE_HEAVY)
    t.add_column("#", style="bold")
    t.add_column("Interface Name")
    for i, name in enumerate(ifaces, start=1):
        t.add_row(str(i), name)
    console.print(t)

def main():
    parser = argparse.ArgumentParser(
        prog="cyber-sniffer",
        description="Educational Network Devices Scanner + Sniffer (metadata only). Use on your own network.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Discover devices on local network via ARP")
    p_scan.add_argument("-t", "--target", required=True, help="Target CIDR, e.g., 192.168.1.0/24")
    p_scan.add_argument("-i", "--iface", default=None, help="Network interface name (optional)")
    p_scan.add_argument("-o", "--out", default=None, help="Save results to CSV file")
    p_scan.set_defaults(func=cmd_scan)

    p_sniff = sub.add_parser("sniff", help="Sniff live packets (metadata only) and log to CSV")
    p_sniff.add_argument("-i", "--iface", default=None, help="Network interface name (optional)")
    p_sniff.add_argument("-f", "--filter", default=None, help='BPF filter, e.g., "tcp or udp"')
    p_sniff.add_argument("-l", "--limit", type=int, default=0, help="Stop after N packets (0 = unlimited)")
    p_sniff.add_argument("-t", "--timeout", type=int, default=0, help="Stop after N seconds (0 = unlimited)")
    p_sniff.add_argument("-o", "--out", default=None, help="CSV output path (default auto)")
    p_sniff.set_defaults(func=cmd_sniff)

    p_if = sub.add_parser("ifaces", help="List available network interfaces")
    p_if.set_defaults(func=cmd_ifaces)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    # Require elevated privileges warning
    if os.name != "nt" and os.geteuid() != 0:
        console.print("[yellow]Tip:[/yellow] Run with sudo for sniffing/scanning:  sudo python3 sniffer.py ...")
    main()
