"""
Description: Take an IP address and a port number, and scan all devices in the network range,
defined by subnet mask 255.255.255.0, for this port. return a list of IP addresses
that have this port open.
Arguments:
  - ip: The target IP address to scan.
  - port: The specific port number to scan.
"""


def scan_network_for_port(ip, port):
    import socket
    from scapy.all import srp, conf
    from scapy.layers.l2 import Ether, ARP

    subnet = ".".join(ip.split(".")[:-1]) + ".0/24"
    open_hosts = []

    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, iface=conf.iface, timeout=2, retry=2, verbose=False)

    for _, received in answered:
        host_ip = received.psrc
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.001)  # Set timeout to 1 millisecond
        try:
            sock.connect((host_ip, port))
            open_hosts.append(host_ip)
        except (socket.timeout, ConnectionRefusedError):
            continue
        finally:
            sock.close()

    return open_hosts


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python network_port_scanner.py <IP_ADDRESS> <PORT>")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])

    if target_port <= 0 or target_port > 65535:
        print("Please provide a valid port number (1-65535).")
        sys.exit(1)

    print(f"Scanning network for open port {target_port}...")
    open_hosts = scan_network_for_port(target_ip, target_port)

    if open_hosts:
        print(f"Hosts with port {target_port} open: {', '.join(open_hosts)}")
    else:
        print(f"No hosts found with port {target_port} open.")
