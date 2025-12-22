"""
description: Scan the specified IP address for open TCP ports.
arguments:
  - ip: The target IP address to scan.
  - number_of_ports: The number of ports to scan - default is 1025, -p- for all ports, or a specific limit between 1 and 65535.
"""


def scan_ports(ip, number_of_ports=1025):
    open_ports = []
    for port in range(1, number_of_ports):
        if is_port_open(ip, port):
            print(f"Port {port} is open.")
            open_ports.append(port)
    return open_ports


def is_port_open(ip, port):
    """Check if a port is open on a given IP address."""
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.001)  # Set timeout to 1 millisecond
    try:
        sock.connect((ip, port))
        return True
    except (socket.timeout, ConnectionRefusedError):
        return False
    finally:
        sock.close()


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python port_scanner.py <IP_ADDRESS> <NUMBER_OF_PORTS>")
        sys.exit(1)

    target_ip = sys.argv[1]
    if sys.argv[2] == "-p-":
        number_of_ports = 65535  # Scan all ports if "-p-" is specified
    else:
        number_of_ports = int(sys.argv[2])
        if number_of_ports <= 0 or number_of_ports > 65535:
            print("Please provide a valid number of ports (1-65535).")
            sys.exit(1)
    print(f"Scanning ports on {target_ip}...")
    open_ports = scan_ports(target_ip, number_of_ports)

    if open_ports:
        print(f"Open ports on {target_ip}: {', '.join(map(str, open_ports))}")
    else:
        print(f"No open ports found on {target_ip}.")
