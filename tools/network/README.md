# Network Security Utilities

This collection contains Python scripts for network reconnaissance, enumeration, and manipulation. These tools are designed for educational purposes and authorized penetration testing labs.

## Tools

### 1. ARP Spoofer Project (NFQUEUE)
**Located in:** `arp_spoofer_nfqueue/`

A sophisticated Man-in-the-Middle framework leveraging kernel forwarding and `NFQUEUE`. It supports a modular plugin system for advanced attacks.

**Key Features:**
- **Traffic Interception**: Uses `netfilter_queue` for deep inspection.
- **Plugin System**: Easily extensible logic.
- **DNS Spoofing**: Supports spoofing domains and bypassing DoH/DoT via `--force-plain-dns`.
- **HTTP Redirection**: Inject HTTP 302 redirects.
- **Traffic View**: Real-time traffic monitoring.

**Main Script:** `arp_spoofer_nfqueue/arp_spoofer.py`

**Usage:**
```bash
cd arp_spoofer_nfqueue
sudo python3 arp_spoofer.py --iface <INT> --victim <IP> --gateway <IP> [options]
```

**Common Options:**
- `--view`: Print traffic summaries.
- `--dns-spoof-domain '*' --force-plain-dns`: Spoof all DNS queries + block DoH/DoT.
- `--redirect-url <URL>`: Redirect HTTP traffic to a specific URL.

See [arp_spoofer_nfqueue/README.md](arp_spoofer_nfqueue/README.md) for full documentation.

---

### 2. ARP Spoofer (Manual Forwarding)
A userspace ARP spoofing tool that manually forwards packets using Scapy. Useful when kernel forwarding is disabled or for understanding L2 packet manipulation (TTL, Checksum recalculation, Fragmentation).

**File:** `arp_spoofer_mnl_fwd.py`
**Usage:**
```bash
sudo python3 arp_spoofer_mnl_fwd.py --iface <INT> --victim <IP> --gateway <IP> [options]
```
**Options:**
- `--view`: Print summaries of forwarded traffic.
- `--no-fragment`: Disable manual packet fragmentation.
- `--client <IP>`: Include a specific client (e.g. remote host) in the scope.

**Example:**
```bash
sudo python3 arp_spoofer_mnl_fwd.py --iface eth0 --victim 10.0.0.5 --gateway 10.0.0.1 --view
```

---

### 3. DNS Subdomain Enumerator
Performs DNS enumeration to discover subdomains of a target domain using a wordlist. It helps map the attack surface of a web application or organization.

**File:** `dns_enumeration.py`
**Usage:**
```bash
python3 dns_enumeration.py <DOMAIN> <WORDLIST_FILE>
```
**Example:**
```bash
python3 dns_enumeration.py example.com subdomains.txt
```

---

### 4. Port Scanner
A straightforward TCP connect scanner to identify open ports on a target system.

**File:** `port_scanner.py`
**Usage:**
```bash
python3 port_scanner.py <IP> <PORTS>
```
**Arguments:**
- `PORTS`: Number of ports to scan (e.g., `1000` scans ports 1-1000), or `-p-` for all 65535 ports.

**Example:**
```bash
python3 port_scanner.py 192.168.1.5 -p-
```

---

### 5. Subnet Scanner
Scans a local /24 subnet for hosts listening on a specific port. Useful for discovering network services like SSH or HTTP servers across the LAN.

**File:** `subnet_scanner.py`
**Usage:**
```bash
python3 subnet_scanner.py <IP_IN_SUBNET> <PORT>
```
**Example:**
```bash
# Scan 192.168.1.0/24 for hosts with port 80 open
python3 subnet_scanner.py 192.168.1.1 80
```

## Requirements
- Python 3.x
- `scapy` (for ARP spoofing and subnet scanning)
- Root privileges (for ARP spoofing and raw socket operations)
